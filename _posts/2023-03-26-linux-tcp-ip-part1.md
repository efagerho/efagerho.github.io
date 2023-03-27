---
toc: true
toc_label: "Table of Contents"
toc_icon: "cog"
title: "Linux TCP/IP Stack Inbound Path - Part 1: The NIC"
date: 2023-03-26T15:34:30-04:00
categories:
  - blog
tags:
  - linux
  - networking
---

This series of posts documents the inner working of the Linux TCP/IP stack when receiving a TCP
or UDP packet. The level is kept at what is interesting for an application developer who
wants to understand the kernel code. Reasons for understanding the kernel code can be e.g.
troubleshooting using kernel tracing tools and writing better code to squeeze out every last
bit of performance of an application. Configuring a system optimally for an application also
requires understanding the TCP/IP stack. Note that we cover here the path where we do not do
kernel bypass networking. I might write a later series looking into DPDK and XDP.

## Modern Network Hardware

Modern network hardware can handle millions of packets per second and tens of gigabits of
throughput. To reach such performance, the hardware needs to be able to perform some of the
packet processing traditionally done by the kernel. We start by discussing the most
important feature in modern NICs.

### Receive Side Scaling

With modern multi-core CPUs the key to high-performance is to reduce contention by ensuring
cores don't write to the same data. Similarly, we need data locality to take advantage of CPU
caches.

RSS is another word for supporting multiple RX/TX queues. For TCP/UDP connections, the NIC
computes a hash of the ip/port pairs of the source and destination and places the packet in
one of the queues based on it. In particular, all network packets related to the same TCP or
UDP socket will be placed on the same queue. One way to setup the queues is to have one queue
per core, but depending on the number of queues supported by the NIC and the number of CPU
cores, this might not always be possible. For example, a `c6i.metal` EC2 instance has 128
cores, but only 8 RX/TX queues on the NIC. The network optimized `c6in` family has more
RX/TX queues per NIC, so it can distribute packet processing over a larger number of CPU cores.

Specially engineered applications can take advantage of this by making sure that a thread
pinned to a particular core only manages connections mapped to the RX/TX queues on the
same core. This allows the application to make optimum use of CPU caches during packet
processing. This can be achieved e.g. with the `SO_ATTACH_REUSEPORT_CBPF` and `SO_INCOMING_CPU`
socket options.

## Interrupt Handlers

To understand what drives the TCP/IP stack, you need to understand interrupts. The Linux
kernel has two types of interrupts: hard and soft. A hard interrupt or *hardirq* is a
general hardware interrupt fired by a hardware device while a soft interrupt or *softirq*
is just a software construct for scheduling high priority deferred work.

Typically most drivers include a *top half*, which is the actual hardware interrupt
handler and the *bottom half*, which does most of the work. The only job of the top half
is to schedule and ack the interrupt and schedule a bottom half to run.

The key point is that these bottom halves execute with interrupts enabled, while the hardirq
handler runs with at least the interrupt line disabled which it is handling.
Running time consuming code with any interrupt disabled is a bad idea for system
responsiveness.

### Hard IRQs

As mentioned earlier, modern NICs support Receive Side Scaling and have multiple RX/TX
queues. Each such queue has a unique HW interrupt. The way a queue is mapped to a
particular CPU is by setting a particular CPU as the handler of the interrupt associated
with the RX/TX queue pair. When talking about network devices or NICs in future sections
we practically always refer to one single queue as all queues are driven by separate
interrupts and therefore execute independently - almost as independent devices.

The device driver of any network device registers a handler for the interrupts in use
by the card. Interrupt handlers need to be extremely small and quick to run as an
interrupt might fire when the CPU is doing something important. A hardirq handler
typically only acks the interrupt by scheduling a task to execute later to do the
actual work needed. As an example, the following code is the handler of the AWS
Elastic Network Interface driver used by EC2 instances:

```c
static irqreturn_t ena_intr_msix_io(int irq, void *data)
{
  struct ena_napi *ena_napi = data;

  /* Used to check HW health */
  WRITE_ONCE(ena_napi->first_interrupt, true);

  WRITE_ONCE(ena_napi->interrupts_masked, true);
  smp_wmb(); /* write interrupts_masked before calling napi */

  /* Turn on polling in NAPI */
  napi_schedule_irqoff(&ena_napi->napi);

  return IRQ_HANDLED;
}
```

The code will become clear once we look at NAPI, i.e. the Linux kernel API for network
devices.

### Soft IRQs

A softirq is a pure software construct within the kernel. It's simply nothing more
than a method for scheduling high priority deferred work in the kernel. There's a
[limited number][list-soft-irqs] of them for the most high-priority tasks in the kernel:

```c
enum
{
  HI_SOFTIRQ=0,
  TIMER_SOFTIRQ,
  NET_TX_SOFTIRQ,
  NET_RX_SOFTIRQ,
  BLOCK_SOFTIRQ,
  IRQ_POLL_SOFTIRQ,
  TASKLET_SOFTIRQ,
  SCHED_SOFTIRQ,
  HRTIMER_SOFTIRQ,
  RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

  NR_SOFTIRQS
};
```

Softirqs are implemented as simple [per-CPU bitmasks][softirq-bitmask]. When a packet
arrives, the NIC sorts it into the appropriate RX queue and fires the interrupt
corresponding to the queue. The traditional way of handling a packet is then to raise the
`NET_RX_SOFTIRQ` softirq and the packet is processed the next time softirq handlers
are executed. Raising a softirq means simply [setting][raise-softirq] the bit
corresponding to the raised softirq in the bitmask of the current CPU:

```c
void __raise_softirq_irqoff(unsigned int nr)
{
  lockdep_assert_irqs_disabled();
  trace_softirq_raise(nr);
  // Set bit nr on the current CPU.
  or_softirq_pending(1UL << nr);
}
```

An important point is that when the hardirq handler raises a softirq, the softirq is
raised on the *same* CPU. A driver that uses softirqs for the bottom half will run the
top and bottom halves on the same core.

## NAPI Overview

NAPI is the "New API" for network device driver packet processing. New is a relative
term here, since it was introduced into Linux back in 2003. Previously, NICs would
fire an interrupt on an incoming packet causing a hardirq handler in the driver to run
and push the packet to the TCP/IP stack. On a high-performance network device, we can
handle millions of packets per second, which would cause a storm of interrupts. A CPU
could simply never keep up with the load, since handling an interrupt is a somewhat
expensive operation.

With NAPI the kernel essentially polls a device. However, polling is wasteful if there
are no incoming packets, so this is done in a somewhat smarter way:

1. Initially, the device is configured to fire an interrupt on packet arrival.
1. When the first packet arrives, the interrupt handler turns on polling.
1. If the kernel polls the NIC and there are no packets available it turns interrupts back on.

The most important functions in the NAPI framework are:

1. [netif_napi_add()][netif-napi-add]: registers device with NAPI for polling
1. [napi_schedule()][napi-schedule]: turns on device polling.
1. [napi_complete()][napi-complete]: turns off device polling.
1. [napi_poll()][napi-poll]: calls the driver I/O handler.
1. [napi_threaded_poll()][napi-threaded-poll]: calls the driver I/O handler if threaded polling enabled

Note that the above functions operate at the queue level, i.e. it's possible for one queue
to have interrupts enabled while another is being polled. This would happen for instance
when there's only a single active TCP connection to a machine. The most important data
structures of NAPI are:

1. [napi_struct][napi-struct]
1. [softnet_data][softnet-data]: contains the poll list for the queue

With NAPI the call to [napi_poll()][napi-poll] is what drives a packet up the TCP/IP
stack. It's therefore important to understand how and when it can execute.

We start by looking at the [napi_schedule()][napi-schedule] function:

```c
void __napi_schedule(struct napi_struct *n)
{
  unsigned long flags;

  local_irq_save(flags);
  ____napi_schedule(this_cpu_ptr(&softnet_data), n);
  local_irq_restore(flags);
}

inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
  struct task_struct *thread;

  lockdep_assert_irqs_disabled();

  if (test_bit(NAPI_STATE_THREADED, &napi->state)) {
    /* Paired with smp_mb__before_atomic() in
     * napi_enable()/dev_set_threaded().
     * Use READ_ONCE() to guarantee a complete
     * read on napi->thread. Only call
     * wake_up_process() when it's not NULL.
     */
    thread = READ_ONCE(napi->thread);
    if (thread) {
      /* Avoid doing set_bit() if the thread is in
       * INTERRUPTIBLE state, cause napi_thread_wait()
       * makes sure to proceed with napi polling
       * if the thread is explicitly woken from here.
       */
      if (READ_ONCE(thread->__state) != TASK_INTERRUPTIBLE)
        set_bit(NAPI_STATE_SCHED_THREADED, &napi->state);
      wake_up_process(thread);
      return;
    }
  }

  list_add_tail(&napi->poll_list, &sd->poll_list);
  __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```

We see that the there are two distinct ways of polling the device: softirq
or a kernel thread. Most device drivers currently use the softirq based polling
and threaded polling is a relatively new feature added in early 2021.

### Softirq Driven Polling

We start by discussing softirq based polling, since it's what most devices use.
The [softnet_data][softnet-data] is a global per-CPU defined struct that handles all the NAPI
state for the particular CPU core. Among other things it contains a `poll_list`.
If a device does not use threaded polling, then calling [napi_schedule()][napi-schedule] simply
appends the [napi_struct][napi-struct] for the device queue to the poll list.

With softirq polling, the polling is initiated by the `NET_RX_SOFTIRQ` handler [net_rx_action()][net-rx-action]:

```c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
  struct softnet_data *sd = this_cpu_ptr(&softnet_data);
  unsigned long time_limit = jiffies +
      usecs_to_jiffies(READ_ONCE(netdev_budget_usecs));
  int budget = READ_ONCE(netdev_budget);
  LIST_HEAD(list);
  LIST_HEAD(repoll);

  local_irq_disable();
  list_splice_init(&sd->poll_list, &list);
  local_irq_enable();

  for (;;) {
    struct napi_struct *n;

    skb_defer_free_flush(sd);

    if (list_empty(&list)) {
      if (!sd_has_rps_ipi_waiting(sd) && list_empty(&repoll))
        goto end;
      break;
    }

    n = list_first_entry(&list, struct napi_struct, poll_list);
    budget -= napi_poll(n, &repoll);

    /* If softirq window is exhausted then punt.
     * Allow this to run for 2 jiffies since which will allow
     * an average latency of 1.5/HZ.
     */
    if (unlikely(budget <= 0 ||
        time_after_eq(jiffies, time_limit))) {
      sd->time_squeeze++;
      break;
    }
  }

  local_irq_disable();

  list_splice_tail_init(&sd->poll_list, &list);
  list_splice_tail(&repoll, &list);
  list_splice(&list, &sd->poll_list);
  if (!list_empty(&sd->poll_list))
    __raise_softirq_irqoff(NET_RX_SOFTIRQ);

  net_rps_action_and_irq_enable(sd);
end:;
}
```

The above handler does the following:

1. Moves the contents of the poll list to `list`
1. Calls each handler in `list` and adds each to `repoll` for which the driver did not disable polling
1. Appends the devices to be repolled to the poll list
1. If poll list is nonempty raises the `NET_RX_SOFTIRQ` again

We also see that [napi_poll()][napi-poll] returns the amount of work it did, which is subtracted
from a budget that the softirq handler has. If the handler uses up its budget, it stops
and reraises the softirq. In this case it also updates a counter, which is exported
through the `/proc` filesystem.

### Kernel Thread Driven Polling

The kernel thread that handles device polling is created in [netif_napi_add()][netif-napi-add], which
registers the device for polling:

```c
void netif_napi_add_weight(struct net_device *dev, struct napi_struct *napi,
			   int (*poll)(struct napi_struct *, int), int weight)
{
  /* Omitted... */

  if (dev->threaded && napi_kthread_create(napi))
    dev->threaded = 0;
}

static int napi_kthread_create(struct napi_struct *n)
{
  int err = 0;

  /* Create and wake up the kthread once to put it in
   * TASK_INTERRUPTIBLE mode to avoid the blocked task
   * warning and work with loadavg.
   */
  n->thread = kthread_run(napi_threaded_poll, n, "napi/%s-%d",
                n->dev->name, n->napi_id);
  if (IS_ERR(n->thread)) {
    err = PTR_ERR(n->thread);
    pr_err("kthread_run failed with err %d\n", err);
    n->thread = NULL;
  }

  return err;
}
```

The above code shows that the kernel thread doing the polling just runs the
following loop:

```c
static int napi_threaded_poll(void *data)
{
  struct napi_struct *napi = data;
  void *have;

  while (!napi_thread_wait(napi)) {
    for (;;) {
      bool repoll = false;

      local_bh_disable();

      have = netpoll_poll_lock(napi);
      __napi_poll(napi, &repoll);
      netpoll_poll_unlock(have);

      local_bh_enable();

      if (!repoll)
        break;

      cond_resched();
    }
  }
  return 0;
}
```

Notice that in contrast to the softirq handler, we ignore the amount of work
done that is returned by [napi_poll()][napi-poll]. There is no need for hacks and heuristics,
since the kernel thread is run by the scheduler.

Note that not all devices support threaded polling. The simple reason is that it
requires support from the driver as the usual functions called to push a packet
to the TCP/IP stack only work in a softirq context and can't be called from any
kernel thread.

### When are Softirqs Executed?

The whole softirq mechanism is a cause of lots of controversy in the kernel
community. See e.g. the [following][softirq-article] recent discussion. The
short story is that softirqs can steal a CPU from a running process without the
scheduler having visibility of it. It can therefore add latency and unpredictable
jitter in sensitive workloads.

Softirqs are handled in the [do_softirq()][do-softirq] function. The core of the
function simply loops through the bits in the bitmask for the current CPU core and
executes the handler for any bit that is set:

```c
while ((softirq_bit = ffs(pending))) {
  unsigned int vec_nr;
  int prev_count;

  h += softirq_bit - 1;

  vec_nr = h - softirq_vec;
  prev_count = preempt_count();

  kstat_incr_softirqs_this_cpu(vec_nr);

  trace_softirq_entry(vec_nr);
  h->action(h);
  trace_softirq_exit(vec_nr);
  if (unlikely(prev_count != preempt_count())) {
    pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
                vec_nr, softirq_to_name[vec_nr], h->action,
                prev_count, preempt_count());
    preempt_count_set(prev_count);
  }
  h++;
  pending >>= softirq_bit;
}
```

Some of the subtleties with softirqs come from the fact that softirq handlers often
raise themselves. This is what the network RX handler does, i.e. it schedules
itself unless there was no work to do in which case it enables interrupts on the RX
queue. The logic here is that if there was work now, there should be work the next
time the handler is called.

For the above reason, if [do_softirq()][do-softirq] kept looping over pending softirqs, it could
completely starve userspace, if there's e.g. a constant stream of incoming packets.
Similarly, if it ignored any raised softirqs while it was executing and waited to be
called another time, then on an idle system it might take a while before the
softirq handler would be executed again. The current solution in the kernel is to
have a per CPU core kernel thread `ksoftirqd/n` (here n is the core number). The following
logic is applied:

1. When called, [do_softirq()][do-softirq] does one pass over the bitmask
1. If `ksoftirqd` is currently running nothing is done
1. Before returning check if any softirqs were raised while executing
1. If softirqs had been raised while running wake up `ksoftirqd`

`ksoftirqd` can keep running as long as there are unhandled softirqs. It runs at low
priority and will yield to other processes. The actual details are somewhat more
complex. Due to how softirqs are executed, different heuristics have been added to
prevent some problems. This is also part of the complaints that instead of principled
solutions heuristics get added and tuned whenever a new issue caused by softirqs is
being reported. The current softirq code does recheck for pending softirqs and runs
itself unless it has done this for too many iterations or spent too long executing.
Check the [code][__do-softirq] for details.

In other words, `ksoftirqd` is executing if there's a constant stream of softirqs
needed to be processed, so that one run of [do_softirq()][do-softirq] is not able to
finish all the work available. If `ksoftirqd` notices that there are no pending
softirqs, then it goes back to sleep until woken up again by the logic explained
above. The following is the precise inner-loop that ksoftirqd keeps executing:

```c
static struct smp_hotplug_thread softirq_threads = {
  .store			= &ksoftirqd,
  .thread_should_run		= ksoftirqd_should_run,
  .thread_fn			= run_ksoftirqd,
  .thread_comm			= "ksoftirqd/%u",
};

static __init int spawn_ksoftirqd(void)
{
  cpuhp_setup_state_nocalls(CPUHP_SOFTIRQ_DEAD, "softirq:dead", NULL,
				  takeover_tasklets);
  BUG_ON(smpboot_register_percpu_thread(&softirq_threads));

  return 0;
}
early_initcall(spawn_ksoftirqd);

static void run_ksoftirqd(unsigned int cpu)
{
  ksoftirqd_run_begin();
  if (local_softirq_pending()) {
    /*
     * We can safely run softirq on inline stack, as we are not deep
     * in the task stack here.
     */
    __do_softirq();
    ksoftirqd_run_end();
    cond_resched();
    return;
  }
  ksoftirqd_run_end();
}
```

This patchwork of heuristics has certain consequences. A CPU intensive job
running on a core that is not doing any system calls will not yield the CPU until
the next scheduler tick, which is typically set at 100Hz, so can take up to 10ms.
If an RX queue is bound to this core and interrupts are currently disabled in NAPI,
then it can take up to 10ms before the packet is processed.  However, if a server
needs to always respond within a few milliseconds, then we might have a problem.
The problem can be solved by running any CPU intensive processes on a CPU, which
is not in charge of a NIC queue.

### Busy Polling

There is also a busy polling mode where the CPU busy loops to pull packets of the
NIC. In contrast to softirq and kernel thread based polling, in this case packets
are not pushed to userspace, but pulled from there. It's therefore difficult
to discuss it before looking at socket APIs, so I will defer this to a later
part of the series.

## Getting Packets from the NIC

The kernel pulls data from the NIC by calling the [napi_poll()][__napi-poll] function.
As discussed earlier, we separately poll each queue on the device as each queue
functions independently.

At this point there's a subtle difference between whether softirq polling or
threaded polling is being used. In the [netif_napi_add()][netif-napi-add] code
discussed above we saw that the polling thread was started by `kthread_run` while
`ksoftirqd` was started by the low-level [smpboot_register_percpu_thread()][smpboot_register_percpu_thread].
Therefore, each `ksoftirqd` is pinned to a particular CPU core while the NAPI
polling threads are regular kernel threads that can be migrated to other cores by
the scheduler. This means that if we're using softirqs, then all packet
processing related to a particular queue will happen on the CPU owning the
interrupt handler. If there's a high rate of incoming packets, then any userspace
thread on the same core will be having a bad time. Note that once the packet
leaves the driver code and enters the TCP/IP stack, it can be routed to another
core using Receive Packet Steering (RPS). However, that is discussed in the next
part of the series.

We already looked at how device polling is scheduled, so let's look at the actual
polling next. We already looked at [napi_poll()][napi-poll], so let's focus on
the more low-level helper [__napi_poll()][__napi-poll]:

```c
static int __napi_poll(struct napi_struct *n, bool *repoll)
{
  int work, weight;

  weight = n->weight;

  /* This NAPI_STATE_SCHED test is for avoiding a race
   * with netpoll's poll_napi().  Only the entity which
   * obtains the lock and sees NAPI_STATE_SCHED set will
   * actually make the ->poll() call.  Therefore we avoid
   * accidentally calling ->poll() when NAPI is not scheduled.
   */
  work = 0;
  if (test_bit(NAPI_STATE_SCHED, &n->state)) {
    work = n->poll(n, weight);
    trace_napi_poll(n, work, weight);
  }

  /* Omitted */
}
```

Here we see that we call the driver's handler in `napi_struct`. Let's look at
an example of a polling function from the AWS ENI driver. The actual handler
is [ena_io_poll()][ena-io-poll], which calls [ena_clean_rx_irq()][ena-clean-rx-irq].
The latter function is called if there's still processing budget left after
acking TX completion events. Most of the code deals with device internals until
we get to:

```c
static int ena_clean_rx_irq(struct ena_ring *rx_ring, struct napi_struct *napi,
			    u32 budget)
{
  /* Omitted */

#ifdef ENA_BUSY_POLL_SUPPORT
    if (ena_bp_busy_polling(rx_ring))
	  netif_receive_skb(skb);
    else
      napi_gro_receive(napi, skb);
#else
    napi_gro_receive(napi, skb);
#endif /* ENA_BUSY_POLL_SUPPORT */

  /* Omitted */
}
```

After this the packet enters the TCP/IP stack and we stop with the appropriate
cliffhanger. Stay tuned for episode two!

## Knobs to Turn

For non-kernel developers the interesting details are the knobs that can be turned
in order to configure what happens in the steps above.

A first question to ask is why so many different methods for polling network devices?
Note that when softirqs are handled, we handle all softirqs not just the ones
belonging to the network subsystem. If all softirqs are handled in one large chunk,
then we can't for instance decouple the priority of network packet processing from
timer processing. We might have a workload that uses timers but for which packet
processing is a low priority. We can't prioritize the process over `ksoftirqd`
without breaking timers. In this case threaded NAPI polling would let us assign
a low priority to the poller threads.

A particular example of the above is audio processing on a desktop, where heavy
network traffic can cause the audio stream to stutter despite audio processing
being configured to happen at a high priority.

### IRQ Assignment

Different NICs use slightly different names for the RX queues, but looking at
`/proc/interrupts` you should be able to tell which queues interrupts are
assigned to. Note that if hyperthreading is enabled, then the even numbered
cores are your distinct physical cores.

If your application is very CPU bound, then it might make sense to try to
separate your application to different cores than your NIC queues. Alternatively,
if the cores which have NIC queues on them have much higher CPU usage, then
it might make sense to ban your application from these cores to get more
consistent performance. Run `mpstat -P ALL 1` or `htop` to see the individual core
usage and check if the cores to which the interrupts have been assigned have
higher usage. `htop` also let's you differentiate between the amount of CPU used
by kernel threads vs. userspace (green vs. red bars).

To force NIC interrupt handlers on particular cores, you can use the
`irqbalance` program. If you want to have applications and interrupt handlers
on different cores, then the simplest way is to use `taskset` to assign your
applications to particular cores and then set the banned CPUs for `irqbalance`
to include those cores. Check their man-pages for how to do this.

### Pinning Processes to Cores

The simplest way to make sure that a certain process only runs on a particular
set of CPUs is to use the `taskset` command. Check the manual pages for how to
do it. To pin a thread to a particular core, you need to set the affinity with
whatever threading API you're using.

### /proc & sysctl

From the code of [net_rx_action()][net-rx-action] we see that the first two things it reads
are `netdev_budget` and `netdev_budget_usecs`. These set the time for how long
the softirq handler can run and how many packets it's allowed to process during
one execution. These can be modified with the following sysctls:

1. `net.core.netdev_budget`
1. `net.core.netdev_budget_usecs`

We also see that [net_rx_action()][net-rx-action] updates the counter `time_squeeze` whenever
there's more work to do than it's allowed to do. If this counter keep rising,
then it might make sense to increase the two sysctl's above, especially if the
NIC is also dropping packets. If not, then changing them will have no effect.
This counter is exposed in `/proc/net/softnet_stat`.  The output of the file
looks as follows:

```
0001bfe5 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00015814 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
00012541 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002
0000fd41 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003
0000ddc2 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000004
0000ecc7 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000005
0000cbec 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000006
0000b6c6 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
0000ae17 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000008
00009aaa 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000009
0000aa11 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000a
0049a087 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000b
0000c17c 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000c
0000cc0a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000d
00019a2a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000e
0002f9f2 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000000f
0003b64a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000010
0003903f 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000011
0002feac 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000012
00024f7a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000013
```

There are no labels, so you actually have to look at the kernel sources in order to
interpret the data.  The code generating the output is [here][softnet-seq-show]. We
see from the format string that the 3rd column is the `time_squeeze` parameter in hex.

### NIC Specific Settings

NICs usually allow lots of tuning themselves, but this is very hardware specific.
Most NICs have their own documentation for tuning the hardware. Typical
configuration options include:

1. Ring buffer sizes (`ethtool -g <device>`)
1. Number of RX/TX queues (`ethtool -l <device>`)
1. RX queue selection

The `ethtool -S <device>` command is useful for seeing various device statistics.
AWS ENI NICs for instance have a stateful firewall on the NIC (the Security Group).
It has various built-in limits, which you might hit and since they happen on the
NIC they are almost invisible to userspace and can be difficult to debug.

Choosing the RX queue is a two step process inside the NIC:

1. A hash of the flow parameters is computed
1. The RX queue is looked up from an indirection table indexed by the lower order bits of the hash

More advanced hardware also support flow steering where you can directly configure
certain flows to go to a certain RX queue. For example, you can direct all traffic
to a particular port to go to a particular RX queue. `ethtool` allows modifying
both the hashing algorithm and the indirection table:

1. `-n` and `-N` options for hashing algorithms
1. `-x` and `-X` options for indirection table 

To see what acceleration features the NIC supports try `ethtool -k <device>`.

For more information check the man pages for `ethtool` and the driver docs for
your particular NIC.

### NUMA Nodes

On large machines with multiple NUMA nodes you can get a performance hit if the packet
arrives on an RX queue assigned to a different NUMA node than your thread handling
the data. Avoiding communication between NUMA nodes can therefore be useful. However,
most applications would not see much of a difference unless microsecond latency is an
issue.

You can check with `numactl --hardware` how many nodes you have and which CPUs belong
to which. If you split your threads with different CPU affinities among the NUMA nodes,
then you need to get the threads to only accept connections coming in on the RX queues
attached to the thread's NUMA node. I've never done this, but it should be doable
using `SO_ATTACH_REUSEPORT_CBPF`.

## Conclusion

Tuning the TCP/IP stack is not really possible unless you actually understand the code.
The descriptions of what a particular setting really does is usually not helpful unless
you understand the context in which it operates. Even worse, some data about what is
going on is hidden in opaque hex dumps.

Stay tuned for part II, which will will cover the protocols above the link layer. This
is where most of the things happen and where there is much more to tune.

## Further Reading

1. [Linux NIC driver docs][linux-nic-docs]
1. [Linux kernel networking][linux-net-docs]
1. [Linux interrupt handling][linux-interrupt-docs]

[internet-checksum]: https://en.wikipedia.org/wiki/Internet_checksum
[list-soft-irqs]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/interrupt.h#L548
[softirq-bitmask]: https://elixir.bootlin.com/linux/v6.2.8/source/kernel/softirq.c#L55
[softnet-data]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/netdevice.h#L3137
[napi-struct]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/netdevice.h#L345
[netif-napi-add]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/netdevice.h#L2588
[napi-schedule]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/netdevice.h#L481
[napi-complete]: https://elixir.bootlin.com/linux/v6.2.8/source/include/linux/netdevice.h#L518
[napi-poll]: https://elixir.bootlin.com/linux/v6.2.8/source/net/core/dev.c#L6536
[__napi-poll]: https://elixir.bootlin.com/linux/v6.2.8/source/net/core/dev.c#L6465
[napi-threaded-poll]: https://elixir.bootlin.com/linux/v6.2.8/source/net/core/dev.c#L6584
[raise-softirq]: https://elixir.bootlin.com/linux/v6.2.8/source/kernel/softirq.c#L700
[do-softirq]: https://elixir.bootlin.com/linux/v6.2.8/source/kernel/softirq.c#L459
[__do-softirq]: https://elixir.bootlin.com/linux/v6.2.8/source/kernel/softirq.c#L528
[ena-io-poll]: https://elixir.bootlin.com/linux/v6.2.8/source/drivers/net/ethernet/amazon/ena/ena_netdev.c#L1958
[ena-clean-rx-irq]: https://elixir.bootlin.com/linux/v6.2.8/source/drivers/net/ethernet/amazon/ena/ena_netdev.c#L1652
[softirq-article]: https://lwn.net/Articles/925540/
[netif-receive-skb]: https://elixir.bootlin.com/linux/v6.2.8/source/net/core/dev.c#L5729
[softnet-seq-show]: https://elixir.bootlin.com/linux/latest/source/net/core/net-procfs.c#L152
[linux-nic-docs]: https://www.kernel.org/doc/html/v6.2/networking/device_drivers/index.html
[linux-net-docs]: https://www.kernel.org/doc/html/v6.2/networking/index.html
[linux-interrupt-docs]: https://www.kernel.org/doc/html/v6.2/core-api/genericirq.html
[smpboot_register_percpu_thread]: https://elixir.bootlin.com/linux/v6.2.8/source/kernel/smpboot.c#L289
[net-rx-action]: https://elixir.bootlin.com/linux/v6.2.8/source/net/core/dev.c#L6632