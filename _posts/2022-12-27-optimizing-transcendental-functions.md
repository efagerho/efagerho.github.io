---
toc: true
toc_label: "Table of Contents"
toc_icon: "cog"
title:  "Computing Transcendental Functions on Modern CPUs"
date:   2022-12-27 11:39 +0200
categories:
  - blog
tags:
  - optimization
---

## Computing Transcendental Functions on Modern CPUs

Ever wondered how computers calculate functions like `sine` and `cosine`? I've noticed from
talking to people that most programmers actually have no idea. Most implementations are
based on Chebyshev polynomials and the formulas themselves look like complete magic. However,
like any polynomial approximations, the accuracy can be tuned by adding more polynomial terms.
Knowing how these functions are implemented, you can tune the accuracy for your particular
application.

The problem is that standard implementations typically provide the accuracy
of the chosen floating point type. You might not need the full 32-bit floating point accuracy.
More importantly, if you need to calculate trigonometric functions in batches, you can
significantly speed them up using SIMD ops, but your language standard library will not
support that. The formulas derived here will let you do that.

There's a famous book named *Computer Approximations* that provides numerous tables for various
transcendental functions. The book basically lists various Chebyshev polynomials and defines
tables for their coefficients. This becomes more or less magic, but armed with some basic
linear algebra you can actually derive such formulas yourself and even for your nonstandard
transcendental function as long as you have access to a computer algebra system that can do
numerical integration. However, if you actually need to come up with the fastest implementation
possible and don't need much accuracy, I would recommend consulting that book.

I'm assuming that the reader has taken a course in basic Linear Algebra and knows what terms
like *linear combination*, *span*, *linear independence*, *basis vectors* etc. mean. If you
don't, then you need to read wikipedia whenever you find a term you don't understand.

### Projections

Let `u` and `v` be vectors in `R^2`. Most people have already seen in high-school the formula

![2D Projection](/assets/images/optimization/projection2d.png){:width="50%"}

For the projection of `u` onto `v`. Here the brackets denote the *inner-product* also called
the *dot product* in `R^n`.

The projection satisfies a very interesting property. Given any other vector `w` in on the
1D subspace spanned by `v`, 
the length of the vector `|u-w|` is at least as large as `|u-P_v(u)|`. In other words, the
projection gives the *closest approximation* of `u` by a vector that is a scalar multiple of
`v`. This is the interpretation of the projection that we will be interested in.

The previous paragraph can be generalized as follows. Given any vector `u` in `R^n` and let
`V` be a subspace of `R^n`, then the projection of `u` onto `V`, denoted by `P_V(u)`, is a
vector in `V` with the property that `|u-P_V(u)| <= |u-w|` for any other vector `w` in `V`.

![3D Projection](/assets/images/optimization/projection3d.png){:width="50%"}

The picture above shows for example the projection of a third vector onto the subspace of
`R^3` spanned by two vectors. Two vectors span a plane, so this is a projection of a vector
onto a plane in `R^3`.

#### Calculating Projections

Let `V` then be any vector subspace of `R^n` and assume we have found some orthonormal basis
of unit vectors for `V`. In other words, we have vectors `v_1`, ..., `v_k` such that each
vector has length 1 and any pair-wise dot product is zero. Having found such a basis, then
we can project any vector `u` in `R^n` onto `V` using the formula:

![Projection onto basis](/assets/images/optimization/projection.png){:width="50%"}

This is quite simple. Just compute the inner-product with each basis vector and those will
give you the coefficient of the projection with respect to each basis vector.

We can turn any set of linearly independent vectors into an *orthonormal basis* using the 
[**Gram-Schmidt process**][gram-schmidt]. Gram-Schmidt is a very simple inductive process
that works as follows. Given vectors `v_1, ..., v_k`:

1. First divide `v_1` by its length, so it becomes a unit vector.
2. For `v_i`, `i=2...k` do the following:
   1. Project it to the subspace spanned by `v_1, ..., v_{i-1}` (using formula above).
   2. Subtract the projection from `v_i`.
   3. Divide `v_i` by its length to normalize it.

Check the wikipedia page if you're rusty on the details.

#### An Abstract Vector Space

A vector space is a set V such that it is closed under addition and scalar multiplication.
Furthermore, we require that it contains a zero vector, such that adding it to any vector
yields the original vector. The standard example is `R^n`, which is basically a list or real
numbers that you can add componentwise and multiply by a scalar by multiplying each element
in the list by that same scalar.

A vector space is an **inner-product space** if for each pair of vectors there is an additional 
operation called the inner-product producing a scalar. I'll let the interested reader check
the full definition on Wikipedia.

Turns out that there are many more vector spaces than just `R^n` and its subspaces. Let `V`
be the set of all continuous functions on the interval `[-1, 1]`. We can add them and
multiply them by a scalar and the result is still a continuous function. Furthermore, the 
function with the constant value zero is also a continuous function. This is actually a vector
space.

Here is where things get interesting. The space of continuous functions on `[-1,1]` has a
subspace consisting of all functions that are at most degree `k` polynomials. If we add together
two such polynomials they're still polynomials of degree at most `k`. Similarly, if you
multiply a polynomial by a constant, it remains a polynomial. This is therefore a subspace.
This subspace also has a basis given by the polynomials, `1, x, ..., x^k`. Any polynomial of
degree at most `k` can be written uniquely as a linear combination of these.

What's less obvious is that the vector space of continuous functions on `[-1,1]` is also
an *inner-product space* with the inner-product defined by:

![Inner-product](/assets/images/optimization/product.png){:width="45%"}

If you look up all the required properties of an inner-product, it's quite easy to prove
that the above formula satisfies them.

Since we have an inner-product, we also get a *length* given by:

![length](/assets/images/optimization/length.png){:width="50%"}

Given two continuous functions on `[-1,1]` we can then measure their difference by:

![difference](/assets/images/optimization/difference.png){:width="70%"}

This is just the area of the squared difference of those functions.
Note that the all the above also works with `[-1,1]` replaced by some other interval.

#### Calculating Approximations

We saw above that this abstract vector space is actually an inner-product space.
In other words, we can compute projections to a subspace! For example, a projection
of sine onto the subspace spanned by `1,x,x^2,x^3` gives us degree 3
polynomial `P(x)` that minimizes the distance

![sine approximation](/assets/images/optimization/sindiff.png){:width="35%"}

This is again the integral of the squared difference between sine and the
polynomial.

In order to compute such projections, we must find an orthonormal basis. We
can just apply Gram-Schmidt on the basis `1,x,x^2,x^3`. I'm doing the computation
here with some details omitted as I used WolframAlpha to do the integrals. This
is just a normal Gram-Schmidt calculation, but computing inner-products amount to
calculating integrals. The final orthonormal basis is at the end of the section
and the restless reader can just jump there.

**Step 1**: Normalize the first basis function. The length of the constant
function `1` is

![length 1](/assets/images/optimization/length1.png){:width="50%"}

so normalizing our first basis vector becomes the constant function `1/sqrt(2)`.

**Step 2**: Project `x` onto the first vector of the orthonormal basis:

![project x onto 1](/assets/images/optimization/projx1.png){:width="50%"}

We see that these functions are already orthogonal.

**Step 3**: Normalize the vector `x`. We just compute the length:

![norm x](/assets/images/optimization/normx.png){:width="50%"}

so the normalized vector becomes the function `sqrt(3)x/sqrt(2)`.

**Step 4**: Project `x^2` onto the space spanned by the two previous vectors:

![x^2 inner-products](/assets/images/optimization/x2dot.png){:width="60%"}

Subtracting the projection gives:

![x^2 sub inner-products](/assets/images/optimization/x2sub.png){:width="75%"}

**Step 5**: Normalize the resulting vector.
I'll skip computing the length, which can be found to be `sqrt(8/45)`. We therefore
get the 3rd orthonormal basis vector `sqrt(45/8)*(x^2-1/3)`.

**Step 6**: Project `x^3` to the subspace spanned by the previous three vectors:

![x^3 inner-products](/assets/images/optimization/x3dot.png){:width="70%"}

Subtracting the projection gives:

![x^3 sub inner-products](/assets/images/optimization/x3sub.png){:width="50%"}

**Step 7**: Normalize the vector `x^3 - 3x/5`. The length is `sqrt(8/175)`, so
the final normalized basis vector is `sqrt(175/8)*(x^3 - 3x/5)`

Finally, we have calculated our set of orthonormal basis vectors for the space
spanned by `1,x,x^2,x^3`:

![basis](/assets/images/optimization/basis.png){:width="50%"}

To compute the projection of `sine`, we calculate:

![sine projection](/assets/images/optimization/sineproj.png){:width="70%"}

Comparing our polynomial with sine we get:

![sine approximation](/assets/images/optimization/sineapprox.png)

A similar calculation for `tan` gives:

![sine projection](/assets/images/optimization/tanproj.png){:width="70%"}

Comparing our polynomial to tan we get:

![tan approximation](/assets/images/optimization/tanapprox.png)

If the interval is longer, then this method will give much better approximations
than the Taylor polynomial derived at the middle point of the interval. For example
the Taylor polynomial of tan is already a bad approximation at the edges of the
inteval:

![tan Taylor polynomial](/assets/images/optimization/tantaylor.png)

### Extending to Other Functions

Let's say you're interested in the values of `sin(e^x)` in the interval `[-2,2]`.
You won't be finding any nice library functions for computing it. The same applies
to most compound functions of transcendental functions. However, you can
use Gram-Schmidt to compute a basis for `1,x,...,x^n` for high enough `n` with the
inner-product being the integral over `[-2,2]`. Then project the function onto
this subspace. This will give you a reasonable polynomial approximation.

To select
the degree of `n` required, check how many zeros the derivative of your function has
in the interval. You will need a polynomial of higher degree than that in most cases.
Further terms might be needed to improve precision.

Note that there are other methods too, but the advantage of a fixed polynomial that
this method derives is that your code will be branch free and easy to vectorize.

### Let's Benchmark!

Enough theory. Let's write some actual code and compare runtimes. Let's check the
difference in performance between the `sine` function implementation in the
standard library compared to our polynomial implementation.

```c++
#include <benchmark/benchmark.h>
#include <cmath>
#include <random>

constexpr int kNumInputs = 10000;

void clobber()
{
    asm volatile("" : : : "memory");
}

float MySin(float x) {
  return x * (0.998075f - 0.157615f * x*x);
}

__attribute__((noinline))
void BenchmarkStd(float* __restrict__ inputs, float* __restrict__ outputs) {
  for (int i = 0; i < kNumInputs; i++) {
    outputs[i] = std::sin(inputs[i]);
  }
}

__attribute__((noinline))
void BenchmarkMy(float* __restrict__ inputs, float* __restrict__ outputs) {
  for (int i = 0; i < kNumInputs; i++) {
    outputs[i] = MySin(inputs[i]);
  }
}

static void BM_StdlibSin(benchmark::State& state) {
  float inputs[kNumInputs];
  float outputs[kNumInputs];

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(0, 1);

  for (int i = 0; i < kNumInputs; i++) {
    inputs[i] = dist(gen);
  }

  for (auto _ : state) {
    BenchmarkStd(inputs, outputs);
    clobber();
  }
}

static void BM_MySin(benchmark::State& state) {
  float inputs[kNumInputs];
  float outputs[kNumInputs];

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(0, 1);

  for (int i = 0; i < kNumInputs; i++) {
    inputs[i] = dist(gen);
  }

  for (auto _ : state) {
    BenchmarkMy(inputs, outputs);
    clobber();
  }
}

BENCHMARK(BM_StdlibSin);
BENCHMARK(BM_MySin);
BENCHMARK_MAIN();
```

We use a buffer of values instead of a single value, since the standard library
implementation contains branches, so a single value in a loop would cause the
CPU branch predictor to guess all branches correctly. The buffer is also chosen
small enough that it fully fits in the L1 cache, so that we are not actually
benchmarking the memory subsystem.

Running the code we see that the standard library version is about 60x slower:

```
-------------------------------------------------------
Benchmark             Time             CPU   Iterations
-------------------------------------------------------
BM_StdlibSin      50886 ns        50877 ns        10816
BM_MySin            840 ns          839 ns       808548
```

Looking at the [assembly output][assembly], the main difference here is that the `MySin` function
is easy to inline and can be vectorized while the former can't.

Note that the `MySin` implementation could be further optimized. We see that the AVX
code currently uses unaligned load instructions. I also haven't checked with a profiler
what the current bottleneck is. However, the goal wasn't to spend a lot of time on
the vectorized code. In most settings, the single function call latency is more
important.

### Conclusion

If you need to evaluate trigonometric functions and you know your input range, then
using the methods explained here, you can derive much faster implementations than
what your language standard library will provide.

Most computer algebra systems also have built-in functions for calculating polynomial
approximations. You can also sample points on your function and then fit a polynomial
to those points. However, these methods are less accurate and depend on the particular
set of points that you happened to sample.

[gram-schmidt]:https://en.wikipedia.org/wiki/Gram%E2%80%93Schmidt_process
[assembly]:https://godbolt.org/z/1MEe8rhnG
