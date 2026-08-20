/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdlib.h>
#include <rte_log.h>
#include "rte_approx.h"

/*
 * Based on paper "Approximating Rational Numbers by Fractions" by Michal
 * Forisek forisek@dcs.fmph.uniba.sk
 *
 * Given a rational number alpha with 0 < alpha < 1 and a precision d, the goal
 * is to find positive integers p, q such that alpha - d < p/q < alpha + d, and
 * q is minimal.
 *
 * http://people.ksp.sk/~misof/publications/2007approx.pdf
 */

/* fraction comparison: compare (a/b) and (c/d) */
static inline uint32_t
less(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	return a*d < b*c;
}

static inline uint32_t
less_or_equal(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	return a*d <= b*c;
}

/* check whether a/b is a valid approximation */
static inline uint32_t
matches(uint32_t a, uint32_t b,
	uint32_t alpha_num, uint32_t d_num, uint32_t denum)
{
	if (less_or_equal(a, b, alpha_num - d_num, denum))
		return 0;

	if (less(a ,b, alpha_num + d_num, denum))
		return 1;

	return 0;
}

static inline void
find_exact_solution_left(uint32_t p_a, uint32_t q_a, uint32_t p_b, uint32_t q_b,
	uint32_t alpha_num, uint32_t d_num, uint32_t denum, uint32_t *p, uint32_t *q)
{
	uint32_t k_num = denum * p_b - (alpha_num + d_num) * q_b;
	uint32_t k_denum = (alpha_num + d_num) * q_a - denum * p_a;
	uint32_t k = (k_num / k_denum) + 1;

	*p = p_b + k * p_a;
	*q = q_b + k * q_a;
}

static inline void
find_exact_solution_right(uint32_t p_a, uint32_t q_a, uint32_t p_b, uint32_t q_b,
	uint32_t alpha_num, uint32_t d_num, uint32_t denum, uint32_t *p, uint32_t *q)
{
	uint32_t k_num = - denum * p_b + (alpha_num - d_num) * q_b;
	uint32_t k_denum = - (alpha_num - d_num) * q_a + denum * p_a;
	uint32_t k = (k_num / k_denum) + 1;

	*p = p_b + k * p_a;
	*q = q_b + k * q_a;
}

static int
find_best_rational_approximation(uint32_t alpha_num, uint32_t d_num, uint32_t denum, uint32_t *p, uint32_t *q)
{
	uint32_t p_a, q_a, p_b, q_b;

	/* check assumptions on the inputs */
	if (!((0 < d_num) && (d_num < alpha_num) && (alpha_num < denum) && (d_num + alpha_num < denum))) {
		return -1;
	}

	/* set initial bounds for the search */
	p_a = 0;
	q_a = 1;
	p_b = 1;
	q_b = 1;

	while (1) {
		uint32_t new_p_a, new_q_a, new_p_b, new_q_b;
		uint32_t x_num, x_denum, x;
		int aa, bb;

		/* compute the number of steps to the left */
		x_num = denum * p_b - alpha_num * q_b;
		x_denum = - denum * p_a + alpha_num * q_a;
		x = (x_num + x_denum - 1) / x_denum; /* x = ceil(x_num / x_denum) */

		/* check whether we have a valid approximation */
		aa = matches(p_b + x * p_a, q_b + x * q_a, alpha_num, d_num, denum);
		bb = matches(p_b + (x-1) * p_a, q_b + (x - 1) * q_a, alpha_num, d_num, denum);
		if (aa || bb) {
			find_exact_solution_left(p_a, q_a, p_b, q_b, alpha_num, d_num, denum, p, q);
			return 0;
		}

		/* update the interval */
		new_p_a = p_b + (x - 1) * p_a ;
		new_q_a = q_b + (x - 1) * q_a;
		new_p_b = p_b + x * p_a ;
		new_q_b = q_b + x * q_a;

		p_a = new_p_a ;
		q_a = new_q_a;
		p_b = new_p_b ;
		q_b = new_q_b;

		/* compute the number of steps to the right */
		x_num = alpha_num * q_b - denum * p_b;
		x_denum = - alpha_num * q_a + denum * p_a;
		x = (x_num + x_denum - 1) / x_denum; /* x = ceil(x_num / x_denum) */

		/* check whether we have a valid approximation */
		aa = matches(p_b + x * p_a, q_b + x * q_a, alpha_num, d_num, denum);
		bb = matches(p_b + (x - 1) * p_a, q_b + (x - 1) * q_a, alpha_num, d_num, denum);
		if (aa || bb) {
			find_exact_solution_right(p_a, q_a, p_b, q_b, alpha_num, d_num, denum, p, q);
			return 0;
		 }

		/* update the interval */
		new_p_a = p_b + (x - 1) * p_a;
		new_q_a = q_b + (x - 1) * q_a;
		new_p_b = p_b + x * p_a;
		new_q_b = q_b + x * q_a;

		p_a = new_p_a;
		q_a = new_q_a;
		p_b = new_p_b;
		q_b = new_q_b;
	}
}

int rte_approx(double alpha, double d, uint32_t *p, uint32_t *q)
{
	uint32_t alpha_num, d_num, denum;

	/* Check input arguments */
	if (!((0.0 < d) && (d < alpha) && (alpha < 1.0))) {
		return -1;
	}

	if ((p == NULL) || (q == NULL)) {
		return -2;
	}

	/* Compute alpha_num, d_num and denum */
	denum = 1;
	while (d < 1) {
		alpha *= 10;
		d *= 10;
		denum *= 10;
	}
	alpha_num = (uint32_t) alpha;
	d_num = (uint32_t) d;

	/* Perform approximation */
	return find_best_rational_approximation(alpha_num, d_num, denum, p, q);
}

static
int rte_approx_get(uint32_t numerator, uint32_t denominator, uint32_t burst,
		   uint32_t *p, uint32_t *q)
{
	uint32_t d = 1;

	/*
	 * We need to restrict the numerator value returned so that it's
	 * less than the shaper burst.  If it exceeds it when we add tokens
	 * the value will be reset to the burst thereby reducing the tokens
	 * which results in a shaper shortfall.
	 */

	uint32_t denum = burst;
	uint32_t alpha = ((uint64_t) numerator * (uint64_t) denum) /
				denominator;
	int rv;

	while (alpha < 4 && denum > 1) {
		denum <<= 1;
		alpha = ((uint64_t) numerator * (uint64_t) denum) / denominator;
	}

	/*
	 * The following is required to avoid find_best_rational_approximation's
	 * input argument checking.
	 */
	alpha = alpha - d;

	/* Perform approximation */
	rv = find_best_rational_approximation(alpha, d, denum, p, q);
	if (rv) {
		RTE_LOG(ERR, SCHED,
			"numer: %u, denominator: %u, alpha: %u, denum: %u\n",
			numerator, denominator, alpha, denum);
	}
	return rv;
}

int __rte_experimental
rte_approx_int(uint32_t numerator, uint32_t denominator,
	       uint32_t *p, uint32_t *q)
{
	/*
	 * The best value proved to be 16383 from the following range tried:
	 * 13131, 16383, 17467, 32003, 48017, 64007, 93931 and 131317
	 */
	return rte_approx_get(numerator, denominator, 16383, p, q);
}
