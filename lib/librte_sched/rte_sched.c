/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_bitmap.h>
#include <rte_reciprocal.h>

#include "rte_sched.h"
#include "rte_sched_common.h"
#include "rte_approx.h"

#ifdef __INTEL_COMPILER
#pragma warning(disable:2259) /* conversion may lose significant bits */
#endif

#ifdef RTE_SCHED_VECTOR
#include <rte_vect.h>

#ifdef RTE_ARCH_X86
#define SCHED_VECTOR_SSE4
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
#define SCHED_VECTOR_NEON
#endif

#endif

#define RTE_SCHED_BYTERATE_TO_BITRATE_SHIFT   3
#define RTE_SCHED_GRINDER_PCACHE_SIZE         (64 / RTE_SCHED_QUEUES_PER_PIPE)
#define RTE_SCHED_PIPE_INVALID                UINT32_MAX
#define RTE_SCHED_BMP_POS_INVALID             UINT32_MAX

/* Scaling for cycles_per_byte calculation
 * Chosen so that minimum rate is 480 bit/sec
 */
#define RTE_SCHED_TIME_SHIFT		      8

struct rte_sched_subport {
	/* Token bucket (TB) */
	uint64_t tb_time; /* time of last update */
	uint32_t tb_period;
	uint32_t tb_credits_per_period;
	uint32_t tb_size;
	uint32_t tb_credits;

	/* Traffic classes (TCs) */
	uint64_t tc_time; /* time of next update */
	uint32_t tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	int32_t tc_credits[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint16_t qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_period;

	/* TC oversubscription */
	uint32_t tc_ov_wm;
	uint32_t tc_ov_wm_min;
	uint32_t tc_ov_wm_max;
	uint8_t tc_ov_period_id;
	uint8_t tc_ov;
	uint32_t tc_ov_n;
	double tc_ov_rate;

	/* Statistics */
	struct rte_sched_subport_stats stats;

	/* Queue base calculation */
	uint32_t qsize_add[RTE_SCHED_QUEUES_PER_PIPE];
	uint32_t qsize_sum;
	uint32_t qoffset;

#ifdef RTE_SCHED_RED
	struct rte_red_config red_config[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][RTE_COLORS];
#endif
};

struct rte_sched_pipe_profile {
	/* Token bucket (TB) */
	uint32_t tb_period;
	uint32_t tb_credits_per_period;
	uint32_t tb_size;

	/* Pipe traffic classes */
	uint32_t tc_period;
	uint32_t tc_credits_per_period[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint8_t tc_ov_weight;

	/* Pipe queues */
	uint8_t  wrr_cost[RTE_SCHED_QUEUES_PER_PIPE];
};

struct rte_sched_pipe {
	/* Token bucket (TB) */
	uint64_t tb_time; /* time of last update */
	uint32_t tb_credits;

	/* Pipe profile and flags */
	uint32_t profile;

	/* Traffic classes (TCs) */
	uint64_t tc_time; /* time of next update */
	int32_t tc_credits[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

	/* Weighted Round Robin (WRR) */
	uint32_t wrr_tokens[RTE_SCHED_QUEUES_PER_PIPE];

	/* TC oversubscription */
	uint32_t tc_ov_credits;
	uint8_t tc_ov_period_id;
	uint8_t reserved[3];
} __rte_cache_aligned;

struct rte_sched_queue {
	uint16_t qw;
	uint16_t qr;
};

enum grinder_state {
	e_GRINDER_PREFETCH_PIPE = 0,
	e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS,
	e_GRINDER_PREFETCH_MBUF,
	e_GRINDER_READ_MBUF
};

enum token_state {
	TOKENS_UNDEFINED = 0,
	TOKENS_USED,
	TOKENS_AVAIL
};

_Static_assert(RTE_SCHED_QUEUES_PER_PIPE <= 32, "Too many queues per pipe");

#if RTE_SCHED_QUEUES_PER_PIPE != 32
typedef uint16_t qbitmask_t;
#else
typedef uint32_t qbitmask_t;
#endif

struct rte_sched_grinder {
	/* Pipe cache */
	qbitmask_t pcache_qmask[RTE_SCHED_GRINDER_PCACHE_SIZE];
	uint32_t pcache_qindex[RTE_SCHED_GRINDER_PCACHE_SIZE];
	uint32_t pcache_w;
	uint32_t pcache_r;

	/* Current pipe */
	enum grinder_state state;
	uint32_t productive;
	uint32_t pindex;
	struct rte_sched_subport *subport;
	struct rte_sched_pipe *pipe;
	struct rte_sched_pipe_profile *pipe_params;

	/* TC cache */
	uint8_t tccache_qmask[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tccache_qindex[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tccache_w;
	uint32_t tccache_r;

	/* Current TC */
	uint32_t tc_index;
	struct rte_sched_queue *queue[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	struct rte_mbuf **qbase[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	uint32_t qindex[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	uint16_t qsize;
	uint32_t qmask;
	uint32_t qpos;
	struct rte_mbuf *pkt;

	/* WRR */
	uint32_t wrr_tokens[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	uint32_t wrr_mask[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	uint8_t wrr_cost[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
};

struct rte_sched_port {
	/* User parameters */
	uint32_t n_subports_per_port;
	uint32_t n_pipes_per_subport;
	uint32_t rate;
	uint32_t mtu;
	int32_t frame_overhead;
	uint16_t qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t n_pipe_profiles;
	uint32_t pipe_low_prio_tc_rate_max;
#ifdef RTE_SCHED_RED
	struct rte_red_config red_config[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE][RTE_COLORS];
#endif

	/* Timing */
	uint64_t time_cpu_cycles;     /* Current CPU time measured in CPU cyles */
	uint64_t time_cpu_bytes;      /* Current CPU time measured in bytes */
	uint64_t time;                /* Current NIC TX time measured in bytes */
	struct rte_reciprocal inv_cycles_per_byte; /* CPU cycles per byte */
	uint64_t cycles_per_byte;

	/* Scheduling loop detection */
	uint32_t pipe_loop;
	uint32_t pipe_exhaustion;

	/* Bitmap */
	struct rte_bitmap *bmp;
	uint32_t grinder_base_bmp_pos[RTE_SCHED_PORT_N_GRINDERS] __rte_aligned_16;

	/* Grinders */
	struct rte_sched_grinder grinder[RTE_SCHED_PORT_N_GRINDERS];
	uint32_t busy_grinders;
	struct rte_mbuf **pkts_out;
	uint32_t n_pkts_out;

	/* Large data structures */
	struct rte_sched_subport *subport;
	struct rte_sched_pipe *pipe;
	struct rte_sched_queue *queue;
	struct rte_sched_queue_extra *queue_extra;
	struct rte_sched_pipe_profile *pipe_profiles;
	uint8_t *bmp_array;
	struct rte_mbuf **queue_array;
	uint8_t memory[0] __rte_cache_aligned;
} __rte_cache_aligned;

enum rte_sched_port_array {
	e_RTE_SCHED_PORT_ARRAY_SUBPORT = 0,
	e_RTE_SCHED_PORT_ARRAY_PIPE,
	e_RTE_SCHED_PORT_ARRAY_QUEUE,
	e_RTE_SCHED_PORT_ARRAY_QUEUE_EXTRA,
	e_RTE_SCHED_PORT_ARRAY_PIPE_PROFILES,
	e_RTE_SCHED_PORT_ARRAY_BMP_ARRAY,
	e_RTE_SCHED_PORT_ARRAY_QUEUE_ARRAY,
	e_RTE_SCHED_PORT_ARRAY_TOTAL,
};

#ifdef RTE_SCHED_COLLECT_STATS

static inline uint32_t
rte_sched_port_queues_per_subport(struct rte_sched_port *port)
{
	return RTE_SCHED_QUEUES_PER_PIPE * port->n_pipes_per_subport;
}

#endif

uint32_t
rte_sched_port_queues_per_port(struct rte_sched_port *port)
{
	return RTE_SCHED_QUEUES_PER_PIPE * port->n_pipes_per_subport * port->n_subports_per_port;
}

static inline struct rte_mbuf **
rte_sched_port_qbase(struct rte_sched_port *port, uint32_t qindex)
{
	uint32_t qpos = qindex & RTE_SCHED_TC_WRR_MASK;
	uint32_t subport_id = qindex / rte_sched_port_queues_per_subport(port);
	struct rte_sched_subport *subport = port->subport + subport_id;
	uint32_t pipe_id;

	pipe_id = qindex -
		(subport_id * rte_sched_port_queues_per_subport(port));
	pipe_id = pipe_id / RTE_SCHED_QUEUES_PER_PIPE;

	return (port->queue_array + subport->qoffset +
		(pipe_id * subport->qsize_sum) +
		subport->qsize_add[qpos]);
}

static inline uint16_t
rte_sched_port_qsize(struct rte_sched_port *port, uint32_t qindex)
{
	uint32_t tc = (qindex >> RTE_SCHED_WRR_BITS) & RTE_SCHED_TC_MASK;
	uint32_t subport_id = qindex / rte_sched_port_queues_per_subport(port);
	struct rte_sched_subport *subport = port->subport + subport_id;

	return subport->qsize[tc];
}

static int
pipe_profile_check(struct rte_sched_pipe_params *params,
	uint32_t rate)
{
	uint32_t i;

	/* Pipe parameters */
	if (params == NULL)
		return -10;

	/* TB rate: non-zero, not greater than port rate */
	if (params->tb_rate == 0 ||
		params->tb_rate > rate)
		return -11;

	/* TB size: non-zero */
	if (params->tb_size == 0)
		return -12;

	/* TC rate: non-zero, less than pipe rate */
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		if (params->tc_rate[i] == 0 ||
			params->tc_rate[i] > params->tb_rate)
			return -13;
	}

	/* TC period: non-zero */
	if (params->tc_period == 0)
		return -14;

#ifdef RTE_SCHED_SUBPORT_TC_OV
	/* Lowest priority TC oversubscription weight: non-zero */
	if (params->tc_ov_weight == 0)
		return -15;
#endif

	/* Queue WRR weights: non-zero */
	for (i = 0; i < RTE_SCHED_QUEUES_PER_PIPE; i++) {
		if (params->wrr_weights[i] == 0)
			return -16;
	}

	return 0;
}

static int
rte_sched_port_check_params(struct rte_sched_port_params *params)
{
	uint32_t i;

	if (params == NULL)
		return -1;

	/* socket */
	if (params->socket < 0)
		return -3;

	/* rate */
	if (params->rate == 0)
		return -4;

	/* mtu */
	if (params->mtu == 0)
		return -5;

	/* n_subports_per_port: non-zero, limited to 16 bits, power of 2 */
	if (params->n_subports_per_port == 0 ||
	    params->n_subports_per_port > 1u << 16 ||
	    !rte_is_power_of_2(params->n_subports_per_port))
		return -6;

	/* n_pipes_per_subport: non-zero, power of 2 */
	if (params->n_pipes_per_subport == 0 ||
	    !rte_is_power_of_2(params->n_pipes_per_subport))
		return -7;

	/* qsize: non-zero, power of 2,
	 * no bigger than 32K (due to 16-bit read/write pointers)
	 */
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint16_t qsize = params->qsize[i];

		if (qsize == 0 || !rte_is_power_of_2(qsize))
			return -8;
	}

	/* pipe_profiles and n_pipe_profiles */
	if (params->pipe_profiles == NULL ||
	    params->n_pipe_profiles == 0 ||
	    params->n_pipe_profiles > RTE_SCHED_PIPE_PROFILES_PER_PORT)
		return -9;

	for (i = 0; i < params->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *p = params->pipe_profiles + i;
		int status;

		status = pipe_profile_check(p, params->rate);
		if (status != 0)
			return status;
	}

	return 0;
}

static uint32_t
rte_sched_port_get_array_base(struct rte_sched_port_params *params,
			      enum rte_sched_port_array array,
			      uint32_t size_queue_array)
{
	uint32_t n_subports_per_port = params->n_subports_per_port;
	uint32_t n_pipes_per_subport = params->n_pipes_per_subport;
	uint32_t n_pipes_per_port = n_pipes_per_subport * n_subports_per_port;
	uint32_t n_queues_per_port = RTE_SCHED_QUEUES_PER_PIPE * n_pipes_per_subport * n_subports_per_port;

	uint32_t size_subport = n_subports_per_port * sizeof(struct rte_sched_subport);
	uint32_t size_pipe = n_pipes_per_port * sizeof(struct rte_sched_pipe);
	uint32_t size_queue = n_queues_per_port * sizeof(struct rte_sched_queue);
	uint32_t size_queue_extra
		= n_queues_per_port * sizeof(struct rte_sched_queue_extra);
	uint32_t size_pipe_profiles
		= RTE_SCHED_PIPE_PROFILES_PER_PORT * sizeof(struct rte_sched_pipe_profile);
	uint32_t size_bmp_array = rte_bitmap_get_memory_footprint(n_queues_per_port);
	uint32_t size_per_pipe_queue_array;

	uint32_t base, i;

	if (size_queue_array == 0) {
		size_per_pipe_queue_array = 0;
		for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
			size_per_pipe_queue_array +=
				RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS
				* params->qsize[i] * sizeof(struct rte_mbuf *);
		}
		size_queue_array = n_pipes_per_port * size_per_pipe_queue_array;
	}

	base = 0;

	if (array == e_RTE_SCHED_PORT_ARRAY_SUBPORT)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_subport);

	if (array == e_RTE_SCHED_PORT_ARRAY_PIPE)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_pipe);

	if (array == e_RTE_SCHED_PORT_ARRAY_QUEUE)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue);

	if (array == e_RTE_SCHED_PORT_ARRAY_QUEUE_EXTRA)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue_extra);

	if (array == e_RTE_SCHED_PORT_ARRAY_PIPE_PROFILES)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_pipe_profiles);

	if (array == e_RTE_SCHED_PORT_ARRAY_BMP_ARRAY)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_bmp_array);

	if (array == e_RTE_SCHED_PORT_ARRAY_QUEUE_ARRAY)
		return base;
	base += RTE_CACHE_LINE_ROUNDUP(size_queue_array);

	return base;
}

static uint32_t
rte_sched_port_get_memory_footprint_common(struct rte_sched_port_params *params,
					   uint32_t size_queue_array)
{
	uint32_t size0, size1;
	int status;

	status = rte_sched_port_check_params(params);
	if (status != 0) {
		RTE_LOG(NOTICE, SCHED,
			"Port scheduler params check failed (%d)\n", status);

		return 0;
	}

	size0 = sizeof(struct rte_sched_port);
	size1 = rte_sched_port_get_array_base(params,
					      e_RTE_SCHED_PORT_ARRAY_TOTAL,
					      size_queue_array);

	return size0 + size1;
}

uint32_t
rte_sched_port_get_memory_footprint(struct rte_sched_port_params *params)
{
	return rte_sched_port_get_memory_footprint_common(params, 0);
}

uint32_t
rte_sched_port_get_memory_footprint_v2(struct rte_sched_port_params *params,
				       uint32_t size_queue_array)
{
	return rte_sched_port_get_memory_footprint_common(params,
							  size_queue_array);
}

static void
rte_sched_subport_config_qsize(struct rte_sched_port *port,
			       uint32_t subport_id,
			       uint16_t *qsize)
{
	struct rte_sched_subport *subport = port->subport + subport_id;
	uint32_t tc;
	uint32_t q;
	uint32_t index;

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		if (qsize == NULL)
			/* The subport inherits its qsizes from the port */
			subport->qsize[tc] = port->qsize[tc];
		else
			/* The subport has explicity configure qsizes */
			subport->qsize[tc] = qsize[tc];
	}

	index = 0;
	subport->qsize_add[index] = 0;
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
                if (tc != 0)
			subport->qsize_add[index] =
				subport->qsize_add[index - 1] +
				subport->qsize[tc - 1];

		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++) {
			if (q != 0)
				subport->qsize_add[index] =
					subport->qsize_add[index - 1] +
					subport->qsize[tc];

			index++;
		}
	}
	subport->qsize_sum = subport->qsize_add[index - 1] +
		subport->qsize[RTE_SCHED_MAX_TC];

	/*
	 * Accumulate each subport's qsize_sum across all subports to
	 * calculate the queue-array offset for this subport.
	 * This only works if subports are configured sequentially.
	 */
	if (subport_id != 0) {
		struct rte_sched_subport *prev = port->subport +
			(subport_id - 1);

		subport->qoffset = prev->qoffset +
			(prev->qsize_sum * port->n_pipes_per_subport);
	}
}

static char *
rte_sched_build_credit_array_string(uint32_t *tc_credits_per_period,
				    char *output_str)
{
	uint32_t tc;
	int str_len;

	str_len = sprintf(output_str, "[");
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		str_len += sprintf(output_str + str_len, "%u",
				   tc_credits_per_period[tc]);
		if (tc != RTE_SCHED_MAX_TC)
			str_len += sprintf(output_str + str_len, ", ");
	}
	sprintf(output_str + str_len, "]");
	return output_str;
}

static char *
rte_sched_build_wrr_cost_string(struct rte_sched_pipe_profile *p,
				char *output_str)
{
	uint32_t wrr;
	int str_len;

	str_len = sprintf(output_str, "[");
	for (wrr = 0; wrr < RTE_SCHED_QUEUES_PER_PIPE; wrr++) {
		str_len += sprintf(output_str + str_len, "%hhu",
				   p->wrr_cost[wrr]);
		if (wrr != RTE_SCHED_QUEUES_PER_PIPE - 1)
			str_len += sprintf(output_str + str_len, ", ");
	}
	sprintf(output_str + str_len, "]");
	return output_str;
}

static char *
rte_sched_build_queue_size_string(uint16_t *qsize, char *output_str)
{
	uint32_t tc;
	int str_len;

	str_len = sprintf(output_str, "[");
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		str_len += sprintf(output_str + str_len, "%u",
				   qsize[tc]);
		if (tc != RTE_SCHED_MAX_TC)
			str_len += sprintf(output_str + str_len, ", ");
	}
	sprintf(output_str + str_len, "]");
	return output_str;
}


static void
rte_sched_port_log_pipe_profile(struct rte_sched_port *port, uint32_t i)
{
	struct rte_sched_pipe_profile *p = port->pipe_profiles + i;
	char credits_str[(12 * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) + 3];
	char wrr_cost_str[(5 * RTE_SCHED_QUEUES_PER_PIPE) + 3];

	rte_sched_build_credit_array_string(p->tc_credits_per_period,
					    credits_str);
	rte_sched_build_wrr_cost_string(p, wrr_cost_str);

	RTE_LOG(DEBUG, SCHED, "Low level config for pipe profile %u:\n"
		"    Token bucket: period = %u, credits per period = %u, size = %u\n"
		"    Traffic classes: period = %u, credits per period = %s\n"
		"    Traffic class 3 oversubscription: weight = %hhu\n"
		"    WRR cost: %s\n",
		i,

		/* Token bucket */
		p->tb_period,
		p->tb_credits_per_period,
		p->tb_size,

		/* Traffic classes */
		p->tc_period,
		credits_str,

		/* Traffic class 3 oversubscription */
		p->tc_ov_weight,

		/* WRR */
		wrr_cost_str);
}

static inline uint64_t
rte_sched_time_us_to_bytes(uint32_t time_us, uint32_t rate)
{
	uint64_t time = time_us;

	time = (time * rate) / 1000000;

	/* Don't allow a zero byte count */
	if (!time)
		return 1;

	return time;
}

static inline uint64_t
rte_sched_time_ms_to_bytes(uint32_t time_ms, uint32_t rate)
{
	uint64_t time = time_ms;

	time = (time * rate) / 1000;

	return time;
}

static uint32_t rte_sched_reduce_to_byte(uint32_t value)
{
	uint32_t shift = 0;

	while (value & 0xFFFFFF00) {
		value >>= 1;
		shift++;
	}
	return shift;
}

static void
rte_sched_pipe_profile_convert(struct rte_sched_pipe_params *src,
	struct rte_sched_pipe_profile *dst,
	uint32_t rate)
{
	uint32_t i;

	/* Token Bucket */
	if (src->tb_rate == rate) {
		dst->tb_credits_per_period = 1;
		dst->tb_period = 1;
	} else {
		rte_approx_int(src->tb_rate, rate,
			&dst->tb_credits_per_period, &dst->tb_period);
	}

	/*
	 * The period must be less than or equal to the burst otherwise
	 * we lose a bunch of tokens every period because the maximum
	 * the token bucket is allowed to be is the burst.
	 */
	dst->tb_size = src->tb_size;
	if (dst->tb_credits_per_period > dst->tb_size)
		dst->tb_size = dst->tb_credits_per_period;

	/* Traffic Classes */
	dst->tc_period = rte_sched_time_us_to_bytes(src->tc_period,
						rate);

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		dst->tc_credits_per_period[i]
			= rte_sched_time_us_to_bytes(src->tc_period,
				src->tc_rate[i]);

#ifdef RTE_SCHED_SUBPORT_TC_OV
	dst->tc_ov_weight = src->tc_ov_weight;
#endif

	/* WRR */
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint32_t wrr_cost[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
		uint32_t lcd[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
		uint32_t lcd_elements;
		uint32_t qindex;
		uint32_t low_pos;
		uint32_t shift;
		uint32_t q;

		qindex = i * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		     q++) {
			lcd[q] = src->wrr_weights[qindex + q];
			wrr_cost[q] = lcd[q];
		}

		/*
		 * Calculate the LCD of an array of wrr_costs.
		 * The number of elements in the array must be a power
		 * of two.  Calculate the LCD of two adjacent values,
		 * store the results back in the array, each time
		 * around the while loop halves the number of active
		 * elements in the array.
		 * The answer eventually appears in lcd[0].
		 */
		lcd_elements = RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		while (lcd_elements > 1) {
			for (q = 0;
			     q < lcd_elements;
			     q += 2) {
				lcd[q/2] = rte_get_lcd(lcd[q],
						       lcd[q + 1]);
			}
			lcd_elements >>= 1;
		}

		/*
		 * Remember where the lowest wrr_cost is.
		 */
		low_pos = rte_min_pos_n_u32(wrr_cost,
			       RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
			wrr_cost[q] = lcd[0] / wrr_cost[q];

		/*
		 * Where we had the lowest wrr_cost will now have the
		 * highest value.  How far right do we have to shift it
		 * in order to fit its most-significant bits into a
		 * byte.
		 */
		shift = rte_sched_reduce_to_byte(wrr_cost[low_pos]);
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		     q++) {
			wrr_cost[q] >>= shift;

			if (wrr_cost[q] == 0)
				wrr_cost[q]++;

			dst->wrr_cost[qindex + q] =
				(uint8_t) wrr_cost[q];
		}
	}
}

static void
rte_sched_port_config_pipe_profile_table(struct rte_sched_port *port,
	struct rte_sched_port_params *params)
{
	uint32_t i;

	for (i = 0; i < port->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *src = params->pipe_profiles + i;
		struct rte_sched_pipe_profile *dst = port->pipe_profiles + i;

		rte_sched_pipe_profile_convert(src, dst, params->rate);
		rte_sched_port_log_pipe_profile(port, i);
	}

	port->pipe_low_prio_tc_rate_max = 0;
	for (i = 0; i < port->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *src = params->pipe_profiles + i;
		uint32_t pipe_low_prio_tc_rate = src->tc_rate[RTE_SCHED_MAX_TC];

		if (port->pipe_low_prio_tc_rate_max < pipe_low_prio_tc_rate)
			port->pipe_low_prio_tc_rate_max = pipe_low_prio_tc_rate;
	}
}

static struct rte_sched_port *
rte_sched_port_config_common(struct rte_sched_port_params *params,
			     uint32_t mem_size)
{
	struct rte_sched_port *port = NULL;
	uint32_t bmp_mem_size, n_queues_per_port, i, cycles_per_byte;

	/* Allocate memory to store the data structures */
	port = rte_zmalloc_socket("qos_params", mem_size, RTE_CACHE_LINE_SIZE,
		params->socket);
	if (port == NULL)
		return NULL;

	/* compile time checks */
	RTE_BUILD_BUG_ON(RTE_SCHED_PORT_N_GRINDERS == 0);
	RTE_BUILD_BUG_ON(RTE_SCHED_PORT_N_GRINDERS & (RTE_SCHED_PORT_N_GRINDERS - 1));

	/* User parameters */
	port->n_subports_per_port = params->n_subports_per_port;
	port->n_pipes_per_subport = params->n_pipes_per_subport;
	port->rate = params->rate;
	port->mtu = params->mtu + params->frame_overhead;
	port->frame_overhead = params->frame_overhead;
	memcpy(port->qsize, params->qsize, sizeof(params->qsize));
	port->n_pipe_profiles = params->n_pipe_profiles;

#ifdef RTE_SCHED_RED
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint32_t j;

		for (j = 0; j < RTE_COLORS; j++) {
			/* if min/max are both zero, then RED is disabled */
			if ((params->red_params[i][j].min_th |
			     params->red_params[i][j].max_th) == 0) {
				continue;
			}

			if (rte_red_config_init(&port->red_config[i][j],
				params->red_params[i][j].wq_log2,
				params->red_params[i][j].min_th,
				params->red_params[i][j].max_th,
				params->red_params[i][j].maxp_inv) != 0) {
				rte_free(port);
				return NULL;
			}
		}
	}
#endif

	/* Timing */
	port->time_cpu_cycles = rte_get_tsc_cycles();
	port->time_cpu_bytes = 0;
	port->time = 0;

	cycles_per_byte = (rte_get_tsc_hz() << RTE_SCHED_TIME_SHIFT)
		/ params->rate;
	port->inv_cycles_per_byte = rte_reciprocal_value(cycles_per_byte);
	port->cycles_per_byte = cycles_per_byte;

	/* Scheduling loop detection */
	port->pipe_loop = RTE_SCHED_PIPE_INVALID;
	port->pipe_exhaustion = 0;

	/* Grinders */
	port->busy_grinders = 0;
	port->pkts_out = NULL;
	port->n_pkts_out = 0;

	/* Large data structures */
	port->subport = (struct rte_sched_subport *)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_SUBPORT,
							      0));
	port->pipe = (struct rte_sched_pipe *)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_PIPE,
							      0));
	port->queue = (struct rte_sched_queue *)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_QUEUE,
							      0));
	port->queue_extra = (struct rte_sched_queue_extra *)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_QUEUE_EXTRA,
							      0));
	port->pipe_profiles = (struct rte_sched_pipe_profile *)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_PIPE_PROFILES,
							      0));
	port->bmp_array =  port->memory
		+ rte_sched_port_get_array_base(params, e_RTE_SCHED_PORT_ARRAY_BMP_ARRAY,
						0);
	port->queue_array = (struct rte_mbuf **)
		(port->memory + rte_sched_port_get_array_base(params,
							      e_RTE_SCHED_PORT_ARRAY_QUEUE_ARRAY,
							      0));

	/* Pipe profile table */
	rte_sched_port_config_pipe_profile_table(port, params);

	/* Bitmap */
	n_queues_per_port = rte_sched_port_queues_per_port(port);
	bmp_mem_size = rte_bitmap_get_memory_footprint(n_queues_per_port);
	port->bmp = rte_bitmap_init(n_queues_per_port, port->bmp_array,
				    bmp_mem_size);
	if (port->bmp == NULL) {
		RTE_LOG(ERR, SCHED, "Bitmap init error\n");
		rte_free(port);
		return NULL;
	}

	for (i = 0; i < RTE_SCHED_PORT_N_GRINDERS; i++)
		port->grinder_base_bmp_pos[i] = RTE_SCHED_PIPE_INVALID;


	return port;
}


struct rte_sched_port *
rte_sched_port_config(struct rte_sched_port_params *params)
{
	uint32_t mem_size;

	/* Check user parameters. Determine the amount of memory to allocate */
	mem_size = rte_sched_port_get_memory_footprint(params);
	if (mem_size == 0)
		return NULL;

	return rte_sched_port_config_common(params, mem_size);
}

struct rte_sched_port *
rte_sched_port_config_v2(struct rte_sched_port_params *params,
			 uint32_t queue_array_size)
{
	uint32_t mem_size;

	/* Check user parameters. Determine the amount of memory to allocate */
	mem_size = rte_sched_port_get_memory_footprint_common(params,
							      queue_array_size);
	if (mem_size == 0)
		return NULL;

	return rte_sched_port_config_common(params, mem_size);
}

void
rte_sched_port_free(struct rte_sched_port *port)
{
	uint32_t qindex;
	uint32_t n_queues_per_port;

	/* Check user parameters */
	if (port == NULL)
		return;

	n_queues_per_port = rte_sched_port_queues_per_port(port);

	/* Free enqueued mbufs */
	for (qindex = 0; qindex < n_queues_per_port; qindex++) {
		struct rte_mbuf **mbufs = rte_sched_port_qbase(port, qindex);
		uint16_t qsize = rte_sched_port_qsize(port, qindex);
		struct rte_sched_queue *queue = port->queue + qindex;
		uint16_t qr = queue->qr & (qsize - 1);
		uint16_t qw = queue->qw & (qsize - 1);

		for (; qr != qw; qr = (qr + 1) & (qsize - 1))
			rte_pktmbuf_free(mbufs[qr]);
	}

	rte_bitmap_free(port->bmp);
	rte_free(port);
}

static void
rte_sched_port_log_subport_config(struct rte_sched_port *port, uint32_t i)
{
	struct rte_sched_subport *s = port->subport + i;
	char credits_str[(13 * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) + 3];
	char queue_size_str[(7 * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) + 3];

	rte_sched_build_credit_array_string(s->tc_credits_per_period,
					    credits_str);
	rte_sched_build_queue_size_string(s->qsize, queue_size_str);

	RTE_LOG(DEBUG, SCHED, "Low level config for subport %u:\n"
		"    Token bucket: period = %u, credits per period = %u, size = %u\n"
		"    Traffic classes: period = %u, credits per period = %s\n"
		"    Traffic class queue-sizes: %s\n"
		"    Traffic class 3 oversubscription: wm min = %u, wm max = %u\n",
		i,

		/* Token bucket */
		s->tb_period,
		s->tb_credits_per_period,
		s->tb_size,

		/* Traffic classes */
		s->tc_period,
		credits_str,
		queue_size_str,

		/* Traffic class 3 oversubscription */
		s->tc_ov_wm_min,
		s->tc_ov_wm_max);
}

static int
rte_sched_subport_config_common(struct rte_sched_port *port,
				uint32_t subport_id,
				struct rte_sched_subport_params *params,
				uint16_t *qsize,
				struct rte_red_params red_params[][RTE_COLORS])
{

	struct rte_sched_subport *s;
	uint32_t i;

	/* Check user parameters */
	if (port == NULL ||
	    subport_id >= port->n_subports_per_port ||
	    params == NULL)
		return -1;

	if (params->tb_rate == 0 || params->tb_rate > port->rate)
		return -2;

	if (params->tb_size == 0)
		return -3;

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		if (params->tc_rate[i] == 0 ||
		    params->tc_rate[i] > params->tb_rate)
			return -4;
	}

	if (params->tc_period == 0)
		return -5;

	s = port->subport + subport_id;

	/* Token Bucket (TB) */
	if (params->tb_rate == port->rate) {
		s->tb_credits_per_period = 1;
		s->tb_period = 1;
	} else {
		rte_approx_int(params->tb_rate, port->rate,
			       &s->tb_credits_per_period, &s->tb_period);
	}

	/*
	 * The period must be less than or equal to the burst otherwise
	 * we lose a bunch of tokens every period because the maximum
	 * the token bucket is allowed to be is the burst.
	 */
	s->tb_size = params->tb_size;
	if (s->tb_credits_per_period > s->tb_size)
		s->tb_size = s->tb_credits_per_period;
	s->tb_time = port->time;
	s->tb_credits = s->tb_size / 2;

	/* Traffic Classes (TCs) */
	s->tc_period = rte_sched_time_us_to_bytes(params->tc_period, port->rate);
	s->tc_time = port->time + s->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		s->tc_credits_per_period[i]
			= rte_sched_time_us_to_bytes(params->tc_period,
						     params->tc_rate[i]);
		s->tc_credits[i] = s->tc_credits_per_period[i];
	}

#ifdef RTE_SCHED_RED
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint32_t j;

		if (!red_params) {
			/* Copy the red configuration from port */
			for (j = 0; j < RTE_COLORS; j++)
				s->red_config[i][j] = port->red_config[i][j];
		} else {
			/* Subport has an individual red configuration */
			for (j = 0; j < RTE_COLORS; j++) {
				/* if min/max are both zero, then RED is
				 * disabled
				 */
				if ((red_params[i][j].min_th |
				     red_params[i][j].max_th) == 0) {
					continue;
				}

				if (rte_red_config_init(&s->red_config[i][j],
					red_params[i][j].wq_log2,
					red_params[i][j].min_th,
					red_params[i][j].max_th,
					red_params[i][j].maxp_inv) != 0) {
					return -6;
				}
			}
		}
	}
#endif

#ifdef RTE_SCHED_SUBPORT_TC_OV
	/* TC oversubscription */
	s->tc_ov_wm_min = port->mtu;
	s->tc_ov_wm_max = rte_sched_time_ms_to_bytes
		(params->tc_period, port->pipe_low_prio_tc_rate_max);
	s->tc_ov_wm = s->tc_ov_wm_max;
	s->tc_ov_period_id = 0;
	s->tc_ov = 0;
	s->tc_ov_n = 0;
	s->tc_ov_rate = 0;
#endif

	rte_sched_subport_config_qsize(port, subport_id, qsize);
	rte_sched_port_log_subport_config(port, subport_id);

	return 0;
}

int
rte_sched_subport_config(struct rte_sched_port *port,
			 uint32_t subport_id,
			 struct rte_sched_subport_params *params)
{
	return rte_sched_subport_config_common(port, subport_id, params, NULL,
					       NULL);
}

int
rte_sched_subport_config_v2(struct rte_sched_port *port,
			    uint32_t subport_id,
			    struct rte_sched_subport_params *params,
			    uint16_t *qsize,
			    struct rte_red_params red_params[][RTE_COLORS])
{
	return rte_sched_subport_config_common(port, subport_id, params,
					       qsize, red_params);
}

static inline uint32_t
rte_sched_port_qindex(struct rte_sched_port *port, uint32_t subport,
		      uint32_t pipe, uint32_t traffic_class, uint32_t queue)
{
	uint32_t result;

	result = subport * port->n_pipes_per_subport + pipe;
	result = result * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE + traffic_class;
	result = result * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;

	return result;
}

int
rte_sched_pipe_config(struct rte_sched_port *port,
	uint32_t subport_id,
	uint32_t pipe_id,
	int32_t pipe_profile)
{
	struct rte_sched_subport *s;
	struct rte_sched_pipe *p;
	struct rte_sched_pipe_profile *params;
	uint32_t deactivate, profile, i;

	/* Check user parameters */
	profile = (uint32_t) pipe_profile;
	deactivate = (pipe_profile < 0);

	if (port == NULL ||
	    subport_id >= port->n_subports_per_port ||
	    pipe_id >= port->n_pipes_per_subport ||
	    (!deactivate && profile >= port->n_pipe_profiles))
		return -1;


	/* Check that subport configuration is valid */
	s = port->subport + subport_id;
	if (s->tb_period == 0)
		return -2;

	p = port->pipe + (subport_id * port->n_pipes_per_subport + pipe_id);

	/* Handle the case when pipe already has a valid configuration */
	if (p->tb_time) {
		params = port->pipe_profiles + p->profile;

#ifdef RTE_SCHED_SUBPORT_TC_OV
		double subport_low_prio_tc_rate;
		double pipe_low_prio_tc_rate;
		uint32_t low_prio_tc_ov = s->tc_ov;

		subport_low_prio_tc_rate =
			(double) s->tc_credits_per_period[RTE_SCHED_MAX_TC]
			/ (double) s->tc_period;
		pipe_low_prio_tc_rate =
			(double) params->tc_credits_per_period[RTE_SCHED_MAX_TC]
			/ (double) params->tc_period;

		/* Unplug pipe from its subport */
		s->tc_ov_n -= params->tc_ov_weight;
		s->tc_ov_rate -= pipe_low_prio_tc_rate;
		s->tc_ov = s->tc_ov_rate > subport_low_prio_tc_rate;

		if (s->tc_ov != low_prio_tc_ov) {
			RTE_LOG(DEBUG, SCHED,
				"Subport %u TC%u oversubscription is OFF (%.4lf >= %.4lf)\n",
				subport_id, RTE_SCHED_MAX_TC,
				subport_low_prio_tc_rate, s->tc_ov_rate);
		}
#endif

		/* Reset the pipe */
		memset(p, 0, sizeof(struct rte_sched_pipe));
	}

	if (deactivate)
		return 0;

	/* Apply the new pipe configuration */
	p->profile = profile;
	params = port->pipe_profiles + p->profile;

	/* Token Bucket (TB) */
	p->tb_time = port->time;
	p->tb_credits = params->tb_size / 2;

	/* Traffic Classes (TCs) */
	p->tc_time = port->time + params->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		p->tc_credits[i] = params->tc_credits_per_period[i];

#ifdef RTE_SCHED_SUBPORT_TC_OV
	{
		/* Subport lowest priority TC oversubscription */
		double subport_low_prio_tc_rate;
		double pipe_low_prio_tc_rate;
		uint32_t low_prio_tc_ov = s->tc_ov;

		subport_low_prio_tc_rate =
			(double) s->tc_credits_per_period[RTE_SCHED_MAX_TC]
			/ (double) s->tc_period;
		pipe_low_prio_tc_rate =
			(double) params->tc_credits_per_period[RTE_SCHED_MAX_TC]
			/ (double) params->tc_period;

		s->tc_ov_n += params->tc_ov_weight;
		s->tc_ov_rate += pipe_low_prio_tc_rate;
		s->tc_ov = s->tc_ov_rate > subport_low_prio_tc_rate;

		if (s->tc_ov != low_prio_tc_ov) {
			RTE_LOG(DEBUG, SCHED,
				"Subport %u TC%u oversubscription is ON (%.4lf < %.4lf)\n",
				subport_id, RTE_SCHED_MAX_TC,
				subport_low_prio_tc_rate, s->tc_ov_rate);
		}
		p->tc_ov_period_id = s->tc_ov_period_id;
		p->tc_ov_credits = s->tc_ov_wm;
	}
#endif

	return 0;
}

int __rte_experimental
rte_sched_port_pipe_profile_add(struct rte_sched_port *port,
	struct rte_sched_pipe_params *params,
	uint32_t *pipe_profile_id)
{
	struct rte_sched_pipe_profile *pp;
	uint32_t i;
	int status;

	/* Port */
	if (port == NULL)
		return -1;

	/* Pipe profiles not exceeds the max limit */
	if (port->n_pipe_profiles >= RTE_SCHED_PIPE_PROFILES_PER_PORT)
		return -2;

	/* Pipe params */
	status = pipe_profile_check(params, port->rate);
	if (status != 0)
		return status;

	pp = &port->pipe_profiles[port->n_pipe_profiles];
	rte_sched_pipe_profile_convert(params, pp, port->rate);

	/* Pipe profile not exists */
	for (i = 0; i < port->n_pipe_profiles; i++)
		if (memcmp(port->pipe_profiles + i, pp, sizeof(*pp)) == 0)
			return -3;

	/* Pipe profile commit */
	*pipe_profile_id = port->n_pipe_profiles;
	port->n_pipe_profiles++;

	if (port->pipe_low_prio_tc_rate_max < params->tc_rate[RTE_SCHED_MAX_TC])
		port->pipe_low_prio_tc_rate_max = params->tc_rate[RTE_SCHED_MAX_TC];

	rte_sched_port_log_pipe_profile(port, *pipe_profile_id);

	return 0;
}

int
rte_sched_pipe_config_v2(struct rte_sched_port *port,
	uint32_t subport_id,
	uint32_t pipe_id,
	int32_t pipe_profile,
	struct rte_sched_port_params *port_params)
{
	int ret;
	struct rte_sched_pipe_params *p_profs;
	struct rte_red_pipe_params *wred_params;
	uint32_t qindex;

	ret = rte_sched_pipe_config(port, subport_id, pipe_id, pipe_profile);
	if (ret != 0)
		return ret;

	p_profs = port_params->pipe_profiles + pipe_profile;

	SLIST_FOREACH(wred_params, &p_profs->qred_head, list) {
		int i;
		uint32_t tc = 0;
		struct rte_sched_queue_extra *qxtra;

		qindex = wred_params->qindex;
		qindex = rte_sched_port_qindex(port, subport_id, pipe_id,
					       tc, qindex);
		qxtra = port->queue_extra + qindex;

		for (i = 0; i < wred_params->red_q_params.num_maps; i++) {
			rte_red_rt_data_init(&qxtra->red);
			if (rte_red_config_init(&qxtra->qred.qcfg[i],
				wred_params->red_q_params.qparams[i].wq_log2,
				wred_params->red_q_params.qparams[i].min_th,
				wred_params->red_q_params.qparams[i].max_th,
				wred_params->red_q_params.qparams[i].maxp_inv))
				return -1;
			qxtra->qred.dscp_set[i] =
				wred_params->red_q_params.dscp_set[i];
		}
		qxtra->qred.num_maps = wred_params->red_q_params.num_maps;

		/*
		 * Initially the qindex is set relative to a pipe since it's
		 * configured in a profile.  We're now attaching the profile to
		 * the subport so need to allow for the subport + pipe offset
		 * in addition to the internal pipe offset.
		 *
		 * There may be several classes using the same wred profile,
		 * if there is copy it and assign to new qindex.
		 */
		if (!wred_params->alloced) {
			wred_params->qindex = qindex;
			wred_params->alloced = true;
		} else {
			if (rte_red_copy_params(p_profs, wred_params,
					        qindex) == NULL)
				return -1;
		}

		RTE_LOG(DEBUG, SCHED,
			"Setup per Q wred sub %u pip %u qind %u maps %u\n",
			subport_id, pipe_id, qindex, qxtra->qred.num_maps);
	}

	return ret;
}

void
rte_sched_port_pkt_write(struct rte_mbuf *pkt,
			 uint32_t subport, uint32_t pipe, uint32_t traffic_class,
			 uint32_t queue, enum rte_color color)
{
	struct rte_sched_port_hierarchy *sched
		= (struct rte_sched_port_hierarchy *) &pkt->hash.sched;

	RTE_BUILD_BUG_ON(sizeof(*sched) > sizeof(pkt->hash.sched));

	sched->color = (uint32_t) color;
	sched->subport = subport;
	sched->pipe = pipe;
	sched->traffic_class = traffic_class;
	sched->queue = queue;
}

void
rte_sched_port_pkt_write_v2(struct rte_mbuf *pkt, uint32_t subport,
			    uint32_t pipe, uint32_t traffic_class,
			    uint32_t queue, enum rte_color color,
			    uint16_t dscp)
{
	struct rte_sched_port_hierarchy *sched
		= (struct rte_sched_port_hierarchy *) &pkt->hash.sched;

	rte_sched_port_pkt_write(pkt, subport, pipe, traffic_class,
				 queue, color);

	sched->dscp = dscp;
}

void
rte_sched_port_pkt_read_tree_path(const struct rte_mbuf *pkt,
				  uint32_t *subport, uint32_t *pipe,
				  uint32_t *traffic_class, uint32_t *queue)
{
	const struct rte_sched_port_hierarchy *sched
		= (const struct rte_sched_port_hierarchy *) &pkt->hash.sched;

	*subport = sched->subport;
	*pipe = sched->pipe;
	*traffic_class = sched->traffic_class;
	*queue = sched->queue;
}

enum rte_color
rte_sched_port_pkt_read_color(const struct rte_mbuf *pkt)
{
	const struct rte_sched_port_hierarchy *sched
		= (const struct rte_sched_port_hierarchy *) &pkt->hash.sched;

	return (enum rte_color) sched->color;
}

int
rte_sched_subport_read_stats(struct rte_sched_port *port,
			     uint32_t subport_id,
			     struct rte_sched_subport_stats *stats,
			     uint32_t *tc_ov)
{
	struct rte_sched_subport *s;

	/* Check user parameters */
	if (port == NULL || subport_id >= port->n_subports_per_port ||
	    stats == NULL || tc_ov == NULL)
		return -1;

	s = port->subport + subport_id;

	/* Copy subport stats and clear */
	memcpy(stats, &s->stats, sizeof(struct rte_sched_subport_stats));
	memset(&s->stats, 0, sizeof(struct rte_sched_subport_stats));

	/* Subport TC oversubscription status */
	*tc_ov = s->tc_ov;

	return 0;
}

int
rte_sched_subport_read_stats64(struct rte_sched_port *port,
			       uint32_t subport_id,
			       struct rte_sched_subport_stats64 *stats64,
			       uint32_t *tc_ov)
{
	struct rte_sched_subport *s;
	uint32_t tc;

	/* Check user parameters */
	if (port == NULL || subport_id >= port->n_subports_per_port ||
	    stats64 == NULL || tc_ov == NULL)
		return -1;

	s = port->subport + subport_id;

	/* Copy subport stats and clear */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		stats64->n_pkts_tc[tc] = s->stats.n_pkts_tc[tc];
		stats64->n_pkts_tc_dropped[tc] =
			s->stats.n_pkts_tc_dropped[tc];
		stats64->n_bytes_tc[tc] = s->stats.n_bytes_tc[tc];
		stats64->n_bytes_tc_dropped[tc] =
			s->stats.n_bytes_tc_dropped[tc];
#ifdef RTE_SCHED_RED
		stats64->n_pkts_red_dropped[tc] =
			s->stats.n_pkts_red_dropped[tc];
#endif
	}
	memset(&s->stats, 0, sizeof(struct rte_sched_subport_stats));

	/* Subport TC oversubscription status */
	*tc_ov = s->tc_ov;

	return 0;
}

int
rte_sched_queue_read_stats(struct rte_sched_port *port,
	uint32_t queue_id,
	struct rte_sched_queue_stats *stats,
	uint16_t *qlen)
{
	struct rte_sched_queue *q;
	struct rte_sched_queue_extra *qe;

	/* Check user parameters */
	if ((port == NULL) ||
	    (queue_id >= rte_sched_port_queues_per_port(port)) ||
		(stats == NULL) ||
		(qlen == NULL)) {
		return -1;
	}
	q = port->queue + queue_id;
	qe = port->queue_extra + queue_id;

	/* Copy queue stats and clear */
	memcpy(stats, &qe->stats, sizeof(struct rte_sched_queue_stats));
	memset(&qe->stats, 0, sizeof(struct rte_sched_queue_stats));

	/* Queue length */
	*qlen = q->qw - q->qr;

	return 0;
}

int
rte_sched_queue_read_stats64(struct rte_sched_port *port,
	uint32_t queue_id,
	struct rte_sched_queue_stats64 *stats64,
	uint16_t *qlen)
{
	struct rte_sched_queue *q;
	struct rte_sched_queue_extra *qe;
	uint32_t i;

	/* Check user parameters */
	if ((port == NULL) ||
	    (queue_id >= rte_sched_port_queues_per_port(port)) ||
		(stats64 == NULL) ||
		(qlen == NULL)) {
		return -1;
	}
	q = port->queue + queue_id;
	qe = port->queue_extra + queue_id;

	/* Copy queue stats and clear */
	stats64->n_pkts = qe->stats.n_pkts;
	stats64->n_pkts_dropped = qe->stats.n_pkts_dropped;
	stats64->n_bytes = qe->stats.n_bytes;
	stats64->n_bytes_dropped = qe->stats.n_bytes_dropped;
#ifdef RTE_SCHED_RED
	stats64->n_pkts_red_dropped = qe->stats.n_pkts_red_dropped;
	for (i = 0; i < RTE_NUM_DSCP_MAPS; i++) {
		stats64->n_pkts_red_dscp_dropped[i] =
			qe->stats.n_pkts_red_dscp_dropped[i];
	}
#endif
	memset(&qe->stats, 0, sizeof(struct rte_sched_queue_stats));

	/* Queue length */
	*qlen = q->qw - q->qr;

	return 0;
}

#ifdef RTE_SCHED_DEBUG

static inline int
rte_sched_port_queue_is_empty(struct rte_sched_port *port, uint32_t qindex)
{
	struct rte_sched_queue *queue = port->queue + qindex;

	return queue->qr == queue->qw;
}

#endif /* RTE_SCHED_DEBUG */

#ifdef RTE_SCHED_COLLECT_STATS

static inline void
rte_sched_port_update_subport_stats(struct rte_sched_port *port, uint32_t qindex, struct rte_mbuf *pkt)
{
	struct rte_sched_subport *s = port->subport + (qindex / rte_sched_port_queues_per_subport(port));
	uint32_t tc_index = (qindex >> RTE_SCHED_WRR_BITS) & RTE_SCHED_TC_MASK;
	uint32_t pkt_len = pkt->pkt_len;

	s->stats.n_pkts_tc[tc_index] += 1;
	s->stats.n_bytes_tc[tc_index] += pkt_len;
}

#ifdef RTE_SCHED_RED
static inline void
rte_sched_port_update_subport_stats_on_drop(struct rte_sched_port *port,
						uint32_t qindex,
						struct rte_mbuf *pkt, uint32_t red)
#else
static inline void
rte_sched_port_update_subport_stats_on_drop(struct rte_sched_port *port,
						uint32_t qindex,
						struct rte_mbuf *pkt, __rte_unused uint32_t red)
#endif
{
	struct rte_sched_subport *s = port->subport + (qindex / rte_sched_port_queues_per_subport(port));
	uint32_t tc_index = (qindex >> RTE_SCHED_WRR_BITS) & RTE_SCHED_TC_MASK;

	uint32_t pkt_len = pkt->pkt_len;

	s->stats.n_pkts_tc_dropped[tc_index] += 1;
	s->stats.n_bytes_tc_dropped[tc_index] += pkt_len;
#ifdef RTE_SCHED_RED
	s->stats.n_pkts_red_dropped[tc_index] += red;
#endif
}

static inline void
rte_sched_port_update_queue_stats(struct rte_sched_port *port, uint32_t qindex, struct rte_mbuf *pkt)
{
	struct rte_sched_queue_extra *qe = port->queue_extra + qindex;
	uint32_t pkt_len = pkt->pkt_len;

	qe->stats.n_pkts += 1;
	qe->stats.n_bytes += pkt_len;
}

#ifdef RTE_SCHED_RED
static inline void
rte_sched_port_update_queue_stats_on_drop(struct rte_sched_port *port,
						uint32_t qindex,
						struct rte_mbuf *pkt, uint32_t red)
#else
static inline void
rte_sched_port_update_queue_stats_on_drop(struct rte_sched_port *port,
						uint32_t qindex,
						struct rte_mbuf *pkt, __rte_unused uint32_t red)
#endif
{
	struct rte_sched_queue_extra *qe = port->queue_extra + qindex;
	uint32_t pkt_len = pkt->pkt_len;

	qe->stats.n_pkts_dropped += 1;
	qe->stats.n_bytes_dropped += pkt_len;
#ifdef RTE_SCHED_RED
	qe->stats.n_pkts_red_dropped += red;
#endif
}

#endif /* RTE_SCHED_COLLECT_STATS */

#ifdef RTE_SCHED_RED

static inline int
rte_sched_port_red_drop(struct rte_sched_port *port, struct rte_mbuf *pkt,
			uint32_t qindex, uint16_t qlen)
{
	struct rte_sched_subport *subport = port->subport +
		(qindex / rte_sched_port_queues_per_subport(port));
	struct rte_sched_queue_extra *qe;
	struct rte_red_config *red_cfg;
	struct rte_red *red;
	uint32_t tc_index;
	enum rte_color color;

	tc_index = (qindex >> RTE_SCHED_WRR_BITS) & RTE_SCHED_TC_MASK;
	color = rte_sched_port_pkt_read_color(pkt);
	red_cfg = &subport->red_config[tc_index][color];

	qe = port->queue_extra + qindex;

	if ((red_cfg->min_th | red_cfg->max_th) == 0 &&
	    !qe->qred.num_maps)
		return 0;

	red = &qe->red;

	if (qe->qred.num_maps) {
		int i, ret;
		struct rte_sched_port_hierarchy *sched =
			(struct rte_sched_port_hierarchy *) &pkt->hash.sched;
		uint64_t dscp_mask;
		dscp_mask = (sched->dscp < MAX_DSCP) ? (1lu << sched->dscp) : 0;
		for (i = 0; i < qe->qred.num_maps; i++) {
			if (dscp_mask & qe->qred.dscp_set[i]) {
				red_cfg = &qe->qred.qcfg[i];
				break;
			}
		}

		/* If we haven't found a dscp match then force a drop */
		if (i >= qe->qred.num_maps)
			return 1;

		ret = rte_red_enqueue(red_cfg, red, qlen, port->time_cpu_bytes);
		if (ret)
			qe->stats.n_pkts_red_dscp_dropped[i]++;

		return ret;
	}

	return rte_red_enqueue(red_cfg, red, qlen, port->time_cpu_bytes);
}

static inline void
rte_sched_port_set_queue_empty_timestamp(struct rte_sched_port *port, uint32_t qindex)
{
	struct rte_sched_queue_extra *qe = port->queue_extra + qindex;
	struct rte_red *red = &qe->red;

	rte_red_mark_queue_empty(red, port->time_cpu_bytes);
}

#else

#define rte_sched_port_red_drop(port, pkt, qindex, qlen)             0

#define rte_sched_port_set_queue_empty_timestamp(port, qindex)

#endif /* RTE_SCHED_RED */

#ifdef RTE_SCHED_DEBUG

static inline void
debug_check_queue_slab(struct rte_sched_port *port, uint32_t bmp_pos,
		       uint64_t bmp_slab)
{
	uint64_t mask;
	uint32_t i, panic;

	if (bmp_slab == 0)
		rte_panic("Empty slab at position %u\n", bmp_pos);

	panic = 0;
	for (i = 0, mask = 1; i < 64; i++, mask <<= 1) {
		if (mask & bmp_slab) {
			if (rte_sched_port_queue_is_empty(port, bmp_pos + i)) {
				printf("Queue %u (slab offset %u) is empty\n", bmp_pos + i, i);
				panic = 1;
			}
		}
	}

	if (panic)
		rte_panic("Empty queues in slab 0x%" PRIx64 "starting at position %u\n",
			bmp_slab, bmp_pos);
}

#endif /* RTE_SCHED_DEBUG */

int rte_sched_get_profile_for_pipe(struct rte_sched_port *port,
				   uint32_t qid)
{
	uint32_t n_pipes, pipeid;
	struct rte_sched_pipe *pipe;

	if (!port)
		return -1;

	n_pipes = port->n_subports_per_port * port->n_pipes_per_subport;
	pipeid = qid / RTE_SCHED_QUEUES_PER_PIPE;
	if (pipeid >= n_pipes)
		return -1;

	pipe = port->pipe + pipeid;

	return pipe->profile;
}

static inline uint32_t
rte_sched_port_enqueue_qptrs_prefetch0(struct rte_sched_port *port,
				       struct rte_mbuf *pkt)
{
	struct rte_sched_queue *q;
#ifdef RTE_SCHED_COLLECT_STATS
	struct rte_sched_queue_extra *qe;
#endif
	uint32_t subport, pipe, traffic_class, queue, qindex;

	rte_sched_port_pkt_read_tree_path(pkt, &subport, &pipe, &traffic_class, &queue);

	qindex = rte_sched_port_qindex(port, subport, pipe, traffic_class, queue);
	q = port->queue + qindex;
	rte_prefetch0(q);
#ifdef RTE_SCHED_COLLECT_STATS
	qe = port->queue_extra + qindex;
	rte_prefetch0(qe);
#endif

	return qindex;
}

static inline void
rte_sched_port_enqueue_qwa_prefetch0(struct rte_sched_port *port,
				     uint32_t qindex, struct rte_mbuf **qbase)
{
	struct rte_sched_queue *q;
	struct rte_mbuf **q_qw;
	uint16_t qsize;

	q = port->queue + qindex;
	qsize = rte_sched_port_qsize(port, qindex);
	q_qw = qbase + (q->qw & (qsize - 1));

	rte_prefetch0(q_qw);
	rte_bitmap_prefetch0(port->bmp, qindex);
}

static inline int
rte_sched_port_enqueue_qwa(struct rte_sched_port *port, uint32_t qindex,
			   struct rte_mbuf **qbase, struct rte_mbuf *pkt)
{
	struct rte_sched_queue *q;
	uint16_t qsize;
	uint16_t qlen;

	q = port->queue + qindex;
	qsize = rte_sched_port_qsize(port, qindex);
	qlen = q->qw - q->qr;

	/* Drop the packet (and update drop stats) when queue is full */
	if (unlikely(rte_sched_port_red_drop(port, pkt, qindex, qlen) ||
		     (qlen >= qsize))) {
		rte_pktmbuf_free(pkt);
#ifdef RTE_SCHED_COLLECT_STATS
		rte_sched_port_update_subport_stats_on_drop(port, qindex, pkt,
							    qlen < qsize);
		rte_sched_port_update_queue_stats_on_drop(port, qindex, pkt,
							  qlen < qsize);
#endif
		return 0;
	}

	/* Enqueue packet */
	qbase[q->qw & (qsize - 1)] = pkt;
	q->qw++;

	/* Activate queue in the port bitmap */
	rte_bitmap_set(port->bmp, qindex);

	/* Statistics */
#ifdef RTE_SCHED_COLLECT_STATS
	rte_sched_port_update_subport_stats(port, qindex, pkt);
	rte_sched_port_update_queue_stats(port, qindex, pkt);
#endif

	return 1;
}


/*
 * The enqueue function implements a 4-level pipeline with each stage
 * processing two different packets. The purpose of using a pipeline
 * is to hide the latency of prefetching the data structures. The
 * naming convention is presented in the diagram below:
 *
 *   p00  _______   p10  _______   p20  _______   p30  _______
 * ----->|       |----->|       |----->|       |----->|       |----->
 *       |   0   |      |   1   |      |   2   |      |   3   |
 * ----->|_______|----->|_______|----->|_______|----->|_______|----->
 *   p01            p11            p21            p31
 *
 */
int
rte_sched_port_enqueue(struct rte_sched_port *port, struct rte_mbuf **pkts,
		       uint32_t n_pkts)
{
	struct rte_mbuf *pkt00, *pkt01, *pkt10, *pkt11, *pkt20, *pkt21,
		*pkt30, *pkt31, *pkt_last;
	struct rte_mbuf **q00_base, **q01_base, **q10_base, **q11_base,
		**q20_base, **q21_base, **q30_base, **q31_base, **q_last_base;
	uint32_t q00, q01, q10, q11, q20, q21, q30, q31, q_last;
	uint32_t r00, r01, r10, r11, r20, r21, r30, r31, r_last;
	uint32_t result, i;

	result = 0;

	/*
	 * Less then 6 input packets available, which is not enough to
	 * feed the pipeline
	 */
	if (unlikely(n_pkts < 6)) {
		struct rte_mbuf **q_base[5];
		uint32_t q[5];

		/* Prefetch the mbuf structure of each packet */
		for (i = 0; i < n_pkts; i++)
			rte_prefetch0(pkts[i]);

		/* Prefetch the queue structure for each queue */
		for (i = 0; i < n_pkts; i++)
			q[i] = rte_sched_port_enqueue_qptrs_prefetch0(port,
								      pkts[i]);

		/* Prefetch the write pointer location of each queue */
		for (i = 0; i < n_pkts; i++) {
			q_base[i] = rte_sched_port_qbase(port, q[i]);
			rte_sched_port_enqueue_qwa_prefetch0(port, q[i],
							     q_base[i]);
		}

		/* Write each packet to its queue */
		for (i = 0; i < n_pkts; i++)
			result += rte_sched_port_enqueue_qwa(port, q[i],
							     q_base[i], pkts[i]);

		return result;
	}

	/* Feed the first 3 stages of the pipeline (6 packets needed) */
	pkt20 = pkts[0];
	pkt21 = pkts[1];
	rte_prefetch0(pkt20);
	rte_prefetch0(pkt21);

	pkt10 = pkts[2];
	pkt11 = pkts[3];
	rte_prefetch0(pkt10);
	rte_prefetch0(pkt11);

	q20 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt20);
	q21 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt21);

	pkt00 = pkts[4];
	pkt01 = pkts[5];
	rte_prefetch0(pkt00);
	rte_prefetch0(pkt01);

	q10 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt10);
	q11 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt11);

	q20_base = rte_sched_port_qbase(port, q20);
	q21_base = rte_sched_port_qbase(port, q21);
	rte_sched_port_enqueue_qwa_prefetch0(port, q20, q20_base);
	rte_sched_port_enqueue_qwa_prefetch0(port, q21, q21_base);

	/* Run the pipeline */
	for (i = 6; i < (n_pkts & (~1)); i += 2) {
		/* Propagate stage inputs */
		pkt30 = pkt20;
		pkt31 = pkt21;
		pkt20 = pkt10;
		pkt21 = pkt11;
		pkt10 = pkt00;
		pkt11 = pkt01;
		q30 = q20;
		q31 = q21;
		q20 = q10;
		q21 = q11;
		q30_base = q20_base;
		q31_base = q21_base;

		/* Stage 0: Get packets in */
		pkt00 = pkts[i];
		pkt01 = pkts[i + 1];
		rte_prefetch0(pkt00);
		rte_prefetch0(pkt01);

		/* Stage 1: Prefetch queue structure storing queue pointers */
		q10 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt10);
		q11 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt11);

		/* Stage 2: Prefetch queue write location */
		q20_base = rte_sched_port_qbase(port, q20);
		q21_base = rte_sched_port_qbase(port, q21);
		rte_sched_port_enqueue_qwa_prefetch0(port, q20, q20_base);
		rte_sched_port_enqueue_qwa_prefetch0(port, q21, q21_base);

		/* Stage 3: Write packet to queue and activate queue */
		r30 = rte_sched_port_enqueue_qwa(port, q30, q30_base, pkt30);
		r31 = rte_sched_port_enqueue_qwa(port, q31, q31_base, pkt31);
		result += r30 + r31;
	}

	/*
	 * Drain the pipeline (exactly 6 packets).
	 * Handle the last packet in the case
	 * of an odd number of input packets.
	 */
	pkt_last = pkts[n_pkts - 1];
	rte_prefetch0(pkt_last);

	q00 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt00);
	q01 = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt01);

	q10_base = rte_sched_port_qbase(port, q10);
	q11_base = rte_sched_port_qbase(port, q11);
	rte_sched_port_enqueue_qwa_prefetch0(port, q10, q10_base);
	rte_sched_port_enqueue_qwa_prefetch0(port, q11, q11_base);

	r20 = rte_sched_port_enqueue_qwa(port, q20, q20_base, pkt20);
	r21 = rte_sched_port_enqueue_qwa(port, q21, q21_base, pkt21);
	result += r20 + r21;

	q_last = rte_sched_port_enqueue_qptrs_prefetch0(port, pkt_last);

	q00_base = rte_sched_port_qbase(port, q00);
	q01_base = rte_sched_port_qbase(port, q01);
	rte_sched_port_enqueue_qwa_prefetch0(port, q00, q00_base);
	rte_sched_port_enqueue_qwa_prefetch0(port, q01, q01_base);

	r10 = rte_sched_port_enqueue_qwa(port, q10, q10_base, pkt10);
	r11 = rte_sched_port_enqueue_qwa(port, q11, q11_base, pkt11);
	result += r10 + r11;

	q_last_base = rte_sched_port_qbase(port, q_last);
	rte_sched_port_enqueue_qwa_prefetch0(port, q_last, q_last_base);

	r00 = rte_sched_port_enqueue_qwa(port, q00, q00_base, pkt00);
	r01 = rte_sched_port_enqueue_qwa(port, q01, q01_base, pkt01);
	result += r00 + r01;

	if (n_pkts & 1) {
		r_last = rte_sched_port_enqueue_qwa(port, q_last, q_last_base, pkt_last);
		result += r_last;
	}

	return result;
}

#ifndef RTE_SCHED_SUBPORT_TC_OV

static inline void
grinder_credits_update(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_subport *subport = grinder->subport;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *params = grinder->pipe_params;
	uint64_t n_periods;
	uint32_t tc;
	uint64_t lapsed;

	/* Subport TB */
	n_periods = (port->time_cpu_bytes - subport->tb_time) / subport->tb_period;
	subport->tb_credits += n_periods * subport->tb_credits_per_period;
	subport->tb_credits = rte_sched_min_val_2_u32(subport->tb_credits, subport->tb_size);
	subport->tb_time += n_periods * subport->tb_period;

	/* Pipe TB */
	n_periods = (port->time_cpu_bytes - pipe->tb_time) / params->tb_period;
	pipe->tb_credits += n_periods * params->tb_credits_per_period;
	pipe->tb_credits = rte_sched_min_val_2_u32(pipe->tb_credits, params->tb_size);
	pipe->tb_time += n_periods * params->tb_period;

	/* Subport TCs */
	if (unlikely(port->time_cpu_bytes >= subport->tc_time)) {
		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			if (subport->tc_credits[tc] < 0)
				subport->tc_credits[tc] +=
					subport->tc_credits_per_period[tc];
			else
				subport->tc_credits[tc] =
					subport->tc_credits_per_period[tc];
		}
		/* If we've run into the next period only update the clock to
		 * the time + tc_period so we'll replenish the tc tokens early
		 * in the next tc_period to compensate.
		 */
		lapsed = port->time_cpu_bytes - subport->tc_time;
		if (lapsed < subport->tc_period)
			subport->tc_time += subport->tc_period;
		else
			subport->tc_time = port->time_cpu_bytes +
						subport->tc_period;
	}

	/* Pipe TCs */
	if (unlikely(port->time_cpu_bytes >= pipe->tc_time)) {
		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			if (pipe->tc_credits[tc] < 0)
				pipe->tc_credits[tc] +=
					params->tc_credits_per_period[tc];
			else
				pipe->tc_credits[tc] =
					params->tc_credits_per_period[tc];
		}
		/* If we've run into the next period only update the clock to
		 * the time + tc_period so we'll replenish the tc tokens early
		 * in the next tc_period to compensate.
		 */
		lapsed = port->time_cpu_bytes - pipe->tc_time;
		if (lapsed < params->tc_period)
			pipe->tc_time += params->tc_period;
		else
			pipe->tc_time = port->time_cpu_bytes +
						params->tc_period;
	}
}

#else

static inline uint32_t
grinder_tc_ov_credits_update(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_subport *subport = grinder->subport;
	uint32_t tc_ov_consumption[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	uint32_t tc_ov_consumption_max;
	uint32_t tc_ov_wm = subport->tc_ov_wm;
	uint32_t consumption = 0;
	uint32_t tc;

	if (subport->tc_ov == 0)
		return subport->tc_ov_wm_max;

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		tc_ov_consumption[tc] = subport->tc_credits_per_period[tc]
			- subport->tc_credits[tc];
		if (tc < RTE_SCHED_MAX_TC)
			consumption += tc_ov_consumption[tc];
	}

	tc_ov_consumption_max =
		subport->tc_credits_per_period[RTE_SCHED_MAX_TC] - consumption;

	if (tc_ov_consumption[RTE_SCHED_MAX_TC] >
	    (tc_ov_consumption_max - port->mtu)) {
		tc_ov_wm  -= tc_ov_wm >> 7;
		if (tc_ov_wm < subport->tc_ov_wm_min)
			tc_ov_wm = subport->tc_ov_wm_min;

		return tc_ov_wm;
	}

	tc_ov_wm += (tc_ov_wm >> 7) + 1;
	if (tc_ov_wm > subport->tc_ov_wm_max)
		tc_ov_wm = subport->tc_ov_wm_max;

	return tc_ov_wm;
}

static inline void
grinder_credits_update(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_subport *subport = grinder->subport;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *params = grinder->pipe_params;
	uint64_t n_periods;

	/* Subport TB */
	n_periods = (port->time - subport->tb_time) / subport->tb_period;
	subport->tb_credits += n_periods * subport->tb_credits_per_period;
	subport->tb_credits = rte_sched_min_val_2_u32(subport->tb_credits, subport->tb_size);
	subport->tb_time += n_periods * subport->tb_period;

	/* Pipe TB */
	n_periods = (port->time - pipe->tb_time) / params->tb_period;
	pipe->tb_credits += n_periods * params->tb_credits_per_period;
	pipe->tb_credits = rte_sched_min_val_2_u32(pipe->tb_credits, params->tb_size);
	pipe->tb_time += n_periods * params->tb_period;

	/* Subport TCs */
	if (unlikely(port->time >= subport->tc_time)) {
		subport->tc_ov_wm = grinder_tc_ov_credits_update(port, pos);

		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++)
			subport->tc_credits[tc] =
				subport->tc_credits_per_period[tc];

		subport->tc_time = port->time + subport->tc_period;
		subport->tc_ov_period_id++;
	}

	/* Pipe TCs */
	if (unlikely(port->time >= pipe->tc_time)) {
		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			pipe->tc_credits[tc] =
				params->tc_credits_per_period[tc];

		pipe->tc_time = port->time + params->tc_period;
	}

	/* Pipe TCs - Oversubscription */
	if (unlikely(pipe->tc_ov_period_id != subport->tc_ov_period_id)) {
		pipe->tc_ov_credits = subport->tc_ov_wm * params->tc_ov_weight;

		pipe->tc_ov_period_id = subport->tc_ov_period_id;
	}
}

#endif /* RTE_SCHED_TS_CREDITS_UPDATE, RTE_SCHED_SUBPORT_TC_OV */


#ifndef RTE_SCHED_SUBPORT_TC_OV

static inline int
grinder_credits_check(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_subport *subport = grinder->subport;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_mbuf *pkt = grinder->pkt;
	uint32_t tc_index = grinder->tc_index;
	int32_t pkt_len = pkt->pkt_len + port->frame_overhead;
	uint32_t subport_tb_credits = subport->tb_credits;
	int32_t subport_tc_credits = subport->tc_credits[tc_index];
	uint32_t pipe_tb_credits = pipe->tb_credits;
	int32_t pipe_tc_credits = pipe->tc_credits[tc_index];
	int enough_credits;

	if (pkt_len < 0)
		pkt_len = 0;

	/* Check queue credits */
	enough_credits = (pkt_len <= (int32_t)subport_tb_credits) &&
		(subport_tc_credits > 0) &&
		(pkt_len <= (int32_t)pipe_tb_credits) &&
		(pipe_tc_credits > 0);

	if (!enough_credits)
		return 0;

	/* Update port credits */
	subport->tb_credits -= pkt_len;
	subport->tc_credits[tc_index] -= pkt_len;
	pipe->tc_credits[tc_index] -= pkt_len;
	pipe->tb_credits -= pkt_len;

	return 1;
}

#else

static inline int
grinder_credits_check(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_subport *subport = grinder->subport;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_mbuf *pkt = grinder->pkt;
	uint32_t tc_index = grinder->tc_index;
	int32_t pkt_len = pkt->pkt_len + port->frame_overhead;
	uint32_t subport_tb_credits = subport->tb_credits;
	uint32_t subport_tc_credits = subport->tc_credits[tc_index];
	uint32_t pipe_tb_credits = pipe->tb_credits;
	uint32_t pipe_tc_credits = pipe->tc_credits[tc_index];
	uint32_t pipe_tc_ov_mask1[] = {UINT32_MAX, UINT32_MAX, UINT32_MAX, pipe->tc_ov_credits};
	uint32_t pipe_tc_ov_mask2[] = {0, 0, 0, UINT32_MAX};
	uint32_t pipe_tc_ov_credits = pipe_tc_ov_mask1[tc_index];
	int enough_credits;

	if (pkt_len < 0)
		pkt_len = 0;

	/* Check pipe and subport credits */
	enough_credits = (pkt_len <= subport_tb_credits) &&
		(pkt_len <= subport_tc_credits) &&
		(pkt_len <= pipe_tb_credits) &&
		(pkt_len <= pipe_tc_credits) &&
		(pkt_len <= pipe_tc_ov_credits);

	if (!enough_credits)
		return 0;

	/* Update pipe and subport credits */
	subport->tb_credits -= pkt_len;
	subport->tc_credits[tc_index] -= pkt_len;
	pipe->tb_credits -= pkt_len;
	pipe->tc_credits[tc_index] -= pkt_len;
	pipe->tc_ov_credits -= pipe_tc_ov_mask2[tc_index] & pkt_len;

	return 1;
}

#endif /* RTE_SCHED_SUBPORT_TC_OV */


static inline int
grinder_schedule(struct rte_sched_port *port, uint32_t pos,
		 enum token_state *token_state)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_queue *queue = grinder->queue[grinder->qpos];
	struct rte_mbuf *pkt = grinder->pkt;
	int32_t pkt_len = pkt->pkt_len + port->frame_overhead;

	if (!grinder_credits_check(port, pos)) {
		*token_state = TOKENS_USED;
		return 0;
	}

	*token_state = TOKENS_AVAIL;

	if (pkt_len < 0)
		pkt_len = 0;

	/* Advance port time */
	port->time += pkt_len;

	/* Send packet */
	port->pkts_out[port->n_pkts_out++] = pkt;
	queue->qr++;
	grinder->wrr_tokens[grinder->qpos] += pkt_len * grinder->wrr_cost[grinder->qpos];
	if (queue->qr == queue->qw) {
		uint32_t qindex = grinder->qindex[grinder->qpos];

		rte_bitmap_clear(port->bmp, qindex);
		grinder->qmask &= ~(1 << grinder->qpos);
		grinder->wrr_mask[grinder->qpos] = 0;
		rte_sched_port_set_queue_empty_timestamp(port, qindex);
	}

	/* Reset pipe loop detection */
	port->pipe_loop = RTE_SCHED_PIPE_INVALID;
	grinder->productive = 1;

	return 1;
}

#ifdef SCHED_VECTOR_SSE4

static inline int
grinder_pipe_exists(struct rte_sched_port *port, uint32_t base_pipe)
{
	__m128i index = _mm_set1_epi32(base_pipe);
	__m128i pipes = _mm_load_si128((__m128i *)port->grinder_base_bmp_pos);
	__m128i res = _mm_cmpeq_epi32(pipes, index);

	pipes = _mm_load_si128((__m128i *)(port->grinder_base_bmp_pos + 4));
	pipes = _mm_cmpeq_epi32(pipes, index);
	res = _mm_or_si128(res, pipes);

	if (_mm_testz_si128(res, res))
		return 0;

	return 1;
}

#elif defined(SCHED_VECTOR_NEON)

static inline int
grinder_pipe_exists(struct rte_sched_port *port, uint32_t base_pipe)
{
	uint32x4_t index, pipes;
	uint32_t *pos = (uint32_t *)port->grinder_base_bmp_pos;

	index = vmovq_n_u32(base_pipe);
	pipes = vld1q_u32(pos);
	if (!vminvq_u32(veorq_u32(pipes, index)))
		return 1;

	pipes = vld1q_u32(pos + 4);
	if (!vminvq_u32(veorq_u32(pipes, index)))
		return 1;

	return 0;
}

#else

static inline int
grinder_pipe_exists(struct rte_sched_port *port, uint32_t base_pipe)
{
	uint32_t i;

	for (i = 0; i < RTE_SCHED_PORT_N_GRINDERS; i++) {
		if (port->grinder_base_bmp_pos[i] == base_pipe)
			return 1;
	}

	return 0;
}

#endif /* RTE_SCHED_OPTIMIZATIONS */

static inline void
grinder_pcache_populate(struct rte_sched_port *port, uint32_t pos, uint32_t bmp_pos, uint64_t bmp_slab)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	qbitmask_t w[RTE_SCHED_GRINDER_PCACHE_SIZE] = { 0 };

	grinder->pcache_w = 0;
	grinder->pcache_r = 0;

	w[0] = (qbitmask_t) bmp_slab;
	w[1] = (qbitmask_t) (bmp_slab >> RTE_SCHED_QUEUES_PER_PIPE);
#if RTE_SCHED_GRINDER_PCACHE_SIZE == 4
	w[2] = (qbitmask_t) (bmp_slab >> (RTE_SCHED_QUEUES_PER_PIPE * 2));
	w[3] = (qbitmask_t) (bmp_slab >> (RTE_SCHED_QUEUES_PER_PIPE * 3));
#endif

	grinder->pcache_qmask[grinder->pcache_w] = w[0];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos;
	grinder->pcache_w += (w[0] != 0);

	grinder->pcache_qmask[grinder->pcache_w] = w[1];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos +
		RTE_SCHED_QUEUES_PER_PIPE;
	grinder->pcache_w += (w[1] != 0);

#if RTE_SCHED_GRINDER_PCACHE_SIZE == 4
	grinder->pcache_qmask[grinder->pcache_w] = w[2];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos +
		(RTE_SCHED_QUEUES_PER_PIPE * 2);
	grinder->pcache_w += (w[2] != 0);

	grinder->pcache_qmask[grinder->pcache_w] = w[3];
	grinder->pcache_qindex[grinder->pcache_w] = bmp_pos +
		(RTE_SCHED_QUEUES_PER_PIPE * 3);
	grinder->pcache_w += (w[3] != 0);
#endif
}

uint32_t qmask_mask[] = { 0x1, 0x3, 0xF, 0xFF };

static inline void
grinder_tccache_populate(struct rte_sched_port *port, uint32_t pos, uint32_t qindex, qbitmask_t qmask)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	uint8_t b[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE] = { 0 };

	grinder->tccache_w = 0;
	grinder->tccache_r = 0;

	b[0] = (uint8_t) (qmask & qmask_mask[RTE_SCHED_WRR_BITS]);
	b[1] = (uint8_t) ((qmask >> RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) &
			  qmask_mask[RTE_SCHED_WRR_BITS]);

#if RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE == 4
	b[2] = (uint8_t) ((qmask >> (RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS * 2)) &
			  qmask_mask[RTE_SCHED_WRR_BITS]);
	b[3] = (uint8_t) ((qmask >> (RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS * 3)) &
			  qmask_mask[RTE_SCHED_WRR_BITS]);
#endif

	grinder->tccache_qmask[grinder->tccache_w] = b[0];
	grinder->tccache_qindex[grinder->tccache_w] = qindex;
	grinder->tccache_w += (b[0] != 0);

	grinder->tccache_qmask[grinder->tccache_w] = b[1];
	grinder->tccache_qindex[grinder->tccache_w] = qindex +
		RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
	grinder->tccache_w += (b[1] != 0);

#if RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE == 4
	grinder->tccache_qmask[grinder->tccache_w] = b[2];
	grinder->tccache_qindex[grinder->tccache_w] = qindex +
		(RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS * 2);
	grinder->tccache_w += (b[2] != 0);

	grinder->tccache_qmask[grinder->tccache_w] = b[3];
	grinder->tccache_qindex[grinder->tccache_w] = qindex +
		(RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS * 3);
	grinder->tccache_w += (b[3] != 0);
#endif
}

static inline int
grinder_next_tc(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_mbuf **qbase;
	uint32_t qindex;
	uint16_t qsize;
	uint32_t q;

	if (grinder->tccache_r == grinder->tccache_w)
		return 0;

	qindex = grinder->tccache_qindex[grinder->tccache_r];
	qbase = rte_sched_port_qbase(port, qindex);
	qsize = rte_sched_port_qsize(port, qindex);

	grinder->tc_index = (qindex >> RTE_SCHED_WRR_BITS) & RTE_SCHED_TC_MASK;

	grinder->qmask = grinder->tccache_qmask[grinder->tccache_r];
	grinder->qsize = qsize;

	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++) {
		grinder->qindex[q] = qindex + q;
		grinder->queue[q] = port->queue + qindex + q;
		grinder->qbase[q] = qbase + (q * qsize);
	}

	grinder->tccache_r++;
	return 1;
}

static inline int
grinder_next_pipe(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	uint32_t pipe_qindex;
	qbitmask_t pipe_qmask;

	if (grinder->pcache_r < grinder->pcache_w) {
		pipe_qmask = grinder->pcache_qmask[grinder->pcache_r];
		pipe_qindex = grinder->pcache_qindex[grinder->pcache_r];
		grinder->pcache_r++;
	} else {
		uint64_t bmp_slab = 0;
		uint32_t bmp_pos = 0;

		/* Get another non-empty pipe group */
		if (unlikely(rte_bitmap_scan(port->bmp, &bmp_pos, &bmp_slab) <= 0))
			return 0;

#ifdef RTE_SCHED_DEBUG
		debug_check_queue_slab(port, bmp_pos, bmp_slab);
#endif

		/* Return if pipe group already in one of the other grinders */
		port->grinder_base_bmp_pos[pos] = RTE_SCHED_BMP_POS_INVALID;
		if (unlikely(grinder_pipe_exists(port, bmp_pos)))
			return 0;

		port->grinder_base_bmp_pos[pos] = bmp_pos;

		/* Install new pipe group into grinder's pipe cache */
		grinder_pcache_populate(port, pos, bmp_pos, bmp_slab);

		pipe_qmask = grinder->pcache_qmask[0];
		pipe_qindex = grinder->pcache_qindex[0];
		grinder->pcache_r = 1;
	}

	/* Install new pipe in the grinder */
	grinder->pindex = pipe_qindex >> RTE_SCHED_TC_WRR_BITS;
	grinder->subport = port->subport + (grinder->pindex / port->n_pipes_per_subport);
	grinder->pipe = port->pipe + grinder->pindex;
	grinder->pipe_params = NULL; /* to be set after the pipe structure is prefetched */
	grinder->productive = 0;

	grinder_tccache_populate(port, pos, pipe_qindex, pipe_qmask);
	grinder_next_tc(port, pos);

	/* Check for pipe exhaustion */
	if (grinder->pindex == port->pipe_loop) {
		port->pipe_exhaustion = 1;
		port->pipe_loop = RTE_SCHED_PIPE_INVALID;
	}

	return 1;
}


static inline void
grinder_wrr_load(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	struct rte_sched_pipe_profile *pipe_params = grinder->pipe_params;
	uint32_t tc_index = grinder->tc_index;
	uint32_t qmask = grinder->qmask;
	uint32_t qindex;
	uint32_t tokens;
	uint32_t q;

	qindex = tc_index * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;

	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++) {
		tokens = pipe->wrr_tokens[qindex + q] <<
			RTE_SCHED_BYTERATE_TO_BITRATE_SHIFT;
		grinder->wrr_tokens[q] = tokens;
		grinder->wrr_mask[q] = ((qmask >> q) & 0x1) * 0xFFFFFFFF;
		grinder->wrr_cost[q] = pipe_params->wrr_cost[qindex + q];
	}
}

static inline void
grinder_wrr_store(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	struct rte_sched_pipe *pipe = grinder->pipe;
	uint32_t tc_index = grinder->tc_index;
	uint32_t qindex;
	uint32_t tokens;
	uint32_t q;

	qindex = tc_index * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++) {
		tokens = (grinder->wrr_tokens[q] & grinder->wrr_mask[q]) >>
			RTE_SCHED_BYTERATE_TO_BITRATE_SHIFT;
		pipe->wrr_tokens[qindex + q] = tokens;
	}
}

static inline void
grinder_wrr(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	uint32_t wrr_tokens_min;
	uint32_t q;

	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
		grinder->wrr_tokens[q] |= ~grinder->wrr_mask[q];

	grinder->qpos = rte_min_pos_n_u32(grinder->wrr_tokens,
					  RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
	wrr_tokens_min = grinder->wrr_tokens[grinder->qpos];

	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
		grinder->wrr_tokens[q] -= wrr_tokens_min;
}


#define grinder_evict(port, pos)

static inline void
grinder_prefetch_pipe(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;

	rte_prefetch0(grinder->pipe);
	rte_prefetch0(grinder->queue[0]);
}

static inline void
grinder_prefetch_tc_queue_arrays(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	uint16_t qsize, qr[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS];
	uint32_t q;

	qsize = grinder->qsize;
	for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
		qr[q] = grinder->queue[q]->qr & (qsize - 1);

	rte_prefetch0(grinder->qbase[0] + qr[0]);
	rte_prefetch0(grinder->qbase[1] + qr[1]);

	grinder_wrr_load(port, pos);
	grinder_wrr(port, pos);

	for (q = 2; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
		rte_prefetch0(grinder->qbase[q] + qr[q]);

}

static inline void
grinder_prefetch_mbuf(struct rte_sched_port *port, uint32_t pos)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;
	uint32_t qpos = grinder->qpos;
	struct rte_mbuf **qbase = grinder->qbase[qpos];
	uint16_t qsize = grinder->qsize;
	uint16_t qr = grinder->queue[qpos]->qr & (qsize - 1);

	grinder->pkt = qbase[qr];
	rte_prefetch0(grinder->pkt);

	if (unlikely((qr & 0x7) == 7)) {
		uint16_t qr_next = (grinder->queue[qpos]->qr + 1) & (qsize - 1);

		rte_prefetch0(qbase + qr_next);
	}
}

static inline uint32_t
grinder_handle(struct rte_sched_port *port, uint32_t pos,
	       enum token_state *token_state)
{
	struct rte_sched_grinder *grinder = port->grinder + pos;

	switch (grinder->state) {
	case e_GRINDER_PREFETCH_PIPE:
	{
		if (grinder_next_pipe(port, pos)) {
			grinder_prefetch_pipe(port, pos);
			port->busy_grinders++;

			grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
			return 0;
		}

		return 0;
	}

	case e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS:
	{
		struct rte_sched_pipe *pipe = grinder->pipe;

		grinder->pipe_params = port->pipe_profiles + pipe->profile;
		grinder_prefetch_tc_queue_arrays(port, pos);
		grinder_credits_update(port, pos);

		grinder->state = e_GRINDER_PREFETCH_MBUF;
		return 0;
	}

	case e_GRINDER_PREFETCH_MBUF:
	{
		grinder_prefetch_mbuf(port, pos);

		grinder->state = e_GRINDER_READ_MBUF;
		return 0;
	}

	case e_GRINDER_READ_MBUF:
	{
		uint32_t result = 0;

		result = grinder_schedule(port, pos, token_state);

		/* Look for next packet within the same TC */
		if (result && grinder->qmask) {
			grinder_wrr(port, pos);
			grinder_prefetch_mbuf(port, pos);

			return 1;
		}
		grinder_wrr_store(port, pos);

		/* Look for another active TC within same pipe */
		if (grinder_next_tc(port, pos)) {
			grinder_prefetch_tc_queue_arrays(port, pos);

			grinder->state = e_GRINDER_PREFETCH_MBUF;
			return result;
		}

		if (grinder->productive == 0 &&
		    port->pipe_loop == RTE_SCHED_PIPE_INVALID)
			port->pipe_loop = grinder->pindex;

		grinder_evict(port, pos);

		/* Look for another active pipe */
		if (grinder_next_pipe(port, pos)) {
			grinder_prefetch_pipe(port, pos);

			grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
			return result;
		}

		/* No active pipe found */
		port->busy_grinders--;

		grinder->state = e_GRINDER_PREFETCH_PIPE;
		return result;
	}

	default:
		rte_panic("Algorithmic error (invalid state)\n");
		return 0;
	}
}

static inline void
rte_sched_port_time_resync(struct rte_sched_port *port)
{
	uint64_t cycles = rte_get_tsc_cycles();
	uint64_t cycles_diff;
	uint64_t bytes_diff;

	if (cycles < port->time_cpu_cycles)
		goto end;

	cycles_diff = cycles - port->time_cpu_cycles;
	/* Compute elapsed time in bytes */
	bytes_diff = rte_reciprocal_divide(cycles_diff << RTE_SCHED_TIME_SHIFT,
					   port->inv_cycles_per_byte);

	/* Advance port time */
	port->time_cpu_cycles +=
		(bytes_diff * port->cycles_per_byte) >> RTE_SCHED_TIME_SHIFT;
	port->time_cpu_bytes += bytes_diff;
	if (port->time < port->time_cpu_bytes)
		port->time = port->time_cpu_bytes;

end:
	/* Reset pipe loop detection */
	port->pipe_loop = RTE_SCHED_PIPE_INVALID;
}

static inline int
rte_sched_port_exceptions(struct rte_sched_port *port, int second_pass)
{
	int exceptions;

	/* Check if any exception flag is set */
	exceptions = (second_pass && port->busy_grinders == 0) ||
		(port->pipe_exhaustion == 1);

	/* Clear exception flags */
	port->pipe_exhaustion = 0;

	return exceptions;
}

int
rte_sched_port_dequeue(struct rte_sched_port *port, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	uint32_t i, count, j;
	enum token_state token_state;
	uint32_t npipes = port->n_subports_per_port *
				port->n_pipes_per_subport;

	port->pkts_out = pkts;
	port->n_pkts_out = 0;

	rte_sched_port_time_resync(port);

	/* Take each queue in the grinder one step further */
	for (i = 0, count = 0, j = 0; ; i++)  {
		token_state = TOKENS_UNDEFINED;
		count += grinder_handle(port, i & (RTE_SCHED_PORT_N_GRINDERS - 1),
					&token_state);
		if ((count == n_pkts) ||
		    rte_sched_port_exceptions(port, i >= RTE_SCHED_PORT_N_GRINDERS)) {
			break;
		}
		/* We need to look at all pipes */
		if ((i+1) < npipes)
			continue;
		/*
		 * If we've been through all the pipes and none have any
		 * tokens leave the loop.
		 */
		if (token_state == TOKENS_USED) {
			if (j++ >= npipes)
				break;
		} else if (token_state == TOKENS_AVAIL) {
			j = 0;
		}
	}

	return count;
}

struct rte_sched_queue_extra *
rte_sched_port_get_queue_extra(struct rte_sched_port *port, uint32_t qindex)
{
	return (port->queue_extra + qindex);
}
