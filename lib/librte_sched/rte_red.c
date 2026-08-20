/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <math.h>
#include "rte_sched.h"
#include <rte_random.h>
#include <rte_common.h>

#ifdef __INTEL_COMPILER
#pragma warning(disable:2259) /* conversion may lose significant bits */
#endif

static int rte_red_init_done = 0;     /**< Flag to indicate that global initialisation is done */
uint32_t rte_red_rand_val = 0;        /**< Random value cache */
uint32_t rte_red_rand_seed = 0;       /**< Seed for random number generation */
uint8_t rte_red_scaling = RTE_RED_SCALING_DEFAULT;
uint16_t rte_red_max_threshold = RTE_RED_DEFAULT_QUEUE_LENGTH - 1;

/**
 * table[i] = log2(1-Wq) * Scale * -1
 *       Wq = 1/(2^i)
 */
uint16_t rte_red_log2_1_minus_Wq[RTE_RED_WQ_LOG2_NUM];

/**
 * table[i] = 2^(i/16) * Scale
 */
uint16_t rte_red_pow2_frac_inv[16];

/**
 * @brief Initialize tables used to compute average
 *        queue size when queue is empty.
 */
static void
__rte_red_init_tables(void)
{
	uint32_t i = 0;
	double scale = 0.0;
	double table_size = 0.0;

	scale = (double)(1 << rte_red_scaling);
	table_size = (double)(RTE_DIM(rte_red_pow2_frac_inv));

	for (i = 0; i < RTE_DIM(rte_red_pow2_frac_inv); i++) {
		double m = (double)i;

		rte_red_pow2_frac_inv[i] = (uint16_t) round(scale / pow(2, m / table_size));
	}

	scale = 1024.0;

	RTE_ASSERT(RTE_RED_WQ_LOG2_NUM == RTE_DIM(rte_red_log2_1_minus_Wq));

	for (i = RTE_RED_WQ_LOG2_MIN; i <= RTE_RED_WQ_LOG2_MAX; i++) {
		double n = (double)i;
		double Wq = pow(2, -n);
		uint32_t index = i - RTE_RED_WQ_LOG2_MIN;

		rte_red_log2_1_minus_Wq[index] = (uint16_t) round(-1.0 * scale * log2(1.0 - Wq));
		/**
		* Table entry of zero, corresponds to a Wq of zero
		* which is not valid (avg would remain constant no
		* matter how long the queue is empty). So we have
		* to check for zero and round up to one.
		*/
		if (rte_red_log2_1_minus_Wq[index] == 0) {
			rte_red_log2_1_minus_Wq[index] = 1;
		}
	}
}

int
rte_red_rt_data_init(struct rte_red *red)
{
	if (red == NULL)
		return -1;

	red->avg = 0;
	red->count = 0;
	red->q_time = 0;
	return 0;
}

int
rte_red_config_init(struct rte_red_config *red_cfg,
	const uint16_t wq_log2,
	const uint16_t min_th,
	const uint16_t max_th,
	const uint16_t maxp_inv)
{
	if (red_cfg == NULL) {
		return -1;
	}
	if (max_th > rte_red_max_threshold) {
		return -2;
	}
	if (min_th >= max_th) {
		return -3;
	}
	if (wq_log2 > RTE_RED_WQ_LOG2_MAX) {
		return -4;
	}
	if (wq_log2 < RTE_RED_WQ_LOG2_MIN) {
		return -5;
	}
	if (maxp_inv < RTE_RED_MAXP_INV_MIN) {
		return -6;
	}
	if (maxp_inv > RTE_RED_MAXP_INV_MAX) {
		return -7;
	}

	/**
	 *  Initialize the RED module if not already done
	 */
	if (!rte_red_init_done) {
		rte_red_rand_seed = rte_rand();
		rte_red_rand_val = rte_fast_rand();
		__rte_red_init_tables();
		rte_red_init_done = 1;
	}

	red_cfg->min_th = ((uint32_t) min_th) << (wq_log2 + rte_red_scaling);
	red_cfg->max_th = ((uint32_t) max_th) << (wq_log2 + rte_red_scaling);
	red_cfg->pa_const = (2 * (max_th - min_th) * maxp_inv) << rte_red_scaling;
	red_cfg->maxp_inv = maxp_inv;
	red_cfg->wq_log2 = wq_log2;

	return 0;
}

int
rte_red_set_scaling(uint16_t max_red_queue_length)
{
	int8_t count;

	if (rte_red_init_done)
		/**
		 * Can't change the scaling once the red table has been
		 * computed.
		 */
		return -1;

	if (max_red_queue_length < RTE_RED_MIN_QUEUE_LENGTH)
		return -2;

	if (max_red_queue_length > RTE_RED_MAX_QUEUE_LENGTH)
		return -3;

	if (!rte_is_power_of_2(max_red_queue_length))
		return -4;

	count = 0;
	while (max_red_queue_length != 0) {
		max_red_queue_length >>= 1;
		count++;
	}

	rte_red_scaling -= count - RTE_RED_SCALING_DEFAULT;
	rte_red_max_threshold = max_red_queue_length - 1;
	return 0;
}

void
rte_red_reset_scaling(void)
{
	rte_red_init_done = 0;
	rte_red_scaling = RTE_RED_SCALING_DEFAULT;
	rte_red_max_threshold = RTE_RED_DEFAULT_QUEUE_LENGTH - 1;
}

struct rte_red_pipe_params *
rte_red_alloc_q_params(struct rte_sched_pipe_params *pipe, unsigned int qindex)
{
	struct rte_red_pipe_params *wred_params;

	wred_params = malloc(sizeof(struct rte_red_pipe_params));
	if (!wred_params) {
		RTE_LOG(ERR, SCHED, "qred_info calloc failed\n");
		return NULL;
	}
	memset(wred_params, 0, sizeof(struct rte_red_pipe_params));
	wred_params->qindex = qindex;
	SLIST_INSERT_HEAD(&pipe->qred_head, wred_params, list);
	return wred_params;
}

struct rte_red_pipe_params *
rte_red_copy_params(struct rte_sched_pipe_params *p_profs,
		    const struct rte_red_pipe_params *orig, uint32_t qindex)
{
	struct rte_red_pipe_params *copy_params;
	int num_params;
	const struct rte_red_q_params *from;
	struct rte_red_q_params *to;
	int i, ret;

	copy_params = rte_red_alloc_q_params(p_profs, qindex);
	if (!copy_params)
		return NULL;

	memcpy(&copy_params->red_q_params, &orig->red_q_params,
	       sizeof(struct rte_red_q_params));
	copy_params->alloced = true;
	num_params = copy_params->red_q_params.num_maps;
	from = &orig->red_q_params;
	to = &copy_params->red_q_params;
	for (i = 0; i < num_params; i++) {
		ret = asprintf(&to->grp_names[i], "%s", from->grp_names[i]);
		if (ret < 0) {
			SLIST_REMOVE_HEAD(&p_profs->qred_head, list);
			for (i--; i >= 0; i--)
				free(to->grp_names[i]);
			free(copy_params);
			return NULL;
		}
	}
	return copy_params;
}

struct rte_red_pipe_params *
rte_red_find_q_params(struct rte_sched_pipe_params *pipe, unsigned int qindex)
{
	struct rte_red_pipe_params *wred_params = NULL;

	SLIST_FOREACH(wred_params, &pipe->qred_head, list) {
		if (wred_params->qindex == qindex)
			break;
	}
	return wred_params;
}

int
rte_red_init_q_params(struct rte_red_q_params *wred_params,
                      unsigned qmax, unsigned qmin, unsigned prob,
                      uint64_t dscp_set, char *grp_name)
{
	int wred_index, ret;

	if (!wred_params || wred_params->num_maps > RTE_MAX_DSCP_MAPS) {
		RTE_LOG(ERR, SCHED, "Invalid DSCP map init params\n");
		return -1;
	}

	/*
	 * Make sure we're not downloading the same map again
	 */
	for (wred_index = 0; wred_index < wred_params->num_maps; wred_index++) {
		if (!wred_params->grp_names[wred_index])
			continue;
		if (!strcmp(wred_params->grp_names[wred_index], grp_name))
			return 0;
	}

	wred_index = wred_params->num_maps++;
	wred_params->qparams[wred_index].max_th = qmax;
	wred_params->qparams[wred_index].min_th = qmin;
	wred_params->qparams[wred_index].maxp_inv = prob;
	wred_params->dscp_set[wred_index] = dscp_set;
	ret = asprintf(&wred_params->grp_names[wred_index], "%s", grp_name);
	if (ret < 0)
		wred_params->grp_names[wred_index] = NULL;
	return 0;
}

void
rte_red_free_q_params(struct rte_sched_pipe_params *pipe, int i)
{
	struct rte_red_pipe_params *wred_params;
	struct rte_red_q_params *qparams;

	while ((wred_params = SLIST_FIRST(&pipe->qred_head)) != NULL) {
		int j;

		SLIST_REMOVE_HEAD(&pipe->qred_head, list);
		RTE_LOG(DEBUG, SCHED,
			"Freeing Q RED params qindex %u profile "
			"%u pipe %p wred_params %p\n",
			wred_params->qindex, i, pipe, wred_params);
		qparams = &(wred_params->red_q_params);
		for (j = 0; j < RTE_NUM_DSCP_MAPS; j++) {
			if (qparams->grp_names[j])
				free(qparams->grp_names[j]);
		}
		free(wred_params);
	}
}

int
rte_red_queue_num_maps(struct rte_sched_port *port, uint32_t queue_id)
{
	struct rte_sched_queue_extra *qe;

	/* Check user parameters */
	if ((port == NULL) ||
 	    (queue_id >= rte_sched_port_queues_per_port(port)))
		return -1;

	qe = rte_sched_port_get_queue_extra(port, queue_id);
	if (!qe)
		return -1;

	return qe->qred.num_maps;
}
