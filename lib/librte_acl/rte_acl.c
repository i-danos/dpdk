/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <rte_eal_memconfig.h>
#include <rte_string_fns.h>
#include <rte_acl.h>
#include <rte_tailq.h>
#include <rte_vect.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_random.h>
#include <rte_mempool.h>
#include <rte_rcu_qsbr.h>

#include "acl.h"

TAILQ_HEAD(rte_acl_list, rte_tailq_entry);

static struct rte_tailq_elem rte_acl_tailq = {
	.name = "RTE_ACL",
};
EAL_REGISTER_TAILQ(rte_acl_tailq)

#ifndef CC_AVX512_SUPPORT
/*
 * If the compiler doesn't support AVX512 instructions,
 * then the dummy one would be used instead for AVX512 classify method.
 */
int
rte_acl_classify_avx512x16(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}

int
rte_acl_classify_avx512x32(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}
#endif

#ifndef CC_AVX2_SUPPORT
/*
 * If the compiler doesn't support AVX2 instructions,
 * then the dummy one would be used instead for AVX2 classify method.
 */
int
rte_acl_classify_avx2(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}
#endif

#ifndef RTE_ARCH_X86
int
rte_acl_classify_sse(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}
#endif

#ifndef RTE_ARCH_ARM
int
rte_acl_classify_neon(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}
#endif

#ifndef RTE_ARCH_PPC_64
int
rte_acl_classify_altivec(__rte_unused const struct rte_acl_ctx *ctx,
	__rte_unused const uint8_t **data,
	__rte_unused uint32_t *results,
	__rte_unused uint32_t num,
	__rte_unused uint32_t categories)
{
	return -ENOTSUP;
}
#endif

static const rte_acl_classify_t classify_fns[] = {
	[RTE_ACL_CLASSIFY_DEFAULT] = rte_acl_classify_scalar,
	[RTE_ACL_CLASSIFY_SCALAR] = rte_acl_classify_scalar,
	[RTE_ACL_CLASSIFY_SSE] = rte_acl_classify_sse,
	[RTE_ACL_CLASSIFY_AVX2] = rte_acl_classify_avx2,
	[RTE_ACL_CLASSIFY_NEON] = rte_acl_classify_neon,
	[RTE_ACL_CLASSIFY_ALTIVEC] = rte_acl_classify_altivec,
	[RTE_ACL_CLASSIFY_AVX512X16] = rte_acl_classify_avx512x16,
	[RTE_ACL_CLASSIFY_AVX512X32] = rte_acl_classify_avx512x32,
};

/*
 * Helper function for acl_check_alg.
 * Check support for ARM specific classify methods.
 */
static int
acl_check_alg_arm(enum rte_acl_classify_alg alg)
{
	if (alg == RTE_ACL_CLASSIFY_NEON) {
#if defined(RTE_ARCH_ARM64)
		if (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
			return 0;
#elif defined(RTE_ARCH_ARM)
		if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON) &&
				rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
			return 0;
#endif
		return -ENOTSUP;
	}

	return -EINVAL;
}

/*
 * Helper function for acl_check_alg.
 * Check support for PPC specific classify methods.
 */
static int
acl_check_alg_ppc(enum rte_acl_classify_alg alg)
{
	if (alg == RTE_ACL_CLASSIFY_ALTIVEC) {
#if defined(RTE_ARCH_PPC_64)
		if (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
			return 0;
#endif
		return -ENOTSUP;
	}

	return -EINVAL;
}

#ifdef CC_AVX512_SUPPORT
static int
acl_check_avx512_cpu_flags(void)
{
	return (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) &&
			rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512VL) &&
			rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512CD) &&
			rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW));
}
#endif

/*
 * Helper function for acl_check_alg.
 * Check support for x86 specific classify methods.
 */
static int
acl_check_alg_x86(enum rte_acl_classify_alg alg)
{
	if (alg == RTE_ACL_CLASSIFY_AVX512X32) {
#ifdef CC_AVX512_SUPPORT
		if (acl_check_avx512_cpu_flags() != 0 &&
			rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_512)
			return 0;
#endif
		return -ENOTSUP;
	}

	if (alg == RTE_ACL_CLASSIFY_AVX512X16) {
#ifdef CC_AVX512_SUPPORT
		if (acl_check_avx512_cpu_flags() != 0 &&
			rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256)
			return 0;
#endif
		return -ENOTSUP;
	}

	if (alg == RTE_ACL_CLASSIFY_AVX2) {
#ifdef CC_AVX2_SUPPORT
		if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2) &&
				rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256)
			return 0;
#endif
		return -ENOTSUP;
	}

	if (alg == RTE_ACL_CLASSIFY_SSE) {
#ifdef RTE_ARCH_X86
		if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_1) &&
				rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
			return 0;
#endif
		return -ENOTSUP;
	}

	return -EINVAL;
}

/*
 * Check if input alg is supported by given platform/binary.
 * Note that both conditions should be met:
 * - at build time compiler supports ISA used by given methods
 * - at run time target cpu supports necessary ISA.
 */
static int
acl_check_alg(enum rte_acl_classify_alg alg)
{
	switch (alg) {
	case RTE_ACL_CLASSIFY_NEON:
		return acl_check_alg_arm(alg);
	case RTE_ACL_CLASSIFY_ALTIVEC:
		return acl_check_alg_ppc(alg);
	case RTE_ACL_CLASSIFY_AVX512X32:
	case RTE_ACL_CLASSIFY_AVX512X16:
	case RTE_ACL_CLASSIFY_AVX2:
	case RTE_ACL_CLASSIFY_SSE:
		return acl_check_alg_x86(alg);
	/* scalar method is supported on all platforms */
	case RTE_ACL_CLASSIFY_SCALAR:
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * Get preferred alg for given platform.
 */
static enum rte_acl_classify_alg
acl_get_best_alg(void)
{
	/*
	 * array of supported methods for each platform.
	 * Note that order is important - from most to less preferable.
	 */
	static const enum rte_acl_classify_alg alg[] = {
#if defined(RTE_ARCH_ARM)
		RTE_ACL_CLASSIFY_NEON,
#elif defined(RTE_ARCH_PPC_64)
		RTE_ACL_CLASSIFY_ALTIVEC,
#elif defined(RTE_ARCH_X86)
		RTE_ACL_CLASSIFY_AVX512X32,
		RTE_ACL_CLASSIFY_AVX512X16,
		RTE_ACL_CLASSIFY_AVX2,
		RTE_ACL_CLASSIFY_SSE,
#endif
		RTE_ACL_CLASSIFY_SCALAR,
	};

	uint32_t i;

	/* find best possible alg */
	for (i = 0; i != RTE_DIM(alg) && acl_check_alg(alg[i]) != 0; i++)
		;

	/* we always have to find something suitable */
	RTE_VERIFY(i != RTE_DIM(alg));
	return alg[i];
}

extern int
rte_acl_set_ctx_classify(struct rte_acl_ctx *ctx, enum rte_acl_classify_alg alg)
{
	int32_t rc;

	/* formal parameters check */
	if (ctx == NULL || (uint32_t)alg >= RTE_DIM(classify_fns))
		return -EINVAL;

	/* user asked us to select the *best* one */
	if (alg == RTE_ACL_CLASSIFY_DEFAULT)
		alg = acl_get_best_alg();

	/* check that given alg is supported */
	rc = acl_check_alg(alg);
	if (rc != 0)
		return rc;

	ctx->alg = alg;
	return 0;
}

int
rte_acl_classify_alg(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t num, uint32_t categories,
	enum rte_acl_classify_alg alg)
{
	if (categories != 1 &&
			((RTE_ACL_RESULTS_MULTIPLIER - 1) & categories) != 0)
		return -EINVAL;

	/* don't call an empty ACL CTX */
	if (!ctx->rcx || ctx->rcx->num_tries == 0)
		return -EINVAL;

	return classify_fns[alg](ctx, data, results, num, categories);
}

int
rte_acl_classify(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t num, uint32_t categories)
{
	return rte_acl_classify_alg(ctx, data, results, num, categories,
		ctx->alg);
}

struct rte_acl_ctx *
rte_acl_find_existing(const char *name)
{
	struct rte_acl_ctx *ctx = NULL;
	struct rte_acl_list *acl_list;
	struct rte_tailq_entry *te;

	acl_list = RTE_TAILQ_CAST(rte_acl_tailq.head, rte_acl_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, acl_list, next) {
		ctx = (struct rte_acl_ctx *) te->data;
		if (strncmp(name, ctx->name, sizeof(ctx->name)) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}
	return ctx;
}

int
rte_acl_rcu_qsbr_add(struct rte_acl_ctx *ctx, struct rte_acl_rcu_config *cfg)
{
	char rcu_dq_name[RTE_RCU_QSBR_DQ_NAMESIZE];
	struct rte_rcu_qsbr_dq_parameters params;

	if (ctx == NULL || cfg == NULL)
		return -EINVAL;

	if (cfg->mode == RTE_ACL_QSBR_MODE_SYNC) {
		/* Nothing to do. */
	} else if (cfg->mode == RTE_ACL_QSBR_MODE_DQ) {
		memset(&params, 0, sizeof(params));
		snprintf(rcu_dq_name, sizeof(rcu_dq_name), "ACL_RCU_%s",
			 ctx->name);
		params.name = rcu_dq_name;
		params.flags = 0;
		params.free_fn = rte_acl_rcu_qsbr_free_rcx;
		params.v = cfg->v;
		params.size = cfg->dq_size;
		params.esize = sizeof(struct rte_acl_rcu_dq_entry);
		params.trigger_reclaim_limit = cfg->dq_trigger_reclaim_limit;
		params.max_reclaim_size = cfg->dq_max_reclaim_size;
		ctx->dq = rte_rcu_qsbr_dq_create(&params);
		if (ctx->dq == NULL) {
			RTE_LOG(ERR, ACL, "ACL defer queue creation failed: %s\n",
				rte_strerror(rte_errno));
			return -rte_errno;
		}
	} else {
		return -EINVAL;
	}

	ctx->rcu_mode = cfg->mode;
	ctx->v = cfg->v;
	ctx->rcu_thread_id = cfg->thread_id;

	return 0;
}

void
rte_acl_free(struct rte_acl_ctx *ctx)
{
	struct rte_acl_list *acl_list;
	struct rte_tailq_entry *te;

	if (ctx == NULL)
		return;

	acl_list = RTE_TAILQ_CAST(rte_acl_tailq.head, rte_acl_list);

	rte_mcfg_tailq_write_lock();

	/* find our tailq entry */
	TAILQ_FOREACH(te, acl_list, next) {
		if (te->data == (void *) ctx)
			break;
	}
	if (te == NULL) {
		rte_mcfg_tailq_write_unlock();
		return;
	}

	TAILQ_REMOVE(acl_list, te, next);

	rte_mcfg_tailq_write_unlock();

	if (ctx->dq)
		rte_rcu_qsbr_dq_delete(ctx->dq);

	if (ctx->rcx) {
		rte_free(ctx->rcx->mem);
		rte_free(ctx->rcx);
	}

	if (ctx->ht)
		rte_hash_free(ctx->ht);
	rte_free(ctx);
	rte_free(te);
}

static struct rte_hash *
acl_create_hashtable(const struct rte_acl_param *param)
{
	int ret;
	char hash_name[RTE_HASH_NAMESIZE];
	struct rte_hash *ht;

	ret = snprintf(hash_name, sizeof(hash_name), "ht_%s", param->name);
	if (ret < 0 || ret >= RTE_HASH_NAMESIZE) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	struct rte_hash_parameters hash_params = {
		.entries = param->max_rule_num  * 1.5, /* max load 75% */
		.key_len = param->hash_key_len,
		.hash_func = param->hash_func,
		.hash_func_init_val = 0,
		.name = hash_name,
		.socket_id = param->socket_id,
		.reserved = 0,
		.extra_flag = 0
	};



	ht = rte_hash_create(&hash_params);
	if (!ht)
		return NULL;

	if (param->hash_cmp_func)
		rte_hash_set_cmp_func(ht, param->hash_cmp_func);

	return ht;
}

struct rte_acl_ctx *
rte_acl_create(const struct rte_acl_param *param)
{
	size_t sz;
	struct rte_acl_ctx *ctx = NULL;
	struct rte_acl_list *acl_list;
	struct rte_tailq_entry *te;
	char name[sizeof(ctx->name)];
	struct rte_hash *ht = NULL;

	acl_list = RTE_TAILQ_CAST(rte_acl_tailq.head, rte_acl_list);

	/* check that input parameters are valid. */
	if (param == NULL || param->name == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	/* check that hashtable parameters are valid. */
	if (param->flags & ACL_F_USE_HASHTABLE
	    && (param->rule_pool == NULL || param->hash_func == NULL)) {
		rte_errno = EINVAL;
		return NULL;
	}

	snprintf(name, sizeof(name), "ACL_%s", param->name);

	if (param->flags & ACL_F_USE_HASHTABLE) {
		ht = acl_create_hashtable(param);
		if (ht == NULL) {
			RTE_LOG(ERR, ACL, "creation of hash-table on socket %d for %s failed: %s\n",
				param->socket_id, name,
				rte_strerror(rte_errno));
			return NULL;
		}
	}

	if (rte_acl_create_mask_ht() < 0)
		return NULL;

	/* calculate amount of memory required for pattern set. */
	sz = sizeof(*ctx);
	if (!(param->flags & ACL_F_USE_HASHTABLE))
		sz += param->max_rule_num * param->rule_size;

	/* get EAL TAILQ lock. */
	rte_mcfg_tailq_write_lock();

	/* if we already have one with that name */
	TAILQ_FOREACH(te, acl_list, next) {
		ctx = (struct rte_acl_ctx *) te->data;
		if (strncmp(param->name, ctx->name, sizeof(ctx->name)) == 0)
			break;
	}

	if (te) {
		rte_hash_free(ht);
		goto exit;
	}

	/* if ACL with such name doesn't exist, then create a new one. */
	te = rte_zmalloc("ACL_TAILQ_ENTRY", sizeof(*te), 0);

	if (te == NULL) {
		RTE_LOG(ERR, ACL, "Cannot allocate tailq entry!\n");
		goto error;
	}

	ctx = rte_zmalloc_socket(name, sz, RTE_CACHE_LINE_SIZE, param->socket_id);

	if (ctx == NULL) {
		RTE_LOG(ERR, ACL,
			"allocation of %zu bytes on socket %d for %s failed\n",
			sz, param->socket_id, name);
		goto error;
	}

	/* init new allocated context. */
	ctx->rules = (param->flags & ACL_F_USE_HASHTABLE) ? NULL : ctx + 1;
	ctx->max_rules = param->max_rule_num;
	ctx->rule_sz = param->rule_size;
	ctx->socket_id = param->socket_id;
	ctx->alg = acl_get_best_alg();
	ctx->flags = param->flags;
	ctx->rule_pool = param->rule_pool;
	ctx->ht = ht;
	strlcpy(ctx->name, param->name, sizeof(ctx->name));

	te->data = (void *) ctx;

	TAILQ_INSERT_TAIL(acl_list, te, next);

exit:
	rte_mcfg_tailq_write_unlock();
	return ctx;

error:
	rte_mcfg_tailq_write_unlock();
	rte_hash_free(ht);
	rte_free(te);
	rte_free(ctx);
	return NULL;
}

static struct rte_acl_rule *
acl_rule_create(struct rte_acl_ctx *ctx)
{
	int ret;
	struct rte_acl_rule *rule;

	if (!ctx)
		return NULL;

	ret = rte_mempool_get(ctx->rule_pool, (void *)&rule);
	if (ret < 0)
		return NULL;

	return rule;
}

static void
acl_rule_free(struct rte_acl_ctx *ctx, struct rte_acl_rule *rule)
{
	if (!ctx || !rule)
		return;

	rte_mempool_put(ctx->rule_pool, (void *)rule);
}

static int
acl_del_rule_ht(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rule)
{
	int ret;
	struct rte_acl_rule *res = NULL;

	ret = rte_hash_lookup_data(ctx->ht, (const void *) rule,
				   (void **) &res);
	if (ret < 0) {
		if (ret == -ENOENT)
			return ret;

		RTE_LOG(ERR, ACL, "lookup of rule on socket %d for %s failed: %s\n",
				ctx->socket_id, ctx->name,
				rte_strerror(-ret));
		return ret;
	}

	ret = rte_hash_del_key(ctx->ht, (const void *) rule);
	if (ret < 0) {
		RTE_LOG(ERR, ACL, "deleting rule on socket %d for %s failed: %s\n",
				ctx->socket_id, ctx->name,
				rte_strerror(-ret));
		return ret;
	}

	acl_rule_free(ctx, res);

	ctx->num_rules--;

	return 0;
}

int
rte_acl_del_rule(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rule)
{
	if (ctx == NULL || rule == NULL || 0 == ctx->rule_sz)
		return -EINVAL;

	if (ctx->ht)
		return acl_del_rule_ht(ctx, rule);
	else
		return -ENOTSUP;
}


static int
acl_add_rules_ht(struct rte_acl_ctx *ctx, const void *rules, uint32_t num)
{
	int ret;
	uint32_t i;
	const uint8_t *pos;
	struct rte_acl_rule *rule;

	/* With flag ACL_F_USE_HASHTABLE set, it is mandatory
	 * to have unique rules only.
	 * If a rule/key already exists, none of the supplied rules
	 * get added.
	 */
	for (i=0, pos = rules; i < num; i++, pos += ctx->rule_sz) {
		ret = rte_hash_lookup(ctx->ht, pos);
		if (ret != -ENOENT)
			return -EEXIST;
	}

	for (i=0, pos = rules; i < num; i++, pos += ctx->rule_sz) {

		rule = acl_rule_create(ctx);
		if (!rule) {
			if (rte_errno == ENOENT)
				return -rte_errno;

			RTE_LOG(ERR, ACL, "creating rule #%d on socket %d for %s failed: %s\n",
				i, ctx->socket_id, ctx->name,
				rte_strerror(rte_errno));
			return -rte_errno;
		}

		memset(rule, 0, ctx->rule_sz);
		memcpy(rule, pos, ctx->rule_sz);

		ret = rte_hash_add_key_data(ctx->ht, rule, (void *) rule);
		if (ret < 0) {
			RTE_LOG(ERR, ACL, "adding rule #%d to hash-table on socket %d for %s failed: %s\n",
				i, ctx->socket_id, ctx->name,
				rte_strerror(rte_errno));

			num = i;

			goto error;
		}

		ctx->num_rules++;
	}

	return 0;

error:

	for (i=0, pos = rules; i < num; i++, pos += ctx->rule_sz) {
		acl_del_rule_ht(ctx, rule);
	}

	return ret;
}

static int
acl_add_rules(struct rte_acl_ctx *ctx, const void *rules, uint32_t num)
{
	uint8_t *pos;

	if (num + ctx->num_rules > ctx->max_rules)
		return -ENOMEM;

	if (ctx->ht)
		return acl_add_rules_ht(ctx, rules, num);

	pos = ctx->rules;
	pos += ctx->rule_sz * ctx->num_rules;
	memcpy(pos, rules, num * ctx->rule_sz);
	ctx->num_rules += num;

	return 0;
}

static int
acl_check_rule(const struct rte_acl_rule_data *rd)
{
	if ((RTE_LEN2MASK(RTE_ACL_MAX_CATEGORIES, typeof(rd->category_mask)) &
			rd->category_mask) == 0 ||
			rd->priority > RTE_ACL_MAX_PRIORITY ||
			rd->priority < RTE_ACL_MIN_PRIORITY)
		return -EINVAL;
	return 0;
}

static int
acl_check_rules(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rules,
		uint32_t num)
{
	const struct rte_acl_rule *rv;
	uint32_t i;
	int32_t rc;

	for (i = 0; i != num; i++) {
		rv = (const struct rte_acl_rule *)
			((uintptr_t)rules + i * ctx->rule_sz);
		rc = acl_check_rule(&rv->data);
		if (rc != 0) {
			RTE_LOG(ERR, ACL, "%s(%s): rule #%u is invalid\n",
				__func__, ctx->name, i + 1);
			return rc;
		}
	}

	return 0;
}

int
rte_acl_add_rules(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rules,
	uint32_t num)
{
	const struct rte_acl_rule *rv;
	uint32_t i;
	int32_t rc;

	if (ctx == NULL || rules == NULL || 0 == ctx->rule_sz)
		return -EINVAL;

	rc = acl_check_rules(ctx, rules, num);
	if (rc)
		return rc;

	return acl_add_rules(ctx, rules, num);
}

static int
acl_copy_rules_ht(struct rte_acl_ctx *dst_ctx,
		  const struct rte_acl_ctx *src_ctx)
{

#define MAX_BATCH 512
	uint32_t bulk_sz, nb_rules;
	uint32_t iter = 0, nb_copied = 0;
	struct rte_acl_rule *src_rule, *rule;
	struct rte_acl_rule *rules[MAX_BATCH];
	int err, ret;
	void *key;

	if (!dst_ctx->ht || !dst_ctx->rule_pool || !src_ctx->ht)
		return -EINVAL;

	nb_rules = src_ctx->num_rules;

	if (rte_mempool_avail_count(dst_ctx->rule_pool) < nb_rules)
		return -ENOBUFS;

	while (nb_rules) {

		if (nb_rules > MAX_BATCH)
			bulk_sz = MAX_BATCH;
		else
			bulk_sz = nb_rules;


		ret = rte_mempool_get_bulk(dst_ctx->rule_pool, (void **)rules,
					   bulk_sz);
		if (ret < 0) {
			if (ret == -ENOBUFS)
				goto error;

			RTE_LOG(ERR, ACL,
				"Could not allocate memory for destination ctx %s : %s\n",
				dst_ctx->name, rte_strerror(-ret));
			goto error;
		}

		while (bulk_sz-- > 0 && rte_hash_iterate(src_ctx->ht,
							 (void *) &key,
							 (void **) &src_rule,
							 &iter) >= 0) {

			rule = rules[bulk_sz];

			memcpy(rule, src_rule, src_ctx->rule_sz);

			ret = rte_hash_add_key_data(dst_ctx->ht, rule,
						    (void *) rule);
			if (ret < 0) {
				RTE_LOG(ERR, ACL,
					"Rule addition failed on ctx %s : %s\n",
					dst_ctx->name, rte_strerror(-ret));
				goto error;
			}

			nb_copied++;
			nb_rules--;
			dst_ctx->num_rules++;
		}
	}
	return 0;

error:
	iter = 0;
	while (nb_copied-- > 0 && rte_hash_iterate(src_ctx->ht, (void *)&key,
						   (void **)&rule, &iter) >= 0) {
		err = rte_hash_del_key(dst_ctx->ht, (const void *)rule);
		if (err < 0) {
			RTE_LOG(ERR, ACL,
				"Rule deletion failed during cleanup on ctx %s : %s\n",
				dst_ctx->name, rte_strerror(-err));
			continue;
		}
		acl_rule_free(dst_ctx, rule);
		dst_ctx->num_rules--;
	}
	return ret;
}


int
rte_acl_copy_rules(struct rte_acl_ctx *dst_ctx,
		   const struct rte_acl_ctx *src_ctx)
{
	const struct rte_acl_rule *rules;
	const struct rte_acl_rule *rv;
	uint32_t i;
	int32_t rc;

	if (dst_ctx == NULL || src_ctx == NULL || 0 == dst_ctx->rule_sz ||
	    0 == src_ctx->rule_sz)
		return -EINVAL;

	if (dst_ctx->flags != src_ctx->flags) {
		RTE_LOG(ERR, ACL,
			"Copying only supported between ACLs with same flags\n");
		return -EINVAL;
	}

	if (dst_ctx->ht)
		return acl_copy_rules_ht(dst_ctx, src_ctx);

	return acl_add_rules(dst_ctx, src_ctx->rules, src_ctx->num_rules);
}

/*
 * Reset all rules.
 * Note that RT structures are not affected.
 */
void
rte_acl_reset_rules(struct rte_acl_ctx *ctx)
{
	uint32_t iter = 0;
	struct rte_acl_rule *r;
	void *key;

	if (ctx == NULL)
		return;

	ctx->num_rules = 0;

	if (ctx->ht == NULL)
		return;

	while (rte_hash_iterate(ctx->ht, (void *) &key, (void **) &r, &iter)
	       >= 0) {
		acl_rule_free(ctx, r);
	}

	rte_hash_reset(ctx->ht);
}

/*
 * Reset all rules and destroys RT structures.
 */
void
rte_acl_reset(struct rte_acl_ctx *ctx)
{
	struct rte_acl_rt_ctx *rcx;

	if (!ctx)
		return;

	rcx = ctx->rcx;
	rte_acl_reset_rules(ctx);
	rte_acl_build(ctx, rcx ? &rcx->config: NULL);

	if (ctx->rcu_mode == RTE_ACL_QSBR_MODE_DQ)
		rte_rcu_qsbr_dq_reclaim(ctx->dq, ~0, NULL, NULL, NULL);
}

/*
 * Dump ACL context to the stdout.
 */
void
rte_acl_dump(const struct rte_acl_ctx *ctx)
{
	if (!ctx)
		return;
	printf("acl context <%s>@%p\n", ctx->name, ctx);
	printf("  socket_id=%"PRId32"\n", ctx->socket_id);
	printf("  alg=%"PRId32"\n", ctx->alg);
	printf("  first_load_sz=%"PRIu32"\n", ctx->first_load_sz);
	printf("  max_rules=%"PRIu32"\n", ctx->max_rules);
	printf("  rule_size=%"PRIu32"\n", ctx->rule_sz);
	printf("  num_rules=%"PRIu32"\n", ctx->num_rules);
	printf("  num_categories=%"PRIu32"\n", ctx->num_categories);
	printf("  num_tries=%"PRIu32"\n", ctx->rcx ? ctx->rcx->num_tries: 0);
	printf("  flags=%u\n", ctx->flags);
}

/*
 * Dump all ACL contexts to the stdout.
 */
void
rte_acl_list_dump(void)
{
	struct rte_acl_ctx *ctx;
	struct rte_acl_list *acl_list;
	struct rte_tailq_entry *te;

	acl_list = RTE_TAILQ_CAST(rte_acl_tailq.head, rte_acl_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, acl_list, next) {
		ctx = (struct rte_acl_ctx *) te->data;
		rte_acl_dump(ctx);
	}
	rte_mcfg_tailq_read_unlock();
}
