/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_ACL_H_
#define _RTE_ACL_H_

/**
 * @file
 *
 * RTE Classifier.
 */

#include <rte_acl_osdep.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	RTE_ACL_MAX_CATEGORIES	16

#define	RTE_ACL_RESULTS_MULTIPLIER	(XMM_SIZE / sizeof(uint32_t))

#define RTE_ACL_MAX_LEVELS 64
#define RTE_ACL_MAX_FIELDS 64

union rte_acl_field_types {
	uint8_t  u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
};

enum {
	RTE_ACL_FIELD_TYPE_MASK = 0,
	RTE_ACL_FIELD_TYPE_RANGE,
	RTE_ACL_FIELD_TYPE_BITMASK
};

/**
 * ACL Field definition.
 * Each field in the ACL rule has an associate definition.
 * It defines the type of field, its size, its offset in the input buffer,
 * the field index, and the input index.
 * For performance reasons, the inner loop of the search function is unrolled
 * to process four input bytes at a time. This requires the input to be grouped
 * into sets of 4 consecutive bytes. The loop processes the first input byte as
 * part of the setup and then subsequent bytes must be in groups of 4
 * consecutive bytes.
 */
struct rte_acl_field_def {
	uint8_t  type;        /**< type - RTE_ACL_FIELD_TYPE_*. */
	uint8_t	 size;        /**< size of field 1,2,4, or 8. */
	uint8_t	 field_index; /**< index of field inside the rule. */
	uint8_t  input_index; /**< 0-N input index. */
	uint32_t offset;      /**< offset to start of field. */
};

/**
 * ACL build configuration.
 * Defines the fields of an ACL trie and number of categories to build with.
 */
struct rte_acl_config {
	uint32_t num_categories; /**< Number of categories to build with. */
	uint32_t num_fields;     /**< Number of field definitions. */
	struct rte_acl_field_def defs[RTE_ACL_MAX_FIELDS];
	/**< array of field definitions. */
	size_t max_size;
	/**< max memory limit for internal run-time structures. */
};

/** RCU reclamation modes */
enum rte_acl_qsbr_mode {
	/** Create defer queue for reclaim. */
	RTE_ACL_QSBR_MODE_DQ = 0,
	/** Use blocking mode reclaim. No defer queue created. */
	RTE_ACL_QSBR_MODE_SYNC
};

/** ACL RCU QSBR configuration. */
struct rte_acl_rcu_config {
	struct rte_rcu_qsbr *v; /**< RCU QSBR variable. */
	enum rte_acl_qsbr_mode mode;
	/**< Mode of RCU QSBR: RTE_ACL_QSBR_MODE_xxx */
	unsigned int thread_id;
	/**< Thread ID of the caller if it is registered to report quiescent
	 * state on this QS variable. If not, pass RTE_QSBR_THRID_INVALID.
	 */
	uint32_t dq_size; /**<Defer queue size. */
	uint32_t dq_trigger_reclaim_limit;
	/**<Threshold to trigger defer queue automatic reclamation.
	 * Set to 0, to trigger reclamation on every rte_acl_build call.
	 */
	uint32_t dq_max_reclaim_size;
	/**<When a threshold to trigger automatic reclation of the defer queue
	 * is set, this is the maximum number of rte_acl_build runntime contexts
	 * being reclaimed.
	 */
};

/**
 * Defines the value of a field for a rule.
 */
struct rte_acl_field {
	union rte_acl_field_types value;
	/**< a 1,2,4, or 8 byte value of the field. */
	union rte_acl_field_types mask_range;
	/**<
	 * depending on field type:
	 * mask -> 1.2.3.4/32 value=0x1020304, mask_range=32,
	 * range -> 0 : 65535 value=0, mask_range=65535,
	 * bitmask -> 0x06/0xff value=6, mask_range=0xff.
	 */
};

enum {
	RTE_ACL_TYPE_SHIFT = 29,
	RTE_ACL_MAX_INDEX = RTE_LEN2MASK(RTE_ACL_TYPE_SHIFT, uint32_t),
	RTE_ACL_MAX_PRIORITY = RTE_ACL_MAX_INDEX,
	RTE_ACL_MIN_PRIORITY = 1,
};

#define	RTE_ACL_MASKLEN_TO_BITMASK(v, s)	\
((v) == 0 ? (v) : (typeof(v))((uint64_t)-1 << ((s) * CHAR_BIT - (v))))

/**
 * Miscellaneous data for ACL rule.
 */
struct rte_acl_rule_data {
	uint32_t category_mask; /**< Mask of categories for that rule. */
	int32_t  priority;      /**< Priority for that rule. */
	uint32_t userdata;      /**< Associated with the rule user data. */
};

/**
 * Defines single ACL rule.
 * data - miscellaneous data for the rule.
 * field[] - value and mask or range for each field.
 */
#define	RTE_ACL_RULE_DEF(name, fld_num)	struct name {\
	struct rte_acl_rule_data data;               \
	struct rte_acl_field field[fld_num];         \
}

RTE_ACL_RULE_DEF(rte_acl_rule,);

#define	RTE_ACL_RULE_SZ(fld_num)	\
	(sizeof(struct rte_acl_rule) + sizeof(struct rte_acl_field) * (fld_num))


/** Max number of characters in name.*/
#define	RTE_ACL_NAMESIZE		32

/** Type of function that can be used for calculating the hash value. */
typedef uint32_t (*rte_acl_hash_function)(const void *key, uint32_t key_len,
					  uint32_t init_val);

/** Type of function to compare the rule hash key */
typedef int (*rte_acl_hash_cmp_eq_t)(const void *key1, const void *key2,
				     size_t key_len);

/**
 * Parameters used when creating the ACL context.
 */
struct rte_acl_param {
	const char *name;         /**< Name of the ACL context. */
	int         socket_id;    /**< Socket ID to allocate memory for. */
	uint32_t    rule_size;    /**< Size of each rule. */
	uint32_t    max_rule_num; /**< Maximum number of rules. */

	unsigned int flags;                  /**< Flags of the ACL context. */
	struct rte_mempool *rule_pool;       /**< Memory pool for ACLs, used with ACL_F_USE_HASHTABLE. */
	uint32_t hash_key_len;               /**< Length of hash key. */
	rte_acl_hash_function hash_func;     /**< Function used to calculate hash. */
	rte_acl_hash_cmp_eq_t hash_cmp_func; /**< Function used to compare keys of hash-table. */
};

#define ACL_F_USE_HASHTABLE 0x0001 /**< Use hashtable for ACL context entries. */


/**
 * Create a new ACL context.
 *
 * @param param
 *   Parameters used to create and initialise the ACL context.
 * @return
 *   Pointer to ACL context structure that is used in future ACL
 *   operations, or NULL on error, with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL - invalid parameter passed to function
 */
struct rte_acl_ctx *
rte_acl_create(const struct rte_acl_param *param);

/**
 * Find an existing ACL context object and return a pointer to it.
 *
 * @param name
 *   Name of the ACL context as passed to rte_acl_create()
 * @return
 *   Pointer to ACL context or NULL if object not found
 *   with rte_errno set appropriately. Possible rte_errno values include:
 *    - ENOENT - value not available for return
 */
struct rte_acl_ctx *
rte_acl_find_existing(const char *name);

/**
 * De-allocate all memory used by ACL context.
 *
 * @param ctx
 *   ACL context to free
 */
void
rte_acl_free(struct rte_acl_ctx *ctx);

/**
 * Associate RCU QSBR variable with the ACL context.
 *
 * @param ctx
 *   ACL context to add RCU QSBR
 * @param cfg
 *   RCU QSBR configuration
 * @return
 *   On success - 0
 *   On error - 1 with error code set in rte_errno.
 *   Possible rte_errno errors include:
 *   - EINVAL if the parameters are invalid.
 *   - EEXIST if QSBR already added.
 *   - ENOMEM if the memory allocation failed.
 *   - Zero if operation completed successfully.
 */
int
rte_acl_rcu_qsbr_add(struct rte_acl_ctx *ctx, struct rte_acl_rcu_config *cfg);

/**
 * Add rules to an existing ACL context.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to add patterns to.
 * @param rules
 *   Array of rules to add to the ACL context.
 *   Note that all fields in rte_acl_rule structures are expected
 *   to be in host byte order.
 *   Each rule expected to be in the same format and not exceed size
 *   specified at ACL context creation time.
 * @param num
 *   Number of elements in the input array of rules.
 * @return
 *   - -ENOMEM if there is no space in the ACL context for these rules.
 *   - -EINVAL if the parameters are invalid.
 *   - Zero if operation completed successfully.
 */
int
rte_acl_add_rules(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rules,
	uint32_t num);

/**
 * Delete rule of an existing ACL context.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to add patterns to.
 * @param rule
 *   Single rule which should get deleted.
 * @return
 *   - -ENOENT if the rule could not be found.
 *   - -EINVAL if the parameters are invalid.
 *   - Zero if operation completed successfully.
 */
int
rte_acl_del_rule(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rule);

/**
 * Copy rules from src context to dest context
 * This function is not multi-thread safe
 * This function is used to copy the build time array of rules maintained
 * within the acl context to a new context to enable a merge of contexts
 *
 * @param dst_ctx
 *  Destination context to add rules to
 * @param src_ctx
 *  Source context to copy rules from
 * @return
 *  - -ENOMEM - if there is no space in the ACL context for these rules
 *  - -EINVAL if the parameters are invalid
 *  - Zero if the operation completed successfully.
 */
int
rte_acl_copy_rules(struct rte_acl_ctx *dst_ctx,
		   const struct rte_acl_ctx *src_ctx);

/**
 * Delete all rules from the ACL context.
 * This function is not multi-thread safe.
 * Note that internal run-time structures are not affected.
 *
 * @param ctx
 *   ACL context to delete rules from.
 */
void
rte_acl_reset_rules(struct rte_acl_ctx *ctx);

/**
 * Analyze set of rules and build required internal run-time structures.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to build.
 * @param cfg
 *   Pointer to struct rte_acl_config - defines build parameters.
 * @return
 *   - -ENOMEM if couldn't allocate enough memory.
 *   - -EINVAL if the parameters are invalid.
 *   - Negative error code if operation failed.
 *   - Zero if operation completed successfully.
 */
int
rte_acl_build(struct rte_acl_ctx *ctx, const struct rte_acl_config *cfg);

/**
 * Delete all rules from the ACL context and
 * destroy all internal run-time structures.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to reset.
 */
void
rte_acl_reset(struct rte_acl_ctx *ctx);

/**
 *  Available implementations of ACL classify.
 */
enum rte_acl_classify_alg {
	RTE_ACL_CLASSIFY_DEFAULT = 0,
	RTE_ACL_CLASSIFY_SCALAR = 1,  /**< generic implementation. */
	RTE_ACL_CLASSIFY_SSE = 2,     /**< requires SSE4.1 support. */
	RTE_ACL_CLASSIFY_AVX2 = 3,    /**< requires AVX2 support. */
	RTE_ACL_CLASSIFY_NEON = 4,    /**< requires NEON support. */
	RTE_ACL_CLASSIFY_ALTIVEC = 5,    /**< requires ALTIVEC support. */
	RTE_ACL_CLASSIFY_AVX512X16 = 6,  /**< requires AVX512 support. */
	RTE_ACL_CLASSIFY_AVX512X32 = 7,  /**< requires AVX512 support. */
};

/**
 * Perform search for a matching ACL rule for each input data buffer.
 * Each input data buffer can have up to *categories* matches.
 * That implies that results array should be big enough to hold
 * (categories * num) elements.
 * Also categories parameter should be either one or multiple of
 * RTE_ACL_RESULTS_MULTIPLIER and can't be bigger than RTE_ACL_MAX_CATEGORIES.
 * If more than one rule is applicable for given input buffer and
 * given category, then rule with highest priority will be returned as a match.
 * Note, that it is a caller's responsibility to ensure that input parameters
 * are valid and point to correct memory locations.
 *
 * @param ctx
 *   ACL context to search with.
 * @param data
 *   Array of pointers to input data buffers to perform search.
 *   Note that all fields in input data buffers supposed to be in network
 *   byte order (MSB).
 * @param results
 *   Array of search results, *categories* results per each input data buffer.
 * @param num
 *   Number of elements in the input data buffers array.
 * @param categories
 *   Number of maximum possible matches for each input buffer, one possible
 *   match per category.
 * @return
 *   zero on successful completion.
 *   -EINVAL for incorrect arguments.
 */
extern int
rte_acl_classify(const struct rte_acl_ctx *ctx,
		 const uint8_t **data,
		 uint32_t *results, uint32_t num,
		 uint32_t categories);

/**
 * Perform search using specified algorithm for a matching ACL rule for
 * each input data buffer.
 * Each input data buffer can have up to *categories* matches.
 * That implies that results array should be big enough to hold
 * (categories * num) elements.
 * Also categories parameter should be either one or multiple of
 * RTE_ACL_RESULTS_MULTIPLIER and can't be bigger than RTE_ACL_MAX_CATEGORIES.
 * If more than one rule is applicable for given input buffer and
 * given category, then rule with highest priority will be returned as a match.
 * Note, that it is a caller's responsibility to ensure that input parameters
 * are valid and point to correct memory locations.
 *
 * @param ctx
 *   ACL context to search with.
 * @param data
 *   Array of pointers to input data buffers to perform search.
 *   Note that all fields in input data buffers supposed to be in network
 *   byte order (MSB).
 * @param results
 *   Array of search results, *categories* results per each input data buffer.
 * @param num
 *   Number of elements in the input data buffers array.
 * @param categories
 *   Number of maximum possible matches for each input buffer, one possible
 *   match per category.
 * @param alg
 *   Algorithm to be used for the search.
 *   It is the caller responsibility to ensure that the value refers to the
 *   existing algorithm, and that it could be run on the given CPU.
 * @return
 *   zero on successful completion.
 *   -EINVAL for incorrect arguments.
 */
extern int
rte_acl_classify_alg(const struct rte_acl_ctx *ctx,
		 const uint8_t **data,
		 uint32_t *results, uint32_t num,
		 uint32_t categories,
		 enum rte_acl_classify_alg alg);

/*
 * Override the default classifier function for a given ACL context.
 * @param ctx
 *   ACL context to change classify function for.
 * @param alg
 *   New default classify algorithm for given ACL context.
 *   It is the caller responsibility to ensure that the value refers to the
 *   existing algorithm, and that it could be run on the given CPU.
 *   The max SIMD bitwidth value in EAL must also allow for the chosen algorithm.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - -ENOTSUP requested algorithm is not supported by given platform.
 *   - Zero if operation completed successfully.
 */
extern int
rte_acl_set_ctx_classify(struct rte_acl_ctx *ctx,
	enum rte_acl_classify_alg alg);

/**
 * Dump an ACL context structure to the console.
 *
 * @param ctx
 *   ACL context to dump.
 */
void
rte_acl_dump(const struct rte_acl_ctx *ctx);

/**
 * Dump all ACL context structures to the console.
 */
void
rte_acl_list_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ACL_H_ */
