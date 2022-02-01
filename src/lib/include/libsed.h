/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _LIBSED_H_
#define _LIBSED_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define SED_MAX_KEY_LEN (32)
#define SED_MIN_KEY_LEN (8)

#define SED_OPAL_MAX_LRS 9

#define MAX_PROP_NAME_LEN 32
#define NUM_TPER_PROPS    23

/* Level0 features */
#define SED_L0DISC_TPER_DESC (1 << 0)
#define SED_L0DISC_LOCKING_DESC (1 << 1)
#define SED_L0DISC_GEOMETRY_DESC (1 << 2)
#define SED_L0DISC_DATASTORE_DESC (1 << 3)
#define SED_L0DISC_OPALV100_DESC (1 << 4)
#define SED_L0DISC_OPALV200_DESC (1 << 5)
#define SED_L0DISC_RUBY_DESC (1 << 6)
#define SED_L0DISC_PYRITEV100_DESC (1 << 7)
#define SED_L0DISC_PYRITEV200_DESC (1 << 8)
#define SED_L0DISC_DATA_RM_DESC (1 << 9)
#define SED_L0DISC_BLOCKSID_DESC (1 << 10)
#define SED_L0DISC_SUM_DESC (1 << 11)
#define SED_L0DISC_CNL_DESC (1 << 12)

/* Level0 Tper Feature descriptor */
#define SED_L0DISC_TPER_FEAT_SYNC (1 << 0)
#define SED_L0DISC_TPER_FEAT_ASYNC (1 << 1)
#define SED_L0DISC_TPER_FEAT_ACK_NAK (1 << 2)
#define SED_L0DISC_TPER_FEAT_BUFFER_MGMT (1 << 3)
#define SED_L0DISC_TPER_FEAT_STREAMING (1 << 4)
#define SED_L0DISC_TPER_FEAT_COMID_MGMT (1 << 6)

/* Level0 Locking Feature descriptor */
#define SED_L0DISC_LOCKING_FEAT_SUPP (1 << 0)
#define SED_L0DISC_LOCKING_FEAT_LOCKING_EN (1 << 1)
#define SED_L0DISC_LOCKING_FEAT_LOCKED (1 << 2)
#define SED_L0DISC_LOCKING_FEAT_MEDIA_ENC (1 << 3)
#define SED_L0DISC_LOCKING_FEAT_MBR_EN (1 << 4)
#define SED_L0DISC_LOCKING_FEAT_MBR_DONE (1 << 5)

/* Level0 Geometry Reporting descriptor */
#define SED_L0DISC_GEOM_ALIGN (1 << 0)

/* Level0 Opalv200 and Ruby descriptor */
#define SED_L0DISC_OPALV200_RUBY_FEAT_RANGE_CROSS (1 << 0)

/* Level0 BlockSID descriptor */
#define SED_L0DISC_BLOCKSID_FEAT1_SID_VALUE (1 << 0)
#define SED_L0DISC_BLOCKSID_FEAT1_SID_AUTH_BLOCKED (1 << 1)
#define SED_L0DISC_BLOCKSID_FEAT2_HW_RESET (1 << 0)

/* Level0 Data removal mechanism descriptor */
#define SED_L0DISC_DATARM_FEAT_REMOVAL_OP (1 << 0)

/* Level0 Configurable Namespace Locking descriptor */
#define SED_L0DISC_CNL_FEAT_RANGEP (1 << 6)
#define SED_L0DISC_CNL_FEAT_RANGEC (1 << 7)

enum SED_ACCESS_TYPE {
	SED_RO_ACCESS = 1 << 0,
	SED_RW_ACCESS = 1 << 1,
	SED_NO_ACCESS = 1 << 2,
};

enum SED_AUTHORITY {
	SED_ADMIN1 = 0x0,
	SED_USER1 = 0x01,
	SED_USER2 = 0x02,
	SED_USER3 = 0x03,
	SED_USER4 = 0x04,
	SED_USER5 = 0x05,
	SED_USER6 = 0x06,
	SED_USER7 = 0x07,
	SED_USER8 = 0x08,
	SED_USER9 = 0x09,
	SED_SID = 0x0A,
	SED_PSID = 0x0B,
	SED_ANYBODY = 0xC,
};

enum sed_key_src {
	SED_KEY_FROMUSER = 0,	/* get key from user (stdio) */
};

struct sed_device;

struct sed_key_options {
	enum sed_key_src key_src;	/* how to get key */
	union {
		void *_unused;
	};
};

struct sed_geometry_supported_feat {
	uint32_t flags;
	uint32_t logical_blk_sz;
	uint64_t alignmnt_granlrty;
	uint64_t lowest_aligned_lba;
};

struct sed_datastr_table_supported_feat {
	uint16_t max_num_datastr_tbls;
	uint32_t max_total_size_datstr_tbls;
	uint32_t datastr_tbl_size_align;
};

struct sed_opalv100_supported_feat {
	uint16_t v1_base_comid;
	uint16_t v1_comid_num;
};

struct sed_opalv200_supported_feat {
	uint16_t base_comid;
	uint16_t comid_num;
	uint8_t flags;
	uint16_t admin_lp_auth_num;
	uint16_t user_lp_auth_num;
	uint8_t init_pin;
	uint8_t revert_pin;
};

struct sed_pyrite_supported_feat {
	uint16_t base_comid;
	uint16_t comid_num;
	uint8_t init_pin;
	uint8_t revert_pin;
};

struct sed_data_rm_mechanism_feat {
	uint8_t reserved;
	uint8_t flags;
	uint8_t supp_data_rm_mechanism;
	uint8_t time_formats;
	uint16_t data_rm_time[6];
};

struct sed_tper_properties {
	struct {
		char key_name[MAX_PROP_NAME_LEN];
		uint64_t value;
	} property[NUM_TPER_PROPS];
};

struct sed_blocksid_supported_feat {
	uint8_t flags1;
	uint8_t flags2;
};

struct sed_cnl_feat {
	uint8_t flags;
	uint32_t max_key_count;
	uint32_t unused_key_count;
	uint32_t max_ranges_per_ns;
};

struct sed_opal_level0_discovery {
	uint16_t com_id;
	/* this is a bit map containing info which descriptors are present*/
	uint64_t features;

	uint8_t tper_feat;
	uint8_t locking_feat;
	struct sed_geometry_supported_feat sed_geo;
	struct sed_datastr_table_supported_feat sed_datastr;
	struct sed_opalv100_supported_feat sed_opalv100;
	struct sed_opalv200_supported_feat sed_opalv200;
	struct sed_opalv200_supported_feat sed_ruby;
	struct sed_pyrite_supported_feat sed_pyritev100;
	struct sed_pyrite_supported_feat sed_pyritev200;
	struct sed_data_rm_mechanism_feat sed_data_rm_mechanism;
	struct sed_blocksid_supported_feat sed_blocksid;
	struct sed_cnl_feat sed_cnl;
};

struct sed_opal_device_discv {
	struct sed_opal_level0_discovery sed_lvl0_discv;
	struct sed_tper_properties sed_tper_props;
};

struct sed_key {
	uint8_t key[SED_MAX_KEY_LEN];
	uint8_t len;
	enum sed_key_src src;
	void *param;	/* depends on src */
};

struct sed_opal_lockingrange {
	size_t start;
	size_t length;
	uint8_t lr_id:4;
	uint8_t read_locked:1;
	uint8_t write_locked:1;
	uint8_t rle:1;
	uint8_t wle:1;
};

struct sed_opal_lockingranges {
	struct sed_opal_lockingrange lrs[SED_OPAL_MAX_LRS];
	uint8_t lr_num;
};

enum sed_status {
	SED_SUCCESS,
	SED_NOT_AUTHORIZED,
	SED_UNKNOWN_ERROR,
	SED_SP_BUSY,
	SED_SP_FAILED,
	SED_SP_DISABLED,
	SED_SP_FROZEN,
	SED_NO_SESSIONS_AVAILABLE,
	SED_UNIQUENESS_CONFLICT,
	SED_INSUFFICIENT_SPACE,
	SED_INSUFFICIENT_ROWS,
	SED_INVALID_FUNCTION,
	SED_INVALID_PARAMETER,
	SED_INVALID_REFERENCE,
	SED_UNKNOWN_ERROR_1,
	SED_TPER_MALFUNCTION,
	SED_TRANSACTION_FAILURE,
	SED_RESPONSE_OVERFLOW,
	SED_AUTHORITY_LOCKED_OUT,
	SED_FAIL = 0x3F, /* Fail status code as defined by Opal is higher value */
};

/**
 * This function initializes libsed for usage. It opens device node file and
 * stores relevant information in data structure representing libsed context.
 * Libsed context must be passed to other libsed functions for its proper
 * operation.
 */
int sed_init(struct sed_device **dev, const char *dev_path, bool pt);

/**
 *
 */
int sed_dev_discovery(struct sed_device *dev,
		      struct sed_opal_device_discv *discv);

/**
 *
 */
void sed_deinit(struct sed_device *dev);

/**
 * Calls the appropriate function based on key source.
 * Prepares 'key' for use in command handlers. May include
 * acquiring actual PEK value.
 */
int sed_get_pwd(struct sed_key_options *opts, enum SED_AUTHORITY auth,
		struct sed_key *key, bool confirm, bool old);

/**
 *
 */
int sed_key_init(struct sed_key *disk_key, const char *key, const uint8_t key_len);

/**
 *
 */
int sed_get_msid_pin(struct sed_device *dev, struct sed_key *msid_pin);

/**
 *
 */
int sed_takeownership(struct sed_device *dev, const struct sed_key *key);

/**
 *
 */
int sed_activatelsp(struct sed_device *dev, const struct sed_key *key);

/**
 *
 */
int sed_setup_global_range(struct sed_device *dev, const struct sed_key *key);

/**
 *
 */
int sed_lock_unlock(struct sed_device *dev, const struct sed_key *key, enum SED_ACCESS_TYPE lock_type);

/**
 *
 */
int sed_reverttper(struct sed_device *dev, const struct sed_key *key, bool psid, bool non_destructive);

/**
 * Revert Locking SP to its Original Factory State.
 *
 * @param dev			the device to operate on
 * @param key			the Admin1 password
 * @param keep_global_rn_key	if true then TPer shall continue to use the media
 * 				encryption key associated with the Global locking
 * 				range after the Locking SP transitions to the
 * 				“Manufactured-Inactive” state. Can be used in order
 * 				to skip data erasing when OPAL functionality is
 * 				reverted.
 *
 * @return OPAL_SUCCESS on success
 */
int sed_revertlsp(struct sed_device *dev, const struct sed_key *key, bool keep_global_rn_key);

/**
 *
 */
int sed_setpw(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key);

/**
 * Get list of locking ranges.
 * @param dev			the device to operate on
 * @param key   		the Admin1 password
 * @param lrs			array of discovered locking ranges
 *
 * @return OPAL_SUCCESS on success
 */
int sed_list_lr(struct sed_device *dev, const struct sed_key *key,
                struct sed_opal_lockingranges *lrs);

/**
 *
 */
int sed_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key);

/**
 *
 */
int sed_ds_read(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, uint8_t *to, uint32_t size,
		uint32_t offset);

/**
 *
 */
int sed_ds_write(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, const void *from, uint32_t size,
		uint32_t offset);

/**
 *
 */
int sed_shadowmbr(struct sed_device *dev, const struct sed_key *key, bool mbr);

/**
 *
 */
int sed_mbrdone(struct sed_device *dev, const struct sed_key *key, bool mbr);

/**
 *
 */
int sed_write_shadow_mbr(struct sed_device *dev, const struct sed_key *key,
			  const uint8_t *from, uint32_t size, uint32_t offset);


/**
 *
 */
int sed_issue_blocksid_cmd(struct sed_device *dev, bool hw_reset);

/**
 *
 */
int sed_stack_reset_cmd(struct sed_device *dev);

/**
 *
 */
const char *sed_error_text(int sed_status);


#endif /* _LIBSED_H_ */
