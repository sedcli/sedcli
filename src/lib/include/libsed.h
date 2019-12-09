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

enum SED_ACCESS_TYPE {
	SED_RO_ACCESS = 1 << 0,
	SED_RW_ACCESS = 1 << 1,
	SED_NO_ACCESS = 1 << 2,
};

struct sed_device;

struct sed_tper_supported_feat {
	uint8_t sync_supp :1;
	uint8_t async_supp :1;
	uint8_t ack_nak_supp :1;
	uint8_t buff_mgmt_supp :1;
	uint8_t stream_supp :1;
	uint8_t reserved1 :1;
	uint8_t comid_mgmt_supp :1;
	uint8_t reserved2:1;
} __attribute__((__packed__));

struct sed_locking_supported_feat {
	uint8_t locking_supp:1;
	uint8_t locking_en:1;
	uint8_t locked:1;
	uint8_t media_enc:1;
	uint8_t mbr_en:1;
	uint8_t mbr_done:1;
	uint8_t reserved:2;
} __attribute__((__packed__));

struct sed_opalv200_supported_feat {
	uint16_t base_comid;
	uint16_t comid_num;
	uint8_t reserved1;
	uint16_t admin_lp_auth_num;
	uint16_t user_lp_auth_num;
	uint8_t reserved2[7];
} __attribute__((__packed__));

struct sed_opal_level0_discovery {
	struct sed_tper_supported_feat sed_tper;
	struct sed_locking_supported_feat sed_locking;
	struct sed_opalv200_supported_feat sed_opalv200;
};

struct sed_key {
	uint8_t key[SED_MAX_KEY_LEN];
	uint8_t len;
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
int sed_init(struct sed_device **dev, const char *dev_path);

/**
 *
 */
int sed_level0_discovery(struct sed_opal_level0_discovery *discv);

/**
 *
 */
void sed_deinit(struct sed_device *dev);

/**
 *
 */
int sed_key_init(struct sed_key *disk_key, const char *key, const uint8_t key_len);

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
int sed_reverttper(struct sed_device *dev, const struct sed_key *key, bool psid);

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
int sed_setpw(struct sed_device *dev, const struct sed_key *old_key,
		const struct sed_key *new_key);

/**
 *
 */
const char *sed_error_text(int sed_status);


#endif /* _LIBSED_H_ */
