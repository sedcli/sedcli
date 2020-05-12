/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _NVME_PT_IOCTL_H
#define _NVME_PT_IOCTL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>
#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libsed.h>

#include "sed_util.h"

#define GENERIC_HOST_SESSION_NUM 0x41

/*
 * TSM SHALL NOT assign any TSN in the range 0 to 4095 to a regular session.
 * These TSNs are reserved by TCG for special sessions
 */
#define RSVD_TPER_SESSION_NUM	(4096)

#define OPAL_SUCCESS (0)

#define MAX_FEATURES 64

#define DTAERROR_NO_METHOD_STATUS 0x89

#define TPER_SYNC_SUPPORTED 0x01
#define MBR_ENABLED_MASK 0x10

/* Derived from TCG Core spec 2.01 Section:
 * 3.2.2.1
 * Data Type
 */
#define TINY_ATOM_BYTE   0x7F
#define SHORT_ATOM_BYTE  0xBF
#define MEDIUM_ATOM_BYTE 0xDF
#define LONG_ATOM_BYTE   0xE3

/*
 * User IDs used in the TCG storage SSCs
 * Derived from: TCG_Storage_Architecture_Core_Spec_v2.01_r1.00
 * Section: 6.3 Assigned UIDs
 */
#define OPAL_UID_LENGTH 8
#define OPAL_METHOD_LENGTH 8
#define OPAL_MSID_KEYLEN 15
#define OPAL_UID_LENGTH_HALF 4

#define OPAL_INVAL_PARAM 12
#define OPAL_MANUFACTURED_INACTIVE 0x08
#define LOCKING_RANGE_NON_GLOBAL 0x03

#define FC_TPER       0x0001
#define FC_LOCKING    0x0002
#define FC_GEOMETRY   0x0003
#define FC_ENTERPRISE 0x0100
#define FC_DATASTORE  0x0202
#define FC_SINGLEUSER 0x0201
#define FC_OPALV100   0x0200
#define FC_OPALV200   0x0203

#define KEEP_GLOBAL_RANGE_KEY (0x060000)

enum {
	TCG_SECP_00 = 0,
	TCG_SECP_01,
};

enum opaluid {
	/* users uid */
	OPAL_SM_UID,
	OPAL_THISSP_UID,
	OPAL_ADMIN_SP_UID,
	OPAL_LOCKING_SP_UID,
	OPAL_ENTERPRISE_LOCKING_SP_UID,
	OPAL_ANYBODY_UID,
	OPAL_SID_UID,
	OPAL_ADMIN1_UID,
	OPAL_USER1_UID,
	OPAL_USER2_UID,
	OPAL_PSID_UID,
	OPAL_ENTERPRISE_BANDMASTER0_UID,
	OPAL_ENTERPRISE_ERASEMASTER_UID,

	/* tables uid */
	OPAL_TABLE_TABLE_UID,
	OPAL_LOCKINGRANGE_GLOBAL_UID,
	OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID,
	OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID,
	OPAL_MBRCONTROL_UID,
	OPAL_MBR_UID,
	OPAL_AUTHORITY_TABLE_UID,
	OPAL_C_PIN_TABLE_UID,
	OPAL_LOCKING_INFO_TABLE_UID,
	OPAL_ENTERPRISE_LOCKING_INFO_TABLE_UID,
	OPAL_DATASTORE_UID,

	/* c_pin_table objects UID's */
	OPAL_C_PIN_MSID_UID,
	OPAL_C_PIN_SID_UID,
	OPAL_C_PIN_ADMIN1_UID,

	/* half UID's (only the first four bytes used) */
	OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID,
	OPAL_HALF_UID_BOOLEAN_ACE_UID,

	/* ACE DS UIDs */
	OPAL_ACE_DS_GET_ALL_UID,
	OPAL_ACE_DS_SET_ALL_UID,

	/* optional parameter UID */
	OPAL_UID_HEXFF_UID,
};

enum opalmethod {
	OPAL_PROPERTIES_METHOD_UID,
	OPAL_STARTSESSION_METHOD_UID,
	OPAL_REVERT_METHOD_UID,
	OPAL_ACTIVATE_METHOD_UID,
	OPAL_EGET_METHOD_UID,
	OPAL_ESET_METHOD_UID,
	OPAL_NEXT_METHOD_UID,
	OPAL_EAUTHENTICATE_METHOD_UID,
	OPAL_GETACL_METHOD_UID,
	OPAL_GENKEY_METHOD_UID,
	OPAL_REVERTSP_METHOD_UID,
	OPAL_GET_METHOD_UID,
	OPAL_SET_METHOD_UID,
	OPAL_AUTHENTICATE_METHOD_UID,
	OPAL_RANDOM_METHOD_UID,
	OPAL_ERASE_METHOD_UID,
};

enum opaltoken {
	/* Boolean */
	OPAL_TRUE = 0x01,
	OPAL_FALSE = 0x00,
	OPAL_BOOLEAN_EXPR = 0x03,
	/* cellblocks */
	OPAL_TABLE = 0x00,
	OPAL_STARTROW = 0x01,
	OPAL_ENDROW = 0x02,
	OPAL_STARTCOLUMN = 0x03,
	OPAL_ENDCOLUMN = 0x04,
	OPAL_VALUES = 0x01,
	/* opal tables */
	OPAL_TABLE_ROW = 0x07,
	/* authority table */
	OPAL_PIN = 0x03,
	/* locking tokens */
	OPAL_RANGESTART = 0x03,
	OPAL_RANGELENGTH = 0x04,
	OPAL_READLOCKENABLED = 0x05,
	OPAL_WRITELOCKENABLED = 0x06,
	OPAL_READLOCKED = 0x07,
	OPAL_WRITELOCKED = 0x08,
	OPAL_ACTIVEKEY = 0x0A,
	/* lockingsp table */
	OPAL_LIFECYCLE = 0x06,
	/* locking info table */
	OPAL_MAXRANGES = 0x04,
	/* mbr control */
	OPAL_MBRENABLE = 0x01,
	OPAL_MBRDONE = 0x02,
	/* properties */
	OPAL_HOSTPROPERTIES = 0x00,
	/* atoms */
	OPAL_STARTLIST = 0xf0,
	OPAL_ENDLIST = 0xf1,
	OPAL_STARTNAME = 0xf2,
	OPAL_ENDNAME = 0xf3,
	OPAL_CALL = 0xf8,
	OPAL_ENDOFDATA = 0xf9,
	OPAL_ENDOFSESSION = 0xfa,
	OPAL_STARTTRANSACTON = 0xfb,
	OPAL_ENDTRANSACTON = 0xfC,
	OPAL_EMPTYATOM = 0xff,
	OPAL_WHERE = 0x00,
};

struct tper_supported_feat {
	uint8_t sync_supp :1;
	uint8_t async_supp :1;
	uint8_t ack_nak_supp :1;
	uint8_t buff_mgmt_supp :1;
	uint8_t stream_supp :1;
	uint8_t reserved1 :1;
	uint8_t comid_mgmt_supp :1;
	uint8_t reserved2:1;
} __attribute__((__packed__));

struct locking_supported_feat {
	uint8_t locking_supp:1;
	uint8_t locking_en:1;
	uint8_t locked:1;
	uint8_t media_enc:1;
	uint8_t mbr_en:1;
	uint8_t mbr_done:1;
	uint8_t reserved:2;
} __attribute__((__packed__));

struct geometry_supported_feat {
	struct {
		uint8_t align:1;
		uint8_t rsvd1:7;
	} __attribute__((__packed__)) rsvd_align;
	uint8_t rsvd2[7];
	uint32_t logical_blk_sz;
	uint64_t alignmnt_granlrty;
	uint64_t lowest_aligned_lba;
} __attribute__((__packed__));

struct datastr_table_supported_feat {
	uint16_t max_num_datastr_tbls;
	uint32_t max_total_size_datstr_tbls;
	uint32_t datastr_tbl_size_align;
} __attribute__((__packed__));

struct opalv100_supported_feat {
	uint16_t v1_base_comid;
	uint16_t v1_comid_num;
} __attribute__((__packed__));

struct opalv200_supported_feat {
	uint16_t base_comid;
	uint16_t comid_num;
	struct {
		uint8_t range_crossing:1;
		uint8_t rsvd1:7;
	} __attribute__((__packed__)) rangecross_rsvd;
	uint16_t admin_lp_auth_num;
	uint16_t user_lp_auth_num;
	uint8_t init_pin;
	uint8_t revert_pin;
	uint8_t reserved2[5];
} __attribute__((__packed__));

struct opal_l0_feat {
	int type;
	union {
		struct {
			struct tper_supported_feat flags;
		} tper;

		struct{
			struct locking_supported_feat flags;
		} locking;

		struct geometry_supported_feat geo;

		struct datastr_table_supported_feat datastr;

		struct opalv100_supported_feat opalv100;

		struct opalv200_supported_feat opalv200;
	} feat;
};

struct opal_l0_disc {
	int feats_size;
	uint32_t rev;
	uint16_t comid;
	struct opal_l0_feat feats[MAX_FEATURES];
} __attribute__((__packed__));

struct opal_level0_header {
	uint32_t len;
	uint32_t rev;
	uint64_t reserved;
	uint8_t vendor_specific[32];
} __attribute__((__packed__)) ;

struct opal_level0_feat_desc {
	uint16_t code;
	uint8_t reserved :4;
	uint8_t rev :4;
	uint8_t len;
	union {
		struct {
			struct tper_supported_feat flags;
			uint8_t reserved[11];
		} __attribute__((__packed__)) tper;

		struct {
			struct locking_supported_feat flags;
			uint8_t reserved[11];
		} __attribute__((__packed__)) locking;

		struct {
			uint8_t reserved[2];
			struct datastr_table_supported_feat datastr_tbl;
		} datastr;

		struct geometry_supported_feat geo;

		struct opalv100_supported_feat opalv100;

		struct opalv200_supported_feat opalv200;
	} feat;
} __attribute__((__packed__)) ;

struct opal_compacket {
	uint32_t reserved;
	uint8_t ext_comid[4];
	uint32_t outstanding_data;
	uint32_t min_transfer;
	uint32_t length;
} __attribute__((__packed__));

struct opal_packet {
	struct {
		uint32_t tsn;
		uint32_t hsn;
	} __attribute__((__packed__)) session;
	uint32_t seq_num;
	uint16_t reserved;
	uint16_t ack_type;
	uint32_t ack;
	uint32_t length;
} __attribute__((__packed__));

struct opal_subpacket {
	uint8_t reserved[6];
	uint16_t kind;
	uint32_t length;
} __attribute__((__packed__));

struct opal_header {
	struct opal_compacket compacket;
	struct opal_packet packet;
	struct opal_subpacket subpacket;
	uint8_t payload[];
} __attribute__((__packed__));

struct opal_level0_discovery {
	struct tper_supported_feat tper;
	struct locking_supported_feat locking;
	struct geometry_supported_feat geo;
	struct datastr_table_supported_feat datastr;
	struct opalv100_supported_feat opalv100;
	struct opalv200_supported_feat opalv200;
};

int opal_init_pt(struct sed_device *dev,
		const char *device_path);

void opal_level0_discv_info_pt(struct sed_opal_level0_discovery *discvry);

int opal_takeownership_pt(struct sed_device *dev, const struct sed_key *key);

int opal_get_msid_pin_pt(struct sed_device *dev, struct sed_key *msid_pin);

int opal_reverttper_pt(struct sed_device *dev, const struct sed_key *key, bool psid);

int opal_revertlsp_pt(struct sed_device *dev, const struct sed_key *key,
		bool keep_global_rn_key);

int opal_activate_lsp_pt(struct sed_device *dev, const struct sed_key *key,
		char *lr_str, bool sum);

int opal_add_usr_to_lr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *usr, enum SED_ACCESS_TYPE lock_type, uint8_t lr);

int opal_activate_usr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *user);

int opal_setup_global_range_pt(struct sed_device *dev, const struct sed_key *key);

int opal_setuplr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *user, uint8_t lr, size_t range_start,
		size_t range_length, bool sum, bool RLE, bool WLE);

int opal_lock_unlock_pt(struct sed_device *dev, const struct sed_key *key,
		enum SED_ACCESS_TYPE lock_type);

int opal_set_pwd_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key);

int opal_mbr_done_pt(struct sed_device *dev, const struct sed_key *key,
		bool mbr_done);

int opal_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key,
		bool mbr);

int opal_write_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key,
			const uint8_t *from, uint32_t size, uint32_t offset);

int opal_eraselr_pt(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user, const uint8_t lr, bool sum);

int opal_rw_datastr_tbl(struct sed_device *dev, const char *password,
			uint8_t key_len, const uint64_t data, uint64_t size,
			uint64_t offset, bool flags);

int opal_ds_read(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, uint8_t *to, uint32_t size, uint32_t offset);

int opal_ds_write(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, const uint8_t *from, uint32_t size, uint32_t offset);

int opal_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key);

int opal_list_lr_pt(struct sed_device *dev, const struct sed_key *key,
		    struct sed_opal_lockingranges *lrs);

void opal_deinit_pt(struct sed_device *dev);

#endif /* _NVME_PT_IOCTL_H */

