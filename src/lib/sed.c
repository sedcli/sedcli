/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <libsed.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <linux/version.h>
#include <sys/ioctl.h>

#include "nvme_pt_ioctl.h"
#include "sed_ioctl.h"
#include "sed_util.h"
#include "sedcli_log.h"

#define OPAL_FEAT_TPER       0x0001
#define OPAL_FEAT_LOCKING    0x0002
#define OPAL_FEAT_GEOMETRY   0x0003
#define OPAL_FEAT_DATASTORE  0x0202
#define OPAL_FEAT_SUM        0x0201
#define OPAL_FEAT_OPALV100   0x0200
#define OPAL_FEAT_OPALV200   0x0203
#define OPAL_FEAT_PYRITEV100 0x0302
#define OPAL_FEAT_PYRITEV200 0x0303
#define OPAL_FEAT_RUBY       0x0304
#define OPAL_FEAT_BLOCKSID   0x0402
#define OPAL_FEAT_CNL        0x0403
#define OPAL_FEAT_DATA_RM    0x0404

#define ARRAY_SIZE(x) ((size_t)(sizeof(x) / sizeof(x[0])))
#define NVME_DEV_PREFIX "nvme"

typedef int (*init)(struct sed_device *, const char *);
typedef int (*dev_discv) (struct sed_device *, struct sed_opal_device_discv *);
typedef int (*take_ownership)(struct sed_device *, const struct sed_key *);
typedef int (*get_msid_pin)(struct sed_device *, struct sed_key *);
typedef int (*reverttper)(struct sed_device *, const struct sed_key *, bool, bool);
typedef int (*activate_lsp)(struct sed_device *, const struct sed_key *,
			char *, bool);
typedef int (*revertsp)(struct sed_device *, const struct sed_key *, bool);
typedef int (*setup_global_range)(struct sed_device *, const struct sed_key *);
typedef int (*add_usr_to_lr)(struct sed_device *, const struct sed_key *,
			const char *, enum SED_ACCESS_TYPE, uint8_t);
typedef int (*activate_usr)(struct sed_device *, const struct sed_key *,
			const char *);
typedef int (*setuplr)(struct sed_device *, const struct sed_key *,
			const char *, uint8_t, size_t, size_t, bool,
			bool, bool);
typedef int (*lock_unlock)(struct sed_device *, const struct sed_key *, enum SED_ACCESS_TYPE);
typedef int (*set_pwd)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, const struct sed_key *);
typedef int (*shadow_mbr)(struct sed_device *, const struct sed_key *, bool);
typedef int (*mbr_done) (struct sed_device *, const struct sed_key *, bool);
typedef int (*write_shadow_mbr)(struct sed_device *, const struct sed_key *,
				const uint8_t *, uint32_t, uint32_t);
typedef int (*eraselr)(struct sed_device *, const struct sed_key *,
			const char *, uint8_t , bool);
typedef int (*ds_add_anybody_get)(struct sed_device *, const struct sed_key *);
typedef int (*ds_read)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, uint8_t *, uint32_t, uint32_t);
typedef int (*ds_write)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, const uint8_t *, uint32_t, uint32_t);
typedef int (*list_lr)(struct sed_device *, const struct sed_key *,
		       struct sed_opal_lockingranges *);
typedef int (*blocksid)(struct sed_device *, bool);
typedef int (*stack_reset)(struct sed_device *);
typedef void (*deinit)(struct sed_device *);
typedef int (*get_pwd)(struct sed_key_options *, enum SED_AUTHORITY, struct sed_key *, bool, bool);

struct opal_interface {
	init init_fn;
	dev_discv dev_discv_fn;
	take_ownership ownership_fn;
	get_msid_pin get_msid_pin_fn;
	reverttper revert_fn;
	revertsp revertsp_fn;	/* (i.e. revertlsp_fn) no cli option */
	activate_lsp activatelsp_fn;
	setup_global_range setup_global_range_fn;
	add_usr_to_lr addusr_to_lr_fn;
	activate_usr activate_usr_fn;
	setuplr setuplr_fn;
	lock_unlock lock_unlock_fn;
	set_pwd set_pwd_fn;
	shadow_mbr shadow_mbr_fn;
	write_shadow_mbr write_shadow_mbr_fn;
	mbr_done mbr_done_fn;
	eraselr eraselr_fn;
	ds_add_anybody_get ds_add_anybody_get_fn;
	ds_read ds_read_fn;
	ds_write ds_write_fn;
	list_lr list_lr_fn;
	blocksid blocksid_fn;
	stack_reset stack_reset_fn;
	deinit deinit_fn;
	get_pwd getpwd_fn;
};

#ifdef CONFIG_OPAL_DRIVER
static struct opal_interface opal_if = {
	.init_fn = sedopal_init,
	.dev_discv_fn = sedopal_dev_discv_info,
	.ownership_fn = sedopal_takeownership,
	.get_msid_pin_fn = NULL,
	.revert_fn = sedopal_reverttper,
	.activatelsp_fn = sedopal_activatelsp,
	.revertsp_fn = sedopal_revertlsp,	/* no cli option */
	.setup_global_range_fn = sedopal_setup_global_range,
	.addusr_to_lr_fn = sedopal_add_usr_to_lr,
	.activate_usr_fn = sedopal_enable_user,
	.setuplr_fn = sedopal_setuplr,
	.lock_unlock_fn = sedopal_lock_unlock,
	.set_pwd_fn = sedopal_setpw,
	.shadow_mbr_fn = sedopal_shadowmbr,
	.mbr_done_fn = sedopal_mbrdone,
	.write_shadow_mbr_fn = sedopal_write_shadow_mbr,
	.eraselr_fn = sedopal_erase_lr,
	.ds_add_anybody_get_fn = NULL,
	.ds_read_fn = NULL,
	.ds_write_fn = NULL,
	.list_lr_fn = NULL,
	.blocksid_fn = NULL,
	.stack_reset_fn = NULL,
	.deinit_fn = sedopal_deinit,
	.getpwd_fn = sedopal_getpwd,
};
#endif

static struct opal_interface nvmept_if = {
	.init_fn	= opal_init_pt,
	.dev_discv_fn	= opal_dev_discv_info_pt,
	.ownership_fn	= opal_takeownership_pt,
	.get_msid_pin_fn = opal_get_msid_pin_pt,
	.revert_fn	= opal_reverttper_pt,
	.activatelsp_fn	= opal_activate_lsp_pt,
	.revertsp_fn	= opal_revertlsp_pt,	/* no cli option */
	.setup_global_range_fn = opal_setup_global_range_pt,
	.addusr_to_lr_fn= opal_add_usr_to_lr_pt,
	.activate_usr_fn= opal_activate_usr_pt,
	.setuplr_fn	= opal_setuplr_pt,
	.lock_unlock_fn	= opal_lock_unlock_pt,
	.set_pwd_fn = opal_set_pwd_pt,
	.shadow_mbr_fn	= opal_shadow_mbr_pt,
	.write_shadow_mbr_fn = opal_write_shadow_mbr_pt,
	.mbr_done_fn = opal_mbr_done_pt,
	.eraselr_fn	= opal_eraselr_pt,
	.ds_add_anybody_get_fn = opal_ds_add_anybody_get,
	.ds_read_fn = opal_ds_read,
	.ds_write_fn = opal_ds_write,
	.list_lr_fn	= opal_list_lr_pt,
	.blocksid_fn	= opal_block_sid_pt,
	.stack_reset_fn	= opal_stack_reset_pt,
	.deinit_fn	= opal_deinit_pt,
	.getpwd_fn	= NULL,
};

static struct opal_interface *curr_if = &nvmept_if;

static const char *sed_statuses[] = {
	[SED_SUCCESS] = "Success",
	[SED_NOT_AUTHORIZED] = "Not Authorized",
	[SED_UNKNOWN_ERROR] = "Unknown Error",
	[SED_SP_BUSY] = "SP Busy",
	[SED_SP_FAILED] = "SP Failed",
	[SED_SP_DISABLED] = "SP Disabled",
	[SED_SP_FROZEN] = "SP Frozen",
	[SED_NO_SESSIONS_AVAILABLE] = "No Sessions Available",
	[SED_UNIQUENESS_CONFLICT] = "Uniqueness Conflict",
	[SED_INSUFFICIENT_SPACE] = "Insufficient Space",
	[SED_INSUFFICIENT_ROWS] = "Insufficient Rows",
	[SED_INVALID_FUNCTION] = "Invalid Function",
	[SED_INVALID_PARAMETER] = "Invalid Parameter",
	[SED_INVALID_REFERENCE] = "Invalid Reference",
	[SED_UNKNOWN_ERROR_1] = "Unknown Error",
	[SED_TPER_MALFUNCTION] = "TPER Malfunction",
	[SED_TRANSACTION_FAILURE] = "Transaction Failure",
	[SED_RESPONSE_OVERFLOW] = "Response Overflow",
	[SED_AUTHORITY_LOCKED_OUT] = "Authority Locked Out",
	[SED_FAIL] = "Failed",
};

static void copy_tper_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->tper_feat = feat->feat.tper.flags;

	discv->features |= SED_L0DISC_TPER_DESC;
}

static void copy_locking_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->locking_feat = feat->feat.locking.flags;

	discv->features |= SED_L0DISC_LOCKING_DESC;
}

static void copy_geometry_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_geo.flags = feat->feat.geo.flags;
	discv->sed_geo.alignmnt_granlrty = be64toh(feat->feat.geo.alignmnt_granlrty);
	discv->sed_geo.logical_blk_sz = be32toh(feat->feat.geo.logical_blk_sz);
	discv->sed_geo.lowest_aligned_lba = be64toh(feat->feat.geo.lowest_aligned_lba);

	discv->features |= SED_L0DISC_GEOMETRY_DESC;
}

static void copy_datastr_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_datastr.datastr_tbl_size_align = be32toh(feat->feat.datastr.datastr_tbl.datastr_tbl_size_align);
	discv->sed_datastr.max_num_datastr_tbls = be16toh(feat->feat.datastr.datastr_tbl.max_num_datastr_tbls);
	discv->sed_datastr.max_total_size_datstr_tbls = be32toh(feat->feat.datastr.datastr_tbl.max_total_size_datstr_tbls);

	discv->features |= SED_L0DISC_DATASTORE_DESC;
}

static void copy_sum_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->features |= SED_L0DISC_SUM_DESC;
}

static void copy_opalv100_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_opalv100.v1_base_comid = be16toh(feat->feat.opalv100.v1_base_comid);
	discv->sed_opalv100.v1_comid_num = be16toh(feat->feat.opalv100.v1_comid_num);

	discv->features |= SED_L0DISC_OPALV100_DESC;
}

static void copy_opalv200_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_opalv200.base_comid = be16toh(feat->feat.opalv200.base_comid);
	discv->sed_opalv200.comid_num = be16toh(feat->feat.opalv200.comid_num);
	discv->sed_opalv200.admin_lp_auth_num = be16toh(feat->feat.opalv200.admin_lp_auth_num);
	discv->sed_opalv200.user_lp_auth_num = be16toh(feat->feat.opalv200.user_lp_auth_num);
	discv->sed_opalv200.init_pin = feat->feat.opalv200.init_pin;
	discv->sed_opalv200.revert_pin = feat->feat.opalv200.revert_pin;
	discv->sed_opalv200.flags = feat->feat.opalv200.flags;

	discv->com_id = discv->sed_opalv200.base_comid;
	discv->features |= SED_L0DISC_OPALV200_DESC;
}

static void copy_pyritev100_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_pyritev100.base_comid = be16toh(feat->feat.pyritev100.base_comid);
	discv->sed_pyritev100.comid_num = be16toh(feat->feat.pyritev100.comid_num);
	discv->sed_pyritev100.init_pin = feat->feat.pyritev100.init_pin;
	discv->sed_pyritev100.revert_pin = feat->feat.pyritev100.revert_pin;

	discv->com_id = discv->sed_pyritev100.base_comid;
	discv->features |= SED_L0DISC_PYRITEV100_DESC;
}

static void copy_pyritev200_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_pyritev200.base_comid = be16toh(feat->feat.pyritev200.base_comid);
	discv->sed_pyritev200.comid_num = be16toh(feat->feat.pyritev200.comid_num);
	discv->sed_pyritev200.init_pin = feat->feat.pyritev200.init_pin;
	discv->sed_pyritev200.revert_pin = feat->feat.pyritev200.revert_pin;

	discv->com_id = discv->sed_pyritev200.base_comid;
	discv->features |= SED_L0DISC_PYRITEV200_DESC;
}

static void copy_ruby_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_ruby.base_comid = be16toh(feat->feat.ruby.base_comid);
	discv->sed_ruby.comid_num = be16toh(feat->feat.ruby.comid_num);
	discv->sed_ruby.admin_lp_auth_num = be16toh(feat->feat.ruby.admin_lp_auth_num);
	discv->sed_ruby.user_lp_auth_num = be16toh(feat->feat.ruby.user_lp_auth_num);
	discv->sed_ruby.init_pin = feat->feat.ruby.init_pin;
	discv->sed_ruby.revert_pin = feat->feat.ruby.revert_pin;
	discv->sed_ruby.flags = feat->feat.ruby.flags;

	discv->com_id = be16toh(feat->feat.ruby.base_comid);
	discv->features |= SED_L0DISC_RUBY_DESC;
}

static void copy_blocksid_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_blocksid.flags1 = feat->feat.blocksid.flags1;
	discv->sed_blocksid.flags2 = feat->feat.blocksid.flags2;

	discv->features |= SED_L0DISC_BLOCKSID_DESC;
}

static void copy_data_rm_mechanism_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	int i = 0;

	discv->sed_data_rm_mechanism.flags = feat->feat.data_rm_mechanism.flags;
	discv->sed_data_rm_mechanism.supp_data_rm_mechanism = feat->feat.data_rm_mechanism.supp_data_rm_mechanism;
	discv->sed_data_rm_mechanism.time_formats = feat->feat.data_rm_mechanism.time_formats;

	for (i = 0; i < 6; i++) {
		discv->sed_data_rm_mechanism.data_rm_time[i] = feat->feat.data_rm_mechanism.data_rm_time[i];
	}

	discv->features |= SED_L0DISC_DATA_RM_DESC;
}

static void copy_cnl_feat(struct sed_opal_level0_discovery *discv,
		struct opal_level0_feat_desc *feat)
{
	discv->sed_cnl.flags = feat->feat.cnl.flags;
	discv->sed_cnl.max_key_count = be32toh(feat->feat.cnl.max_key_count);
	discv->sed_cnl.max_ranges_per_ns = be32toh(feat->feat.cnl.max_ranges_per_ns);
	discv->sed_cnl.unused_key_count = be32toh(feat->feat.cnl.unused_key_count);

	discv->features |= SED_L0DISC_CNL_DESC;
}

typedef void (*copy)(struct sed_opal_level0_discovery *, struct opal_level0_feat_desc *);

struct opal_disc_copy_fn {
	int feat_code;
	copy copy_fn;
};

static struct opal_disc_copy_fn opal_disc_copy_fns[] = {
	{.feat_code = OPAL_FEAT_TPER, .copy_fn = copy_tper_feat},
	{.feat_code = OPAL_FEAT_LOCKING, .copy_fn = copy_locking_feat},
	{.feat_code = OPAL_FEAT_GEOMETRY, .copy_fn = copy_geometry_feat},
	{.feat_code = OPAL_FEAT_DATASTORE, .copy_fn = copy_datastr_feat},
	{.feat_code = OPAL_FEAT_SUM, .copy_fn = copy_sum_feat},
	{.feat_code = OPAL_FEAT_OPALV100, .copy_fn = copy_opalv100_feat},
	{.feat_code = OPAL_FEAT_OPALV200, .copy_fn = copy_opalv200_feat},
	{.feat_code = OPAL_FEAT_PYRITEV100, .copy_fn = copy_pyritev100_feat},
	{.feat_code = OPAL_FEAT_PYRITEV200, .copy_fn = copy_pyritev200_feat},
	{.feat_code = OPAL_FEAT_RUBY, .copy_fn = copy_ruby_feat},
	{.feat_code = OPAL_FEAT_BLOCKSID, .copy_fn = copy_blocksid_feat},
	{.feat_code = OPAL_FEAT_DATA_RM, .copy_fn = copy_data_rm_mechanism_feat},
	{.feat_code = OPAL_FEAT_CNL, .copy_fn = copy_cnl_feat},
};

static copy opal_get_copy_fn(int feat_code)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(opal_disc_copy_fns); i++) {
		if (opal_disc_copy_fns[i].feat_code == feat_code) {
			return opal_disc_copy_fns[i].copy_fn;
		}
	}

	return NULL;
}

int sed_get_discv(struct sed_opal_level0_discovery *discv, uint8_t *buffer)
{
	struct opal_level0_header *header;
	struct opal_level0_feat_desc *desc;
	copy copy_fn;
	int pos, end, feat_no;
	uint16_t feat_code;

	header = (struct opal_level0_header *) buffer;

	/* processing level 0 features */
	pos = 0;
	feat_no = 0;
	pos += sizeof(*header);
	end = be32toh(header->len);

	while (pos < end) {
		desc = (struct opal_level0_feat_desc *) (buffer + pos);
		feat_code = be16toh(desc->code);

		pos += desc->len + 4;

		copy_fn = opal_get_copy_fn(feat_code);

		if (copy_fn != NULL) {
			copy_fn(discv, desc);
			feat_no++;
		}

	}

	return 0;
}

int sed_init(struct sed_device **dev, const char *dev_path, bool pt)
{
	int status = 0;
	struct sed_device *ret;
	char *base;

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return -ENOMEM;
	}

	memset(ret, 0, sizeof(*ret));

	base = basename(dev_path);
#ifdef CONFIG_OPAL_DRIVER
	if (!pt) {
		curr_if = &opal_if;
	} else if (strncmp(base, NVME_DEV_PREFIX, strnlen(NVME_DEV_PREFIX, PATH_MAX))) {
		SEDCLI_DEBUG_PARAM("%s is not an NVMe device and function not supported by driver!\n", dev_path);
		return -EOPNOTSUPP;
	}
#else
	if (strncmp(base, NVME_DEV_PREFIX, strnlen(NVME_DEV_PREFIX, PATH_MAX))) {
		SEDCLI_DEBUG_PARAM("%s is not an NVMe device and opal-driver not built-in!\n", dev_path);
		return -EOPNOTSUPP;
	}
#endif

	status = curr_if->init_fn(ret, dev_path);
	if (status != 0) {
		sed_deinit(ret);

		return status;
	}

	*dev = ret;
	return status;
}

int sed_dev_discovery(struct sed_device *dev,
			 struct sed_opal_device_discv *discv)
{
	if (curr_if->dev_discv_fn == NULL)
		return -EINVAL;	/* EOPNOTSUPP means something else here */

	return curr_if->dev_discv_fn(dev, discv);
}

void sed_deinit(struct sed_device *dev)
{
	if (dev != NULL) {
		curr_if->deinit_fn(dev);
		memset(dev, 0, sizeof(*dev));
		free(dev);
	}
}

int sed_get_pwd(struct sed_key_options *opts, enum SED_AUTHORITY auth,
		struct sed_key *key, bool confirm, bool old)
{
	if (curr_if->getpwd_fn == NULL) {
		SEDCLI_DEBUG_MSG("Key source not supported on interface.\n");
		return -EOPNOTSUPP;
	}
	return curr_if->getpwd_fn(opts, auth, key, confirm, old);
}

int sed_key_init(struct sed_key *auth_key, const char *key, const uint8_t key_len)
{
	uint8_t src_len = key_len;
	uint8_t dest_len = SED_MAX_KEY_LEN;

	if (src_len == 0) {
		return -EINVAL;
	}

	if (src_len > dest_len) {
		SEDCLI_DEBUG_MSG("Key length exceeds the destination size.\n");
		return -ERANGE;
	}

	memcpy(auth_key->key, key, src_len);

	auth_key->len = key_len;

	return 0;
}

int sed_takeownership(struct sed_device *dev, const struct sed_key *key)
{
	return curr_if->ownership_fn(dev, key);
}

int sed_get_msid_pin(struct sed_device *dev, struct sed_key *msid_pin)
{
	if (curr_if->get_msid_pin_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->get_msid_pin_fn(dev, msid_pin);
}

int sed_setup_global_range(struct sed_device *dev, const struct sed_key *key)
{
	return curr_if->setup_global_range_fn(dev, key);
}

int sed_reverttper(struct sed_device *dev, const struct sed_key *key, bool psid, bool non_destructive)
{
	return curr_if->revert_fn(dev, key, psid, non_destructive);
}

int sed_revertlsp(struct sed_device *dev, const struct sed_key *key, bool keep_global_rn_key)
{
	if (curr_if->revertsp_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->revertsp_fn(dev, key, keep_global_rn_key);
}

int sed_activatelsp(struct sed_device *dev, const struct sed_key *key)
{
	return curr_if->activatelsp_fn(dev, key, NULL, false);
}

int sed_lock_unlock(struct sed_device *dev, const struct sed_key *key,
		enum SED_ACCESS_TYPE lock_type)
{
	return curr_if->lock_unlock_fn(dev, key, lock_type);
}

int sed_addusertolr(struct sed_device *dev, const struct sed_key *key,
		    const char *user, enum SED_ACCESS_TYPE lock_type, uint8_t lr)
{
	return curr_if->addusr_to_lr_fn(dev, key, user, lock_type, lr);
}

int sed_enableuser(struct sed_device *dev, const struct sed_key *key,
		   const char *user)
{
	return curr_if->activate_usr_fn(dev, key, user);
}

int sed_setuplr(struct sed_device *dev, const struct sed_key *key,
		const char *user, uint8_t lr, size_t range_start,
		size_t range_length, bool sum, bool RLE, bool WLE)
{
	return curr_if->setuplr_fn(dev, key, user, lr, range_start,
				   range_length, sum, RLE, WLE);
}

int sed_setpw(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key)
{
	return curr_if->set_pwd_fn(dev, auth, old_key, new_key);
}

int sed_shadowmbr(struct sed_device *dev, const struct sed_key *key, bool mbr)
{
	return curr_if->shadow_mbr_fn(dev, key, mbr);
}

int sed_write_shadow_mbr(struct sed_device *dev, const struct sed_key *key,
			const uint8_t *from, uint32_t size, uint32_t offset)
{
	if (curr_if->write_shadow_mbr_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->write_shadow_mbr_fn(dev, key, from, size, offset);
}

int sed_mbrdone(struct sed_device *dev, const struct sed_key *key, bool mbr)
{
	return curr_if->mbr_done_fn(dev, key, mbr);
}

int sed_eraselr(struct sed_device *dev, const struct sed_key *key,
		const char *user, const uint8_t lr, bool sum)
{
	return curr_if->eraselr_fn(dev, key, user, lr, sum);
}

int sed_ds_read(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, uint8_t *to, uint32_t size,
		uint32_t offset)
{
	if (curr_if->ds_read_fn == NULL)
		return -EOPNOTSUPP;

	if (auth != SED_ANYBODY && key == NULL) {
		SEDCLI_DEBUG_MSG("Key can't be null\n");
		return -EINVAL;
	}

	return curr_if->ds_read_fn(dev, auth, key, to, size, offset);
}

int sed_ds_write(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, const void *from, uint32_t size,
		uint32_t offset)
{
	if (curr_if->ds_write_fn == NULL)
		return -EOPNOTSUPP;

	if (auth != SED_ANYBODY && key == NULL) {
		SEDCLI_DEBUG_MSG("Key can't be null\n");
		return -EINVAL;
	}

	return curr_if->ds_write_fn(dev, auth, key, from, size, offset);
}

int sed_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key)
{
	if (curr_if->ds_add_anybody_get_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->ds_add_anybody_get_fn(dev, key);
}

int sed_list_lr(struct sed_device *dev, const struct sed_key *key,
		struct sed_opal_lockingranges *lrs)
{
	if (curr_if->list_lr_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->list_lr_fn(dev, key, lrs);
}

int sed_issue_blocksid_cmd(struct sed_device *dev, bool hw_reset)
{
	if (curr_if->blocksid_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->blocksid_fn(dev, hw_reset);
}

int sed_stack_reset_cmd(struct sed_device *dev)
{
	if (curr_if->stack_reset_fn == NULL)
		return -EOPNOTSUPP;

	return curr_if->stack_reset_fn(dev);
}

const char *sed_error_text(int sed_status)
{
	if (sed_status < SED_SUCCESS || sed_status > SED_FAIL) {
		return NULL;
	}

	return sed_statuses[sed_status];
}

int sed_dev_ioctl(struct sed_device *dev, unsigned long request, unsigned long parm)
{
	return ioctl(dev->fd, request, parm);
}
