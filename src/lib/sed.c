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

#include "nvme_pt_ioctl.h"
#include "sed_ioctl.h"
#include "sed_util.h"
#include "sedcli_log.h"

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
	.dev_discv_fn = NULL,
	.ownership_fn = sedopal_takeownership,
	.get_msid_pin_fn = NULL,
	.revert_fn = sedopal_reverttper,
	.activatelsp_fn = sedopal_activatelsp,
	.revertsp_fn = NULL,	/* (i.e. revertlsp_fn) no cli option */
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
		return -EINVAL;
	}
#else
	if (strncmp(base, NVME_DEV_PREFIX, strnlen(NVME_DEV_PREFIX, PATH_MAX))) {
		SEDCLI_DEBUG_PARAM("%s is not an NVMe device and opal-driver not built-in!\n", dev_path);
		return -EINVAL;
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
		return -EOPNOTSUPP;

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
