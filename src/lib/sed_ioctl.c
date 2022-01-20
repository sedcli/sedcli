/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <keyutils.h>

#include <linux/sed-opal.h>

#include "sed_ioctl.h"
#include "sed_util.h"
#include "sedcli_log.h"

int sedopal_init(struct sed_device *dev, const char *device_path)
{
	int ret = 0;

	dev->fd = 0;
	dev->priv = NULL;

	ret = open_dev(device_path);
	if (ret < 0)
		return -ENODEV;

	dev->fd = ret;

	return 0;
}

static int set_opal_key(const struct sed_key *key, struct opal_key *okey)
{
	switch (key->src) {
	case SED_KEY_FROMUSER:
		if (key->len == 0)
			return -EINVAL;
#ifdef CONFIG_OPAL_DRIVER_KEY_TYPE
		okey->key_type = OPAL_INCLUDED;
#endif
		break;
#ifdef CONFIG_OPAL_DRIVER_KEY_TYPE
	case SED_KEY_KEYRING:
		okey->key_type = OPAL_KEYRING;
		if (key->key_sn > 0) {
			okey->key_len = sizeof(okey->key_sn);
			okey->key_sn = key->key_sn;
		} else
			okey->key_len = 0;
		return 0;
#endif
	default:
		return -EINVAL;
	}
	okey->key_len = key->len;
	memcpy(okey->key, key->key, okey->key_len);
	return 0;
}

static int do_generic_opal(int fd, const struct sed_key *key,
				unsigned long ioctl_cmd)
{
	struct opal_key opal_disk_key = { };

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must Provide a password for this command\n");
		return -EINVAL;
	}

	if (set_opal_key(key, &opal_disk_key) != 0) {
		return -EINVAL;
	}

	return ioctl(fd, ioctl_cmd, &opal_disk_key);
}

static int do_generic_lkul(int fd, const struct sed_key *key,
					enum SED_AUTHORITY user, enum SED_ACCESS_TYPE lock_type, uint8_t lr,
					bool sum, unsigned long ioctl_cmd)
{
	struct opal_lock_unlock oln = { };
	uint32_t opal_user = user, opal_locktype = lock_type;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Need to supply password!\n");
		return -EINVAL;
	}

	if (!sum && (opal_user > SED_USER9 || opal_locktype > SED_NO_ACCESS)) {
		SEDCLI_DEBUG_MSG("Need to provide correct user or lock type!\n");
		return -EINVAL;
	}

	oln.session.sum = sum;
	oln.session.who = opal_user;
	oln.l_state = opal_locktype;

	if (set_opal_key(key, &oln.session.opal_key) != 0) {
		return -EINVAL;
	}

	oln.session.opal_key.lr = lr;

	return ioctl(fd, ioctl_cmd, &oln);
}

int sedopal_lock_unlock(struct sed_device *dev, const struct sed_key *key,
						enum SED_ACCESS_TYPE lock_type)
{
	int fd = dev->fd;

	return do_generic_lkul(fd, key, SED_ADMIN1, lock_type, 0,
			false, IOC_OPAL_LOCK_UNLOCK);
}

int sedopal_takeownership(struct sed_device *dev, const struct sed_key *key)
{
	int fd = dev->fd;

	return do_generic_opal(fd, key, IOC_OPAL_TAKE_OWNERSHIP);
}

int sedopal_write_shadow_mbr(struct sed_device *dev, const struct sed_key *key,
		const uint8_t *from, uint32_t size, uint32_t offset)
{
	int fd = dev->fd;
	struct opal_shadow_mbr opal_wr_mbr = {
		.data = (__u64)from,
		.size = size,
		.offset = offset,
	};

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Need to supply password!\n");
		return -EINVAL;
	}

	if (set_opal_key(key, &opal_wr_mbr.key) != 0) {
		return -EINVAL;
	}

	return ioctl(fd, IOC_OPAL_WRITE_SHADOW_MBR, &opal_wr_mbr);
}

int sedopal_activatelsp(struct sed_device *dev, const struct sed_key *key, char *lr_str, bool sum)
{
	int fd = dev->fd;
	struct opal_lr_act opal_activate = { };
	unsigned long parsed;
	size_t count = 0;
	char *num, *errchk;

	if (key == NULL || (sum && !lr_str)) {
		SEDCLI_DEBUG_MSG("Must Provide a password, and a LR string "\
				 "if SUM \n");
		return -EINVAL;
	}

	opal_activate.sum = sum;
	SEDCLI_DEBUG_PARAM("Sum is %d\n", sum);

	if (!lr_str)
		opal_activate.num_lrs = 1;
	else {
		num = strtok(lr_str, ",");
		while (num != NULL && count < OPAL_MAX_LRS) {
			parsed = strtoul(num, &errchk, 10);
			if (errchk == num)
				continue;
			opal_activate.lr[count] = parsed;
			SEDCLI_DEBUG_PARAM("added %lu to lr at index %zu\n",
					   parsed, count);
			num = strtok(NULL, ",");
			count++;
		}
		opal_activate.num_lrs = count;
	}

	if (set_opal_key(key, &opal_activate.key) != 0) {
		return -EINVAL;
	}

	return ioctl(fd, IOC_OPAL_ACTIVATE_LSP, &opal_activate);
}

int sedopal_setup_global_range(struct sed_device *dev, const struct sed_key *key)
{
	struct opal_user_lr_setup setup = { };
	int fd = dev->fd;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Incorrect parameters, please try again\n");
		return -EINVAL;
	}

	setup.session.who = SED_ADMIN1;
	setup.session.sum = false;
	setup.RLE = true;
	setup.WLE = true;
	setup.range_start = 0;
	setup.range_length = 0;
	setup.session.opal_key.lr = 0;

	if (set_opal_key(key, &setup.session.opal_key) != 0) {
		return -EINVAL;
	}

	return ioctl(fd, IOC_OPAL_LR_SETUP, &setup);
}

int sedopal_setuplr(struct sed_device *dev, const struct sed_key *key,
                    const char *user, uint8_t lr, size_t range_start,
                    size_t range_length, bool sum, bool RLE, bool WLE)
{
	struct opal_user_lr_setup setup = { };
	int fd = dev->fd;

	if (range_start == ~0|| range_length == ~0 || (!sum && user == NULL) ||
	    key == NULL) {
		SEDCLI_DEBUG_MSG("Incorrect parameters, please try again\n");
		return -EINVAL;
	}

	if (!sum)
		if (sed_get_user(user, &setup.session.who))
			return -EINVAL;

	setup.session.sum = sum;
	setup.RLE = RLE;
	setup.WLE = WLE;
	setup.range_start = range_start;
	setup.range_length = range_length;

	if (set_opal_key(key, &setup.session.opal_key) != 0) {
		return -EINVAL;
	}

	setup.session.opal_key.lr = lr;

	return ioctl(fd, IOC_OPAL_LR_SETUP, &setup);
}


int sedopal_add_usr_to_lr(struct sed_device *dev, const struct sed_key *key,
			const char *user, enum SED_ACCESS_TYPE lock_type, uint8_t lr)
{
	return do_generic_lkul(dev->fd, key, SED_ADMIN1, lock_type, lr,
				false, IOC_OPAL_ADD_USR_TO_LR);
}

int sedopal_mbrdone(struct sed_device *dev, const struct sed_key *key,
		bool mbr_done)
{
	struct opal_mbr_done mbr = { };

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("User must provide ADMIN1 password\n");
		return -EINVAL;
	}

	mbr.done_flag = mbr_done ? OPAL_MBR_DONE : OPAL_MBR_NOT_DONE;

	if (set_opal_key(key, &mbr.key) != 0) {
		return -EINVAL;
	}

	return ioctl(dev->fd, IOC_OPAL_MBR_DONE, &mbr);
}

int sedopal_shadowmbr(struct sed_device *dev, const struct sed_key *key,
		      bool enable_mbr)
{
	struct opal_mbr_data mbr = { };

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("User must provide ADMIN1 password\n");
		return -EINVAL;
	}

	mbr.enable_disable = enable_mbr ? OPAL_MBR_ENABLE : OPAL_MBR_DISABLE;

	if (set_opal_key(key, &mbr.key) != 0) {
		return -EINVAL;
	}

	return ioctl(dev->fd, IOC_OPAL_ENABLE_DISABLE_MBR, &mbr);
}

int sedopal_setpw(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key)
{
	struct opal_new_pw pw = { };
	int fd = dev->fd;

	if (old_key == NULL || new_key == NULL || auth != SED_ADMIN1) {
		SEDCLI_DEBUG_MSG("Invalid arguments, please try again\n");
		return -EINVAL;
	}

	pw.session.who = SED_ADMIN1;
	pw.session.sum = 0;
	pw.session.opal_key.lr = 0;
	pw.new_user_pw.who = SED_ADMIN1;
	pw.new_user_pw.opal_key.lr = 0;

	if (set_opal_key(old_key, &pw.session.opal_key) != 0) {
		return -EINVAL;
	}
	if (set_opal_key(new_key, &pw.new_user_pw.opal_key) != 0) {
		return -EINVAL;
	}

	return ioctl(fd, IOC_OPAL_SET_PW, &pw);
}

int sedopal_enable_user(struct sed_device *dev, const struct sed_key *key,
                        const char *user)
{
	struct opal_session_info usr = { };
	int fd = dev->fd;

	if (user == NULL || key == NULL) {
		SEDCLI_DEBUG_PARAM("Invalid arguments for %s\n", __func__);
		return -EINVAL;
	}

	if(sed_get_user(user, &usr.who))
		return -EINVAL;

	if (usr.who == OPAL_ADMIN1) {
		SEDCLI_DEBUG_MSG("Opal Admin is already activated by default!\n");
		return -EINVAL;
	}

	if (set_opal_key(key, &usr.opal_key) != 0) {
		return -EINVAL;
	}

	usr.opal_key.lr = 0;

	return ioctl(fd, IOC_OPAL_ACTIVATE_USR, &usr);
}

int sedopal_erase_lr(struct sed_device *dev, const struct sed_key *key,
                     const char *user, uint8_t lr, bool sum)
{
	struct opal_session_info session = { };
	int fd = dev->fd;

	if ((!sum && user == NULL) || key == NULL) {
		SEDCLI_DEBUG_MSG("Need to supply user, lock type and password!\n");
		return -EINVAL;
	}

	session.sum = sum;
	if (!sum)
		if(sed_get_user(user, &session.who))
			return -EINVAL;

	if (set_opal_key(key, &session.opal_key) != 0) {
		return -EINVAL;
	}

	session.opal_key.lr = lr;

	return ioctl(fd, IOC_OPAL_ERASE_LR, &session);
}

int sedopal_secure_erase_lr(struct sed_device *dev, const struct sed_key *key,
                            const char *user, uint8_t lr, bool sum)
{
	struct opal_session_info usr = { };
	int fd = dev->fd;

	if (user == NULL || key == NULL) {
		SEDCLI_DEBUG_PARAM("Invalid arguments for %s\n", __func__);
		return -EINVAL;
	}

	if(sed_get_user(user, &usr.who))
		return -EINVAL;

	if (set_opal_key(key, &usr.opal_key) != 0) {
		return -EINVAL;
	}

	usr.opal_key.lr = 0;

	return ioctl(fd, IOC_OPAL_SECURE_ERASE_LR, &usr);
}

int sedopal_reverttper(struct sed_device *dev, const struct sed_key *key,
				bool psid, bool non_destructive)
{
	int fd = dev->fd;
	unsigned long ioctl_code;

	if (non_destructive)
		return -EOPNOTSUPP;

	if (psid) {
#ifdef CONFIG_OPAL_DRIVER_PSID_REVERT
		ioctl_code = IOC_OPAL_PSID_REVERT_TPR;
#else
		return -EOPNOTSUPP;
#endif
	} else {
		ioctl_code = IOC_OPAL_REVERT_TPR;
	}

	return do_generic_opal(fd, key, ioctl_code);
}

int sedopal_save(struct sed_device *dev, const struct sed_key *key,
				const char *user, enum SED_ACCESS_TYPE lock_type, uint8_t lr, bool sum)
{
	int fd = dev->fd;

	return do_generic_lkul(fd, key, SED_ADMIN1, lock_type, lr, sum, IOC_OPAL_SAVE);
}

void sedopal_deinit(struct sed_device *dev)
{
	close(dev->fd);
}

int sedopal_getpwd(struct sed_key_options *opts, enum SED_AUTHORITY auth,
		struct sed_key *key, bool confirm, bool old)
{
	if (opts->key_src == SED_KEY_KEYRING) {
		key->src = SED_KEY_KEYRING;
		key->key_sn = opts->key_sn;
		return 0;
	}
	return -EOPNOTSUPP;
}
