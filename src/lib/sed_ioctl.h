/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _SED_IOCTL_H
#define _SED_IOCTL_H

#include <linux/types.h>
#include <stdbool.h>
#include <libsed.h>

int sedopal_init(struct sed_device *dev, const char *device_path);

int sedopal_lock_unlock(struct sed_device *dev, const struct sed_key *key,
						enum SED_ACCESS_TYPE lock_type);

int sedopal_takeownership(struct sed_device *dev, const struct sed_key *key);

int sedopal_activatelsp(struct sed_device *dev, const struct sed_key *key, char *lr_str, bool sum);

int sedopal_setuplr(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user, uint8_t lr, size_t range_start,
		size_t range_length, bool sum, bool RLE, bool WLE);

int sedopal_setup_global_range(struct sed_device *dev, const struct sed_key *key);

int sedopal_add_usr_to_lr(struct sed_device *dev, const struct sed_key *key,
			const char *user, enum SED_ACCESS_TYPE lock_type, uint8_t lr);

int sedopal_shadowmbr(struct sed_device *dev, const struct sed_key *key,
		      bool enable_mbr);

int sedopal_mbrdone(struct sed_device *dev, const struct sed_key *key,
		bool mbr_done);

int sedopal_setpw(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key);

int sedopal_enable_user(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user);

int sedopal_erase_lr(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user, uint8_t lr, bool sum);

int sedopal_secure_erase_lr(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user, uint8_t lr, bool sum);

int sedopal_reverttper(struct sed_device *dev, const struct sed_key *key, bool psid, bool non_destructive);

int sedopal_save(struct sed_device *dev, const char *password, uint8_t key_len,
				const char *user, enum SED_ACCESS_TYPE lock_type, uint8_t lr, bool sum);

void sedopal_deinit(struct sed_device *dev);

#endif /* _SED_IOCTL_H */
