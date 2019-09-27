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

#define SED_MAX_KEY_LEN (256)

enum SED_LOCK_TYPE {
	SED_NO_LOCK = 0x00,
	SED_READ_LOCK = 0x01,
	SED_WRITE_LOCK = 0x02,
	SED_READ_WRITE_LOCK = (SED_READ_LOCK | SED_WRITE_LOCK),
};

struct sed_device;

struct sed_key {
	uint8_t key[SED_MAX_KEY_LEN];
	uint8_t len;
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
int sed_lock_unlock(struct sed_device *dev, const struct sed_key *key, enum SED_LOCK_TYPE lock_type);

/**
 *
 */
int sed_reverttper(struct sed_device *dev, const struct sed_key *key, bool psid);

/**
 *
 */
int sed_revertsp(struct sed_device *dev, const struct sed_key *key, bool keep_global_rn_key);

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
