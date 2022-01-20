/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _SED_UTIL_H_
#define _SED_UTIL_H_

#include <stdint.h>
#include <libsed.h>

enum SED_ACCESSTYPE {
	SED_RO = 0x01, /* 1 << 0 */
	SED_RW = 0x02, /* 1 << 1 */
	SED_LK = 0x04, /* 1 << 2 */
};

struct sed_device {
	int fd;
	struct sed_opal_device_discv discv;
	void *priv;
};

int open_dev(const char *dev);

int sed_get_user(const char *user, uint32_t *who);

int sed_get_discv(struct sed_opal_level0_discovery *discv, uint8_t *dest);

#endif /* _SED_UTIL_H_ */
