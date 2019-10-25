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

enum sed_user {
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
};

struct sed_device {
	int fd;
	void *priv;
};

int open_dev(const char *dev);

int sed_get_user(const char *user, uint32_t *who);

#endif /* _SED_UTIL_H_ */
