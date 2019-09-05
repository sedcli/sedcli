/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "sed_util.h"
#include "sedcli_log.h"

#define NVME_DEV_PREFIX "nvme"

int open_dev(const char *dev)
{
	int err, fd;
	struct stat _stat;
	char *base;

	base = basename(dev);
	if (strncmp(base, NVME_DEV_PREFIX, strnlen(NVME_DEV_PREFIX, PATH_MAX))) {
		SEDCLI_DEBUG_PARAM("%s is not an NVMe device!\n", dev);
		return -EINVAL;
	}

	err = open(dev, O_RDONLY);
	if (err < 0)
		goto perror;
	fd = err;

	err = fstat(fd, &_stat);
	if (err < 0) {
		close(fd);
		goto perror;
	}

	if (!S_ISBLK(_stat.st_mode)) {
		SEDCLI_DEBUG_PARAM("%s is not a block device!\n", dev);
		close(fd);
		return -ENODEV;
	}

	return fd;

perror:
	perror(dev);
	return err;
}

int sed_get_user(const char *user, uint32_t *who)
{
	unsigned int unum = 0;
	char *error;

	if (strlen(user) < 5) {
		SEDCLI_DEBUG_MSG("Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}

	if (!strncasecmp(user, "admin", 5)) {
		SEDCLI_DEBUG_MSG("Making the user an admin\n");
		*who = SED_ADMIN1;
	} else if (!strncasecmp(user, "user", 4)) {
		unum = strtol(&user[4], &error, 10);
		if (error == &user[4]) {
			SEDCLI_DEBUG_MSG("Failed to parse user # from string\n");
			return -EINVAL;
		}
		if (unum < SED_USER1 || unum > SED_USER9) {
			SEDCLI_DEBUG_MSG("Incorrect User, please provide userN\n");
			return -EINVAL;
		}
		*who = unum;
	} else {
		SEDCLI_DEBUG_MSG("Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}

	return 0;
}

