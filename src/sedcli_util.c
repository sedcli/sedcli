/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <termios.h>
#include <errno.h>
#include <string.h>

#include <sys/syslog.h>
#include <sys/mman.h>

#include <libsed.h>

#include "argp.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

static struct termios term;
extern sedcli_printf_t sedcli_printf;

static char *allowed_lock_type[] = {"RO", "RW", "LK"};

int get_lock_type(const char *lock_type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(allowed_lock_type); i++) {
		if (!strcmp(allowed_lock_type[i], lock_type)) {
			return (1 << i);
		}
	}

	return -1;
}

static void echo_disable()
{
	tcgetattr(1, &term);
	term.c_cc[VMIN] = 1;
	term.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(1, 0, &term);
}

static void echo_enable()
{
	term.c_lflag |= ECHO | ICANON;
	tcsetattr(1, 0, &term);
}

int get_password(char *pwd, uint8_t *len, int min, int max)
{
	size_t dest = max + 2;
	uint8_t temp[dest];
	int ret, temp_len;

	echo_disable();

	memset(temp, 0, dest);

	if (fgets((char *) temp, dest, stdin) == NULL) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		ret = -EINVAL;
		goto err;
	}
	sedcli_printf(LOG_INFO, "\n");

	/*
	 * The temp buffer is chosen to be 2-Bytes greater than the MAX_KEY_LEN
	 * This helps to identify if the user is trying to exceed the MAX
	 * allowable key_len, by checking for NULL or NEW-LINE character at index
	 * dest-2. (Last Byte is always a NULL character as per the fgets functionality)
	 */
	if (temp[dest - 2] != '\n' && temp[dest - 2] != '\0') {
		sedcli_printf(LOG_ERR, "Password too long..!!\n");
		sedcli_printf(LOG_ERR, "Please provide password max %d characters long.\n", max);
		ret = -EINVAL;
		goto err;
	}

	temp_len = strnlen((char *)temp, SED_MAX_KEY_LEN);
	if (temp[temp_len - 1] == '\n') {
		temp[temp_len - 1] = '\0';
		--temp_len;
		if (temp_len < min) {
			sedcli_printf(LOG_ERR, "Password too short..!!\n");
			sedcli_printf(LOG_ERR, "Please provide password min %d characters long.\n", min);
			ret = -EINVAL;
			goto err;
		}
	}

	*len = temp_len;
	memcpy(pwd, temp, *len);
	ret = 0;

err:
	memset(temp, 0, dest);
	echo_enable();
	return ret;
}

void *alloc_locked_buffer(size_t size)
{
	void *buf;
	int status;

	buf = malloc(size);

	if (!buf)
		return NULL;

	memset(buf, 0, 1);	/* silence GCC warning (error) */
	status = mlock(buf, size);

	if (status) {
		free(buf);
		return NULL;
	}

	return buf;
}

void free_locked_buffer(void *buf, size_t buf_size)
{
	if (!buf)
		return;

	memset(buf, 0, buf_size);
	munlock(buf, buf_size);
	free(buf);
}
