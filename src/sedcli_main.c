/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/syslog.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <termios.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <libsed.h>

#include "argp.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define SEDCLI_TITLE "Self-Encrypting Drive command line interface (sedcli)"

extern sedcli_printf_t sedcli_printf;

static int ownership_handle_opts(char *opt, char **arg);
static int activatelsp_handle_opts(char*opt, char **arg);
static int reverttper_handle_opts(char *opt, char **arg);
static int lock_unlock_handle_opts(char *opt, char **arg);
static int setup_global_range_handle_opts(char *opt, char **arg);
static int setpw_handle_opts(char *opt, char **arg);

static int handle_ownership(void);
static int handle_version(void);
static int handle_help(void);
static int handle_activatelsp(void);
static int handle_reverttper(void);
static int handle_lock_unlock(void);
static int handle_setup_global_range(void);
static int handle_setpw(void);

static void echo_enable();
static void echo_disable();

static cli_option ownership_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{0}
};

static cli_option activatelsp_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{0}
};

static cli_option reverttper_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'i', "psid", "Revert Trusted Peripheral (TPer) with the PSID authority", 0, "FLAG", CLI_OPTION_OPTIONAL_ARG},
	{0}
};

static cli_option lock_unlock_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'t', "locktype", "String specifying how to lock/unlock drive. Allowed values: RW/RO/WO/UNLOCK", 1, "FMT", CLI_OPTION_REQUIRED},
	{0}
};

static cli_option setup_global_range_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{0}
};

static cli_option setpw_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{0}
};

static cli_command sedcli_commands[] = {
	{
		.name = "ownership",
		.short_name = 'O',
		.desc = "Bring the Trusted Peripheral(TPer) out of a factory setting",
		.long_desc = "Take ownership operation updates password for SID authority in Admin SP.",
		.options = ownership_opts,
		.command_handle_opts = ownership_handle_opts,
		.handle = handle_ownership,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "activate-lsp",
		.short_name = 'A',
		.desc = "Activate the Locking SP",
		.long_desc = "Activate Locking SP if in Manufactured-Inactive state.\n"
				"   SID password is copied into Admin1 authority for activated Locking SP.",
		.options = activatelsp_opts,
		.command_handle_opts = activatelsp_handle_opts,
		.handle = handle_activatelsp,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "revert",
		.short_name = 'R',
		.desc = "Revert Trusted Peripheral(TPer) to factory State. *THIS WILL ERASE ALL YOUR DATA*",
		.long_desc = "TPer is reverted back to Manufactured-inactive state.",
		.options = reverttper_opts,
		.command_handle_opts = reverttper_handle_opts,
		.handle = handle_reverttper,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "setup-global-range",
		.short_name = 'S',
		.desc = "Set up global locking range",
		.long_desc = "Setup global locking range with Read Lock Enabled(RLE) and Write Lock Enabled(WLE) options set.",
		.options = setup_global_range_opts,
		.command_handle_opts = setup_global_range_handle_opts,
		.handle = handle_setup_global_range,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "lock-unlock",
		.short_name = 'L',
		.desc = "Lock or unlock global locking range",
		.long_desc = "Lock or unlock global locking range in Locking SP.",
		.options = lock_unlock_opts,
		.command_handle_opts = lock_unlock_handle_opts,
		.handle = handle_lock_unlock,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "set-password",
		.short_name = 'P',
		.desc = "Change password for Admin1 authority in Locking SP",
		.long_desc = "Update password for Admin1 authority in Locking SP.",
		.options = setpw_opts,
		.command_handle_opts = setpw_handle_opts,
		.handle = handle_setpw,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "version",
		.short_name = 'V',
		.desc = "Print sedcli version",
		.long_desc = NULL,
		.options = NULL,
		.command_handle_opts = NULL,
		.handle = handle_version,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "help",
		.short_name = 'H',
		.desc = "Print help",
		.long_desc = NULL,
		.options = NULL,
		.command_handle_opts = NULL,
		.handle = handle_help,
		.flags = 0,
		.help = NULL
	},
	{0},
};

struct sedcli_options {
	char dev_path[PATH_MAX];
	struct sed_key pwd;
	struct sed_key repeated_pwd;
	struct sed_key old_pwd;
	int psid;
	int lock_type;
};

static struct sedcli_options *opts = NULL;

static char *allowed_lock_type[] = {
	[SED_NO_LOCK] = "UNLOCK",
	[SED_READ_LOCK] = "WO",
	[SED_WRITE_LOCK] = "RO",
	[SED_READ_WRITE_LOCK] = "RW",
};

static struct termios term;

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


int ownership_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	}

	return 0;
}

int activatelsp_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	}

	return 0;
}

int reverttper_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "psid")) {
		opts->psid = 1;
	}

	return 0;
}

static int get_lock_type(const char *lock_type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(allowed_lock_type); i++) {
		if (0 == strcmp(allowed_lock_type[i], lock_type)) {
			return i;
		}
	}

	return -1;
}

int lock_unlock_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "locktype")) {
		opts->lock_type = get_lock_type(arg[0]);
		if (opts->lock_type == -1) {
			sedcli_printf(LOG_ERR, "Incorrect lock type\n");
			return -EINVAL;
		}
	}

	return 0;
}

int setup_global_range_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	}

	return 0;
}

int setpw_handle_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	}

	return 0;
}

static int get_password(struct sed_key *pwd)
{
	int c, flag = 0;

	echo_disable();

	if (fgets((char *) pwd->key, SED_MAX_KEY_LEN, stdin) == NULL) {
		sedcli_printf(LOG_INFO, "Error getting password\n");
		return -EINVAL;
	}

	sedcli_printf(LOG_INFO, "\n");

	pwd->len = strnlen((char *) pwd->key, SED_MAX_KEY_LEN);

	/* Handle case when user entered more characters than allowed max size */
	if (pwd->len == SED_MAX_KEY_LEN - 1 && pwd->key[pwd->len - 1] != '\n') {
		while ((c = getchar()) != '\n' && c != EOF) {
			flag = 1;
			break;
		}

		if (flag) {
			memset(pwd->key, 0, SED_MAX_KEY_LEN);
			pwd->len = 0;
			sedcli_printf(LOG_ERR, "Password too long\n");
			echo_enable();
			return -EINVAL;
		}
	}

	/* Remove new line character if needed */
	if (pwd->key[pwd->len - 1] == '\n') {
		pwd->key[pwd->len - 1] = 0;
		pwd->len--;
	}

	if (pwd->len == 0) {
		sedcli_printf(LOG_ERR, "Password too short\n");
		memset(pwd->key, 0, SED_MAX_KEY_LEN);
		pwd->len = 0;
		echo_enable();
		return -EINVAL;
	}

	echo_enable();
	return 0;
}

static int handle_ownership(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "New SID password: ");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	sedcli_printf(LOG_INFO, "Repeat new SID password: ");

	ret = get_password(&opts->repeated_pwd);

	if (ret != 0) {
		return -1;
	}

	if (0 != strcmp((char *) opts->pwd.key, (char *) opts->repeated_pwd.key)) {
		sedcli_printf(LOG_ERR, "Error: passwords don't match\n");
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_takeownership(dev, &opts->pwd);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_activatelsp(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "Enter SID password: ");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_activatelsp(dev, &opts->pwd);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else if (ret == -ENODEV) {
			sedcli_printf(LOG_ERR, "Couldn't determine device state\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_reverttper(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "Enter %s password: ", opts->psid ? "PSID" : "SID");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_reverttper(dev, &opts->pwd, opts->psid);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_lock_unlock(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "Enter Admin1 password: ");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_lock_unlock(dev, &opts->pwd, opts->lock_type);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else if (ret == -ENOMEM) {
			sedcli_printf(LOG_ERR, "No memory\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_setup_global_range(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "Enter Admin1 password: ");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_setup_global_range(dev, &opts->pwd);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_setpw(void)
{
	struct sed_device *dev = NULL;
	const char *sed_status = NULL;
	int ret;

	sedcli_printf(LOG_INFO, "Old Admin1 password: ");

	ret = get_password(&opts->old_pwd);

	if (ret != 0) {
		return -1;
	}

	sedcli_printf(LOG_INFO, "New Admin1 password: ");

	ret = get_password(&opts->pwd);

	if (ret != 0) {
		return -1;
	}

	sedcli_printf(LOG_INFO, "Repeat new Admin1 password: ");

	ret = get_password(&opts->repeated_pwd);

	if (ret != 0) {
		return -1;
	}

	if (0 != strcmp((char *) opts->pwd.key, (char *) opts->repeated_pwd.key)) {
		sedcli_printf(LOG_ERR, "Error: passwords don't match\n");
		return -1;
	}

	ret = sed_init(&dev, opts->dev_path);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = sed_setpw(dev, &opts->old_pwd, &opts->pwd);

	sed_status = sed_error_text(ret);

	if (sed_status == NULL && ret != 0) {
		if (ret == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error\n");
		}
	} else {
		sedcli_printf(LOG_ERR, "%s\n", sed_status);
	}

	sed_deinit(dev);

	return ret;
}

static int handle_version(void)
{
	sedcli_printf(LOG_INFO, "sedcli %s\n", SEDCLI_VERSION);

	return SUCCESS;
}

static int handle_help(void)
{
	app app_values;
	app_values.name = "sedcli";
	app_values.info = "<command> [option...]";
	app_values.title = SEDCLI_TITLE;
	app_values.doc = "";
	app_values.man = "sedcli";
	app_values.block = 0;

	print_help(&app_values, sedcli_commands);
	return 0;
}

int main(int argc, char *argv[])
{
	int blocked = 0, status;
	app app_values;

	app_values.name = argv[0];
	app_values.info = "<command> [option...]";
	app_values.title = SEDCLI_TITLE;
	app_values.doc = "";
	app_values.man = "sedcli";
	app_values.block = blocked;

	opts = malloc(sizeof(*opts));

	if (opts == NULL) {
		sedcli_printf(LOG_ERR, "Failed to allocated memory\n");
		return -1;
	}

	status = mlock(opts, sizeof(*opts));
	if (status != 0) {
		free(opts);
		sedcli_printf(LOG_ERR, "Failed to allocated memory\n");
		return -1;
	}

	status = args_parse(&app_values, sedcli_commands, argc, argv);

	memset(opts, 0, sizeof(*opts));
	munlock(opts, sizeof(*opts));
	free(opts);

	return status;
}
