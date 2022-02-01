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
#include <unistd.h>
#include <keyutils.h>
#include <linux/fs.h>	/* for BLKRRPART */

#include <sys/mman.h>
#include <sys/stat.h>

#include <libsed.h>

#include "argp.h"
#include "sedcli_util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define SEDCLI_TITLE "Self-Encrypting Drive command line interface (sedcli)"
#define PYRITE_V100 "v1.00"
#define PYRITE_V200 "v2.00"

extern sedcli_printf_t sedcli_printf;

static int sed_discv_handle_opts(char *opt, char **arg);
static int ownership_handle_opts(char *opt, char **arg);
static int activatelsp_handle_opts(char*opt, char **arg);
static int reverttper_handle_opts(char *opt, char **arg);
static int lock_unlock_handle_opts(char *opt, char **arg);
static int setup_global_range_handle_opts(char *opt, char **arg);
static int setpw_handle_opts(char *opt, char **arg);
static int mbr_control_handle_opts(char *opt, char **arg);
static int write_mbr_handle_opts(char *opt, char **arg);
static int blocksid_handle_opts(char *opt, char **arg);
static int unlock_handle_opts(char *opt, char **arg);
static int provision_handle_opts(char *opt, char **arg);

static int handle_sed_discv(void);
static int handle_ownership(void);
static int handle_version(void);
static int handle_help(void);
static int handle_activatelsp(void);
static int handle_reverttper(void);
static int handle_lock_unlock(void);
static int handle_setup_global_range(void);
static int handle_setpw(void);
static int handle_mbr_control(void);
static int handle_write_mbr(void);
static int handle_blocksid(void);
static int handle_unlock(void);
static int handle_provision(void);

#define COMMON_OPTS	\
	{'q', "quiet", "Suppress informative messages", 0},	\
	{'p', "pass-thru", "Force use of pass-thru inferface", 0}

#define KEY_SOURCE_VALS	"{user|keyring}"
#define KEY_SOURCE_OPTS	\
	{'k', "key-source", "Key source " KEY_SOURCE_VALS, 1, "SRC", 0}

static cli_option sed_discv_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'f', "format", "Output format: {normal|udev|numeric}", 1, "FMT", CLI_OPTION_OPTIONAL_ARG},
	COMMON_OPTS,
	{0}
};

static cli_option ownership_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option activatelsp_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option reverttper_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'i', "psid", "Revert Trusted Peripheral (TPer) with the PSID authority", 0, "FLAG", CLI_OPTION_OPTIONAL_ARG},
	{'n', "non-destructive", "Perform non-destructive revert on TPer (i.e. keep the user data intact even after revert)", 0, "FLAG", CLI_OPTION_OPTIONAL_ARG},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option lock_unlock_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'t', "accesstype", "String specifying access type to the data on drive. Allowed values: RO/RW/LK", 1, "FMT", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option setup_global_range_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option setpw_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	{'o', "old-key-source", "Old Key source " KEY_SOURCE_VALS, 1, "SRC", 0},
	COMMON_OPTS,
	{0}
};

static cli_option mbr_control_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'e', "enable", "Set/Unset MBR Enable column. Allowed values: TRUE/FALSE", 1, "FMT", CLI_OPTION_OPTIONAL_ARG},
	{'m', "done", "Set/Unset MBR Done column. Allowed values: TRUE/FALSE", 1, "FMT", CLI_OPTION_OPTIONAL_ARG},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option write_mbr_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'f', "file", "File path containing Pre-boot Application(PBA) image ", 1, "FMT", CLI_OPTION_REQUIRED},
	{'o', "offset", "Enter the offset(by default 0)", 1, "NUM", CLI_OPTION_OPTIONAL_ARG},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option blocksid_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'r', "hwreset", "Clear events by setting Hardware Reset flag. Allowed values: 1/0", 1, "FMT", CLI_OPTION_REQUIRED},
	COMMON_OPTS,
	{0}
};

static cli_option unlock_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_option provision_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	KEY_SOURCE_OPTS,
	COMMON_OPTS,
	{0}
};

static cli_command sedcli_commands[] = {
	{
		.name = "discovery",
		.short_name = 'D',
		.desc = "Performs SED Opal Device discovery(works only with NVMe passthru mechanism)",
		.long_desc = "Performs SED Opal Device discovery. Provides Level 0 and Level 1 Discovery info. of the device(works only with NVMe passthru mechanism)",
		.options = sed_discv_opts,
		.command_handle_opts = sed_discv_handle_opts,
		.handle = handle_sed_discv,
		.flags = 0,
		.help = NULL
	},
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
		.name = "mbr-control",
		.short_name = 'M',
		.desc = "Enable/Disable MBR Shadow and Set/Unset MBR Done",
		.long_desc = "Enable/Disable MBR Shadow and Set/Unset MBR Done",
		.options = mbr_control_opts,
		.command_handle_opts = mbr_control_handle_opts,
		.handle = handle_mbr_control,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "write-mbr",
		.short_name = 'W',
		.desc = "Write data into shadow MBR region",
		.long_desc = "Write data into shadow MBR region",
		.options = write_mbr_opts,
		.command_handle_opts = write_mbr_handle_opts,
		.handle = handle_write_mbr,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "block_sid",
		.short_name = 'B',
		.desc = "Issue BlockSID authentication command",
		.long_desc = "Issue BlockSID authentication command",
		.options = blocksid_opts,
		.command_handle_opts = blocksid_handle_opts,
		.handle = handle_blocksid,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "unlock",
		.short_name = 'U',
		.desc = "Unlock drive and prepare for use",
		.long_desc = "Unlock drive, set MBRDone, and re-read partition table.",
		.options = unlock_opts,
		.command_handle_opts = unlock_handle_opts,
		.handle = handle_unlock,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "provision",
		.short_name = 'T',
		.desc = "Provision (Take over) drive for locking",
		.long_desc = "Perform provisioning steps to setup locking on drive.",
		.options = provision_opts,
		.command_handle_opts = provision_handle_opts,
		.handle = handle_provision,
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

struct supp_data_rm_mechanism_map {
	int mask;
	char *text;
};

static struct supp_data_rm_mechanism_map map[] = {
	{ .mask = (1 << 0), .text = "Overwrite Data Erase" },
	{ .mask = (1 << 1), .text = "Block Erase" },
	{ .mask = (1 << 2), .text = "Crypto Erase" },
	{ .mask = (1 << 3), .text = "Unmap" },
	{ .mask = (1 << 4), .text = "Reset Write Pointers" },
	{ .mask = (1 << 5), .text = "Vendor Specific Erase" },
};

struct sedcli_options {
	char dev_path[PATH_MAX];
	int pass_thru;
	char file_path[PATH_MAX];	/* for --write-mbr command */
	struct sed_key pwd;
	struct sed_key old_pwd;		/* for --set-password command */
	int psid;
	int lock_type;
	int print_fmt;
	int enable;
	int done;
	int offset;
	bool hardware_reset;
	int non_destructive;
	struct sed_key_options key_opts;
	struct sed_key_options old_key_opts; /* for --set-password command */
};

static struct sedcli_options *opts = NULL;
static int quiet = 0;

enum sed_print_flags {
	SED_NORMAL,
	SED_UDEV,
	SED_UDEV_NUM,
};

static int handle_common_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "quiet")) {
		quiet = 1;
		return 0;
	} else if (!strcmp(opt, "pass-thru")) {
		opts->pass_thru = 1;
		return 0;
	}
	return 1;	/* not matched */
}

static int get_keyring_expr(char *arg, struct sed_key_options *kopts)
{
	/* parse [%:keyring]%key-type:key-desc */
	/* initial '%' has been removed. */
	key_serial_t kr = 0, sn = 0;

	char *krx = arg;
	char *ktx = strchr(arg, '%');
	if (ktx) {
		if (*krx++ != ':') {
			return -EINVAL;
		}
		*ktx++ = '\0';
	} else {
		krx = NULL;
		ktx = arg;
	}
	char *kkx = strchr(ktx, ':');
	if (!kkx) {
		return -EINVAL;
	}
	*kkx++ = '\0';
	if (krx) {
		kr = find_key_by_type_and_desc("keyring", krx, 0);
		if (kr <= 0) {
			return -EINVAL;
		}
		sn = keyctl_search(kr, ktx, kkx, 0);
	} else {
		sn = find_key_by_type_and_desc(ktx, kkx, 0);
	}
	if (sn <= 0) {
		return -EINVAL;
	}
	kopts->key_sn = sn;
	return 0;
}

static int get_keyring_opts(char *arg, struct sed_key_options *kopts)
{
	/*
	 * syntax: keyring[:{<key-serial>|[%:<keyring>]%<type>:<desc>}]
	 * examples:
	 * 	-k keyring
	 * 	-k keyring:1234567
	 * 	-k keyring:%user:sed-opal-pek
	 * 	-k keyring:%:_ses%user:sed-opal-pek
	 */
	kopts->key_sn = 0UL;	/* default to sed-opal keyring/key */
	if (*arg) {
		if (*arg++ != ':') {
			return -EINVAL;
		}
		if (*arg == '%') {
			if (get_keyring_expr(arg + 1, kopts) != 0) {
				return -EINVAL;
			}
		} else {
			unsigned long sn;
			char *end;
			sn = strtoul(arg, &end, 0);
			if (end == arg || *end) {
				return -EINVAL;
			}
			kopts->key_sn = sn;
		}
	}
	kopts->key_src = SED_KEY_KEYRING;
	return 0;
}

static int get_key_source(char *arg, struct sed_key_options *kopts)
{
	int err = 0;
	if (!strcmp(arg, "user")) {
		/* default */
		kopts->key_src = SED_KEY_FROMUSER;
	} else if (!strncmp(arg, "keyring", 7)) {
#ifdef CONFIG_OPAL_DRIVER_KEY_TYPE
		err = get_keyring_opts(arg + 7, kopts);
#else
		sedcli_printf(LOG_ERR,
			"keyring source requires opal-driver with key_type\n");
		err = -EINVAL;
#endif
	} else {
		sedcli_printf(LOG_ERR,
			"Invalid key source, use " KEY_SOURCE_VALS "\n");
		err = -EINVAL;
	}
	return err;
}

static int handle_key_source(char *opt, char **arg)
{
	if (!strcmp(opt, "key-source")) {
		return get_key_source(arg[0], &opts->key_opts);
	} else if (!strcmp(opt, "old-key-source")) {
		return get_key_source(arg[0], &opts->old_key_opts);
	}
	return 1;	/* not matched */
}

enum sed_print_flags val_output_fmt(const char *fmt)
{
	if (!fmt)
		return -EINVAL;
	if (!strcmp(fmt, "normal"))
		return SED_NORMAL;
	if (!strcmp(fmt, "udev"))
		return SED_UDEV;
	if (!strcmp(fmt, "numeric"))
		return SED_UDEV_NUM;
	return -EINVAL;
}

int fmt_flag = 0;
int sed_discv_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (fmt_flag == 0) {
		/* Set the print format to Normal by default */
		opts->print_fmt = SED_NORMAL;
	}

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "format")) {
		opts->print_fmt = val_output_fmt(arg[0]);
		fmt_flag = 1;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int ownership_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int activatelsp_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int reverttper_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "psid")) {
		opts->psid = 1;
	} else if (!strcmp(opt, "non-destructive")) {
		opts->non_destructive = 1;
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int lock_unlock_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "accesstype")) {
		opts->lock_type = get_lock_type(arg[0]);
		if (opts->lock_type == -1) {
			sedcli_printf(LOG_ERR, "Incorrect lock type\n");
			return -EINVAL;
		}
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int setup_global_range_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int setpw_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

static int get_mbr_flag(char *mbr_flag)
{
	if (mbr_flag == NULL) {
		sedcli_printf(LOG_ERR, "User must provide TRUE/FALSE value\n");
		return -EINVAL;
	}

	if (!strncasecmp(mbr_flag, "TRUE", 4))
		return 1;
	if (!strncasecmp(mbr_flag, "FALSE", 5))
		return 0;

	sedcli_printf(LOG_ERR, "Invalid value given by the user\n");
	return -EINVAL;
}

bool mbr_enable = false;
bool mbr_done = false;
int mbr_control_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "enable")) {
		mbr_enable = true;
		opts->enable = get_mbr_flag(arg[0]);
		if (opts->enable < 0)
			return opts->enable;
	} else if (!strcmp(opt, "done")) {
		mbr_done = true;
		opts->done = get_mbr_flag(arg[0]);
		if (opts->done < 0)
			return opts->done;
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

bool offset_flag = false;
int write_mbr_handle_opts(char *opt, char **arg)
{
	int ret = 0;
	char *error;

	if (!offset_flag)
		opts->offset = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "file")) {
		strncpy(opts->file_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "offset")) {
		opts->offset = strtol(arg[0], &error, 10);
		if (error == arg[0]) {
			sedcli_printf(LOG_ERR,
				"Failed to parse user offset from string\n");
			return -EINVAL;
		}
		offset_flag = true;
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int blocksid_handle_opts(char *opt, char **arg)
{
	/* No reset BlockSID upon power events */
	int hwreset_flag = 0;
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if (!strcmp(opt, "hwreset") && strlen(arg[0]) == 1) {
		if ((arg[0][0] != '0') && (arg[0][0] != '1')) {
			return -EINVAL;
		}
		hwreset_flag = atoi(arg[0]);
		opts->hardware_reset = (hwreset_flag == 1) ? true : false;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int unlock_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

int provision_handle_opts(char *opt, char **arg)
{
	int ret = 0;

	if (!strcmp(opt, "device")) {
		strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
	} else if ((ret = handle_key_source(opt, arg)) != 1) {
		return ret;
	} else if ((ret = handle_common_opts(opt, arg)) != 1) {
		return ret;
	}

	return 0;
}

static void print_sed_status(int status)
{
	const char *sed_status = NULL;

	if (status < 0) {
		if (status == -EINVAL) {
			sedcli_printf(LOG_ERR, "Invalid parameter\n");
		} else if (status == -ENODEV) {
			sedcli_printf(LOG_ERR, "Couldn't determine device state\n");
		} else if (status == -ENOMEM) {
			sedcli_printf(LOG_ERR, "No memory\n");
		} else if (status == -EOPNOTSUPP) {
			sedcli_printf(LOG_ERR, "Not supported\n");
		} else {
			sedcli_printf(LOG_ERR, "Unknown error: %d\n", status);
		}
	} else {
		sed_status = sed_error_text(status);
		if (sed_status == NULL)
			sedcli_printf(LOG_ERR, "Unknown Error: %d\n", status);
		else if (status != SED_SUCCESS)
			sedcli_printf(LOG_ERR, "%s\n", sed_status);
		else if (!quiet)
			sedcli_printf(LOG_INFO, "%s\n", sed_status);
	}
}

static void print_tper_feat(uint8_t flags)
{
	sedcli_printf(LOG_INFO, "\nSED TPER FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "----------------------------\n");

	sedcli_printf(LOG_INFO, "\tSync Supported        : %s\n", (flags & SED_L0DISC_TPER_FEAT_SYNC) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tAsync Supported       : %s\n", (flags & SED_L0DISC_TPER_FEAT_ASYNC) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tACK/NAK Supported     : %s\n", (flags & SED_L0DISC_TPER_FEAT_ACK_NAK) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tBuffer Mgmt Supported : %s\n", (flags & SED_L0DISC_TPER_FEAT_BUFFER_MGMT) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tStreaming Supported   : %s\n", (flags & SED_L0DISC_TPER_FEAT_STREAMING) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tComID Mgmt Supported  : %s\n", (flags & SED_L0DISC_TPER_FEAT_COMID_MGMT) ? "Y" : "N");
}

static void print_locking_feat(uint8_t flags)
{
	sedcli_printf(LOG_INFO, "\nSED LOCKING FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "-------------------------------\n");

	sedcli_printf(LOG_INFO, "\tLocking Supported : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_SUPP) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tLocking Enabled   : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_LOCKING_EN) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tLocked            : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_LOCKED) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tMedia Encryption  : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_MEDIA_ENC) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tMBR Enabled       : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_MBR_EN) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tMBR Done          : %s\n", (flags & SED_L0DISC_LOCKING_FEAT_MBR_DONE) ? "Y" : "N");
}

static void print_geometry_feat(struct sed_geometry_supported_feat *geo)
{
	sedcli_printf(LOG_INFO, "\nSED GEOMETRY FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "--------------------------------\n");

	sedcli_printf(LOG_INFO, "\tAlignment required    : %s\n", (geo->flags & SED_L0DISC_GEOM_ALIGN) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tLogical Block Size    : %d\n", geo->logical_blk_sz);
	sedcli_printf(LOG_INFO, "\tAlignment Granularity : %ld\n", geo->alignmnt_granlrty);
	sedcli_printf(LOG_INFO, "\tLowest Aligned LBA    : %ld\n", geo->lowest_aligned_lba);
}

static void print_datastr_feat(struct sed_datastr_table_supported_feat *datastr)
{
	sedcli_printf(LOG_INFO, "\nSED DATASTORE FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "---------------------------------\n");

	sedcli_printf(LOG_INFO, "\tMax DataStore tables       : %d\n", datastr->max_num_datastr_tbls);
	sedcli_printf(LOG_INFO, "\tMax size DataStore tables  : %d\n", datastr->max_total_size_datstr_tbls);
	sedcli_printf(LOG_INFO, "\tDataStore table size align : %d\n", datastr->datastr_tbl_size_align);
}

static void print_opalv100_feat(struct sed_opalv100_supported_feat *opalv100)
{
	sedcli_printf(LOG_INFO, "\nSED Opal v1.00 FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "----------------------------------\n");

	sedcli_printf(LOG_INFO, "\tBase ComID       : %d\n", opalv100->v1_base_comid);
	sedcli_printf(LOG_INFO, "\tNumber of ComIDs : %d\n", opalv100->v1_comid_num);
}

static void print_opalv200_header()
{
	sedcli_printf(LOG_INFO, "\nSED Opal v2.00 FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "----------------------------------\n");
}

static void print_ruby_header()
{
	sedcli_printf(LOG_INFO, "\nSED Ruby FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "----------------------------------\n");
}

static void print_opalv200_ruby_feat(struct sed_opalv200_supported_feat *header)
{
	sedcli_printf(LOG_INFO, "\tBase ComID                      : %d\n", header->base_comid);
	sedcli_printf(LOG_INFO, "\tNumber of ComIDs                : %d\n", header->comid_num);
	sedcli_printf(LOG_INFO, "\tRange Crossing Behavior         : %d\n", (header->flags & SED_L0DISC_OPALV200_RUBY_FEAT_RANGE_CROSS) ? 0 : 1);
	sedcli_printf(LOG_INFO, "\tAdmin Authorities LSP Supported : %d\n", header->admin_lp_auth_num);
	sedcli_printf(LOG_INFO, "\tUser Authorities LSP Supported  : %d\n", header->user_lp_auth_num);
	sedcli_printf(LOG_INFO, "\tInitial PIN                     : %d\n", header->init_pin);
	sedcli_printf(LOG_INFO, "\tRevert PIN                      : %d\n", header->revert_pin);
}

static void print_pyrite_header(char *version)
{
	sedcli_printf(LOG_INFO, "\nSED Pyrite %s FEATURES SUPPORTED\n", version);
	sedcli_printf(LOG_INFO, "-------------------------------------\n");
}

static void print_pyrite_feat(struct sed_pyrite_supported_feat *pyrite_feat)
{
	sedcli_printf(LOG_INFO, "\tBase ComID                      : %d\n", pyrite_feat->base_comid);
	sedcli_printf(LOG_INFO, "\tNumber of ComIDs                : %d\n", pyrite_feat->comid_num);
	sedcli_printf(LOG_INFO, "\tInitial PIN                     : %d\n", pyrite_feat->init_pin);
	sedcli_printf(LOG_INFO, "\tRevert PIN                      : %d\n", pyrite_feat->revert_pin);
}

static void print_data_rm_mechanism_feat(struct sed_data_rm_mechanism_feat *data_rm_feat)
{
	char line[255];
	int i, cnt, curr_fmt, size, off;
	uint8_t val, fmt;

	sedcli_printf(LOG_INFO, "\nData Removal Mechanism FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "-------------------------------------------\n");

	sedcli_printf(LOG_INFO, "\tData Removal Operation Processing     : %s\n",
		      (data_rm_feat->flags & SED_L0DISC_DATARM_FEAT_REMOVAL_OP) ? "Revert or RevertSP" : "Other");

	sedcli_printf(LOG_INFO, "\tSupported Data Removal Mechanisms:\n");

	val = data_rm_feat->supp_data_rm_mechanism;
	fmt = data_rm_feat->time_formats;
	cnt = 1;
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (val & map[i].mask) {
			off = 0;
			size = ARRAY_SIZE(line);
			curr_fmt = fmt & map[i].mask;

			/* Clear line buffer first and then start appending
			 * until we have full line*/
			memset(line, 0, sizeof(line));
			off += snprintf(&line[off], size - off, "\t%d. %s: ", cnt, map[i].text);

			if (data_rm_feat->data_rm_time[i] == 0) {
				off += snprintf(&line[off], size - off, "Not reported\n");
			} else if (data_rm_feat->data_rm_time[i] < 65535) {
				off += snprintf(&line[off], size - off, "%d %s\n",
						data_rm_feat->data_rm_time[i] * 2,
						curr_fmt ? "minutes" : "seconds");
			} else {
				off += snprintf(&line[off], size - off, "> 131068 %s\n",
						curr_fmt ? "minutes" : "seconds");
			}

			sedcli_printf(LOG_INFO, "%s", line);
			cnt++;
		}
	}
}

static void print_blocksid_feat(struct sed_blocksid_supported_feat *blocksid)
{
	sedcli_printf(LOG_INFO, "\nBlock SID FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "-----------------------------\n");

	sedcli_printf(LOG_INFO, "\tSID Value State     : %d\n", (blocksid->flags1 & SED_L0DISC_BLOCKSID_FEAT1_SID_VALUE) ? 1 : 0);
	sedcli_printf(LOG_INFO, "\tSID Blocked State   : %d\n", (blocksid->flags1 & SED_L0DISC_BLOCKSID_FEAT1_SID_AUTH_BLOCKED) ? 1 : 0);
	sedcli_printf(LOG_INFO, "\tHardware Reset Flag : %d\n", (blocksid->flags2 & SED_L0DISC_BLOCKSID_FEAT2_HW_RESET) ? 1 : 0);
}

static void print_cnl_feat(struct sed_cnl_feat *cnl)
{
	sedcli_printf(LOG_INFO, "\nSED CNL FEATURES SUPPORTED\n");
	sedcli_printf(LOG_INFO, "---------------------------\n");

	sedcli_printf(LOG_INFO, "\tNamespace Non-Global Range Locking objects Supported : %s\n",
			(cnl->flags & SED_L0DISC_CNL_FEAT_RANGEC) ? "Y" : "N");
	sedcli_printf(LOG_INFO, "\tNamespace Non-Global Range Locking objects           : %s\n",
			(cnl->flags & SED_L0DISC_CNL_FEAT_RANGEP) ? "ONE or MORE" : "ZERO");
	sedcli_printf(LOG_INFO, "\tMaximum Key Count                                    : %d\n",
			cnl->max_key_count);
	sedcli_printf(LOG_INFO, "\tUnused Key Count                                     : %d\n",
			cnl->unused_key_count);
	sedcli_printf(LOG_INFO, "\tMaximum Ranges Per Namespace                         : %d (%#x)\n",
			cnl->max_ranges_per_ns, cnl->max_ranges_per_ns);
}

static void print_tper_properties(struct sed_tper_properties *tper)
{
	sedcli_printf(LOG_INFO, "\nTPER PROPERTIES\n");
	sedcli_printf(LOG_INFO, "----------------\n");

	for (int i = 0; i < NUM_TPER_PROPS; i++) {
		if (strcmp(tper->property[i].key_name, "") == 0)
			break;
		sedcli_printf(LOG_INFO, "\t%-25s : %ld\n", tper->property[i].key_name,
				tper->property[i].value);
	}
}

static void sed_discv_print_normal(struct sed_opal_device_discv *discv, const char *dev_path)
{
	uint16_t comid = 0;

	if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV200_DESC) {
		comid = discv->sed_lvl0_discv.sed_opalv200.base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV100_DESC) {
		comid = discv->sed_lvl0_discv.sed_opalv100.v1_base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_RUBY_DESC) {
		comid = discv->sed_lvl0_discv.sed_ruby.base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_PYRITEV200_DESC) {
		comid = discv->sed_lvl0_discv.sed_pyritev200.base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_PYRITEV100_DESC) {
		comid = discv->sed_lvl0_discv.sed_pyritev100.base_comid;
	}

	if (!comid) {
		sedcli_printf(LOG_INFO, "Invalid disk, %s is NOT SED-OPAL Compliant\n", dev_path);
		return;
	}

	if (discv->sed_lvl0_discv.features & SED_L0DISC_TPER_DESC)
		print_tper_feat(discv->sed_lvl0_discv.tper_feat);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_LOCKING_DESC)
		print_locking_feat(discv->sed_lvl0_discv.locking_feat);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_GEOMETRY_DESC)
		print_geometry_feat(&discv->sed_lvl0_discv.sed_geo);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_DATASTORE_DESC)
		print_datastr_feat(&discv->sed_lvl0_discv.sed_datastr);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV100_DESC)
		print_opalv100_feat(&discv->sed_lvl0_discv.sed_opalv100);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV200_DESC) {
		print_opalv200_header();
		print_opalv200_ruby_feat(&discv->sed_lvl0_discv.sed_opalv200);
	}
	if (discv->sed_lvl0_discv.features & SED_L0DISC_PYRITEV100_DESC) {
		print_pyrite_header(PYRITE_V100);
		print_pyrite_feat(&discv->sed_lvl0_discv.sed_pyritev100);
	}
	if (discv->sed_lvl0_discv.features & SED_L0DISC_PYRITEV200_DESC) {
		print_pyrite_header(PYRITE_V200);
		print_pyrite_feat(&discv->sed_lvl0_discv.sed_pyritev200);
	}
	if (discv->sed_lvl0_discv.features & SED_L0DISC_DATA_RM_DESC) {
		print_data_rm_mechanism_feat(&discv->sed_lvl0_discv.sed_data_rm_mechanism);
	}
	if (discv->sed_lvl0_discv.features & SED_L0DISC_RUBY_DESC) {
		print_ruby_header();
		print_opalv200_ruby_feat(&discv->sed_lvl0_discv.sed_ruby);
	}
	if (discv->sed_lvl0_discv.features & SED_L0DISC_BLOCKSID_DESC)
		print_blocksid_feat(&discv->sed_lvl0_discv.sed_blocksid);
	if (discv->sed_lvl0_discv.features & SED_L0DISC_CNL_DESC)
		print_cnl_feat(&discv->sed_lvl0_discv.sed_cnl);

	print_tper_properties(&discv->sed_tper_props);

	sedcli_printf(LOG_INFO, "\n");
}

#define SED_ENABLE "ENABLED"
#define SED_DISABLE "DISABLED"

static void sed_discv_print_udev(struct sed_opal_device_discv *discv, bool numeric)
{
	bool locking_enabled, locking_supp, locked, mbr_enabled, mbr_done;
	uint16_t comid = 0;
	uint8_t locking_feat = discv->sed_lvl0_discv.locking_feat;
	char *on = numeric ? "1" : SED_ENABLE;
	char *off = numeric ? "0" : SED_DISABLE;

	locking_supp = (locking_feat & SED_L0DISC_LOCKING_FEAT_SUPP) ? true : false;
	locking_enabled = (locking_feat & SED_L0DISC_LOCKING_FEAT_LOCKING_EN) ? true : false;
	locked = (locking_feat & SED_L0DISC_LOCKING_FEAT_LOCKED) ? true : false;
	mbr_enabled = (locking_feat & SED_L0DISC_LOCKING_FEAT_MBR_EN) ? true : false;
	mbr_done = (locking_feat & SED_L0DISC_LOCKING_FEAT_MBR_DONE) ? true : false;

	if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV200_DESC) {
		comid = discv->sed_lvl0_discv.sed_opalv200.base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_RUBY_DESC) {
		comid = discv->sed_lvl0_discv.sed_ruby.base_comid;
	} else if (discv->sed_lvl0_discv.features & SED_L0DISC_OPALV100_DESC) {
		comid = discv->sed_lvl0_discv.sed_opalv100.v1_base_comid;
	}

	sedcli_printf(LOG_INFO, "DEV_SED_COMPATIBLE=%s\n", comid ? on : off);
	/* this name is misleading: does not specify if device is actually locked */
	sedcli_printf(LOG_INFO, "DEV_SED_LOCKED=%s\n", locking_enabled ? on : off);
	sedcli_printf(LOG_INFO, "DEV_SED_LOCKING_SUPP=%s\n", locking_supp ? on : off);
	sedcli_printf(LOG_INFO, "DEV_SED_LOCKING=%s\n", locking_enabled ? on : off);
	sedcli_printf(LOG_INFO, "DEV_SED_LOCKING_LOCKED=%s\n", locked ? on : off);
	sedcli_printf(LOG_INFO, "DEV_SED_MBR_SHADOW=%s\n", mbr_enabled ? on : off);
	sedcli_printf(LOG_INFO, "DEV_SED_MBR_DONE=%s\n", mbr_done ? on : off);
}

static int handle_sed_discv(void)
{
	int ret = 0;
	struct sed_device *dev = NULL;
	struct sed_opal_device_discv discv = { 0 };

#ifdef CONFIG_OPAL_DRIVER_DISCOVERY
	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
#else
	/* special case until sed_ioctl() supports discovery */
	ret = sed_init(&dev, opts->dev_path, true);
#endif
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error initializing device\n", opts->dev_path);
		return -EINVAL;
	}

	ret = sed_dev_discovery(dev, &discv);
	if (ret) {
		sedcli_printf(LOG_ERR, "Command NOT supported for this interface.\n");
		goto deinit;
	}

	switch(opts->print_fmt) {
	case SED_NORMAL:
		sed_discv_print_normal(&discv, opts->dev_path);
		ret = 0;
		break;
	case SED_UDEV:
		sed_discv_print_udev(&discv, false);
		ret = 0;
		break;
	case SED_UDEV_NUM:
		sed_discv_print_udev(&discv, true);
		ret = 0;
		break;
	default:
		sedcli_printf(LOG_ERR, "Invalid format provided\n");
		ret = -EINVAL;
		break;
	}

deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_ownership(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->key_opts, SED_SID, &opts->pwd, true, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto deinit;
	}

	ret = sed_takeownership(dev, &opts->pwd);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_activatelsp(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->key_opts, SED_SID, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto deinit;
	}

	ret = sed_activatelsp(dev, &opts->pwd);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_reverttper(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->key_opts, opts->psid ? SED_PSID : SED_SID, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto deinit;
	}

	ret = sed_reverttper(dev, &opts->pwd, opts->psid, opts->non_destructive);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_lock_unlock(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto deinit;
	}

	ret = sed_lock_unlock(dev, &opts->pwd, opts->lock_type);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_setup_global_range(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto deinit;
	}

	ret = sed_setup_global_range(dev, &opts->pwd);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int handle_setpw(void)
{
	struct sed_device *dev = NULL;
	int ret;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", opts->dev_path);
		return ret;
	}

	ret = get_pwd_key(&opts->old_key_opts, SED_ADMIN1, &opts->old_pwd, false, true);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting old password\n");
		goto deinit;
	}
	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, true, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting new password\n");
		goto deinit;
	}

	ret = sed_setpw(dev, SED_ADMIN1, &opts->old_pwd, &opts->pwd);

	print_sed_status(ret);
deinit:
	sed_deinit(dev);

	return ret;
}

static int check_current_levl0_discv(struct sed_device *dev)
{
	int ret;
	struct sed_opal_device_discv discv = { 0 };

	ret = sed_dev_discovery(dev, &discv);
	if (ret) {
		if (ret == -EOPNOTSUPP) {
			sedcli_printf(LOG_WARNING, "Level0 discovery not supported "
					"for this interface.\n");
			/*
			 * Continue the operations even if the interface doesn't
			 * support level0 discovery, the kernel takes care of it
			 */
			return 0;
		} else {
			sedcli_printf(LOG_ERR, "Error doing level0 discovery\n");
			return ret;
		}
	}

	/*
	 * Check the current status of any level0 feture (Add them here)
	 * Return zero on successful checks and -1 on unsuccessful checks
	 */
	if (!(discv.sed_lvl0_discv.locking_feat & SED_L0DISC_LOCKING_FEAT_LOCKING_EN)) {
		sedcli_printf(LOG_INFO, "LSP NOT ACTIVATED\n");
		ret = -1;
	}

	return ret;
}

static int handle_mbr_control(void)
{
	struct sed_device *dev = NULL;
	int ret;

	if (mbr_enable && !opts->enable && opts->done) {
		sedcli_printf(LOG_ERR, "Error: disabling MBR shadow and setting "
				"MBR done doesn't take any effect\n");

		return -EINVAL;
	}

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n",
				opts->dev_path);
		return ret;
	}

	ret = check_current_levl0_discv(dev);
	if (ret)
		goto init_deinit;

	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto init_deinit;
	}

	if (mbr_enable) {
		ret = sed_shadowmbr(dev, &opts->pwd, opts->enable);
		if (ret)
			goto print_deinit;
	}

	if (mbr_done)
		ret = sed_mbrdone(dev, &opts->pwd, opts->done);

print_deinit:
	print_sed_status(ret);
init_deinit:
	sed_deinit(dev);
	return ret;
}

static int handle_write_mbr(void)
{
	struct sed_device *dev = NULL;
	int ret, mbr_fd;
	struct stat mbr_st;
	void *mbr_mmap;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n",
				opts->dev_path);
		return ret;
	}

	ret = check_current_levl0_discv(dev);
	if (ret)
		goto init_deinit;

	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error getting password\n");
		goto init_deinit;
	}

	mbr_fd = open(opts->file_path, O_RDONLY | O_CLOEXEC);
	if (fstat(mbr_fd, &mbr_st) == -1) {
		sedcli_printf(LOG_ERR, "Error opening/fstating file: %s\n",
				opts->file_path);
		ret = -1;
		goto close_fd;
	}

	mbr_mmap = mmap(NULL, mbr_st.st_size, PROT_READ, MAP_PRIVATE, mbr_fd,
			0);
	if (mbr_mmap == MAP_FAILED) {
		sedcli_printf(LOG_ERR, "Error mmaping file: %s\n",
				opts->file_path);
		ret = -1;
		goto close_fd;
	}

	ret = sed_write_shadow_mbr(dev, &opts->pwd, (const uint8_t *)mbr_mmap,
				mbr_st.st_size, opts->offset);

	print_sed_status(ret);

	munmap(mbr_mmap, mbr_st.st_size);
close_fd:
	close(mbr_fd);
init_deinit:
	sed_deinit(dev);
	return ret;
}

static int handle_blocksid(void)
{
	struct sed_device *dev = NULL;
	int ret = sed_init(&dev, opts->dev_path, opts->pass_thru);

	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n",
				opts->dev_path);
		return ret;
	}

	ret = sed_issue_blocksid_cmd(dev, opts->hardware_reset);

	print_sed_status(ret);
	sed_deinit(dev);

	return ret;
}

static int handle_unlock(void)
{
	int ret = 0;
	struct sed_device *dev = NULL;
	struct sed_opal_device_discv discv = { 0 };
	uint8_t flags;
	bool locked, mbr;

#ifdef CONFIG_OPAL_DRIVER_DISCOVERY
	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
#else
	/*
	 * special case until sed_ioctl() supports discovery,
	 * initialize device for pass-through.
	 */
	ret = sed_init(&dev, opts->dev_path, true);
#endif
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error initializing device\n", opts->dev_path);
		return -EINVAL;
	}
	ret = sed_dev_discovery(dev, &discv);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error getting device state.\n", opts->dev_path);
		goto deinit;
	}
	if (!(discv.sed_lvl0_discv.features & SED_L0DISC_LOCKING_DESC))
		goto print_deinit;
	flags = discv.sed_lvl0_discv.locking_feat;
	if (!(flags & SED_L0DISC_LOCKING_FEAT_SUPP) ||
			!(flags & SED_L0DISC_LOCKING_FEAT_LOCKING_EN))
		goto print_deinit;
	locked = (flags & SED_L0DISC_LOCKING_FEAT_LOCKED);
	mbr = (flags & SED_L0DISC_LOCKING_FEAT_MBR_EN) &&
		!(flags & SED_L0DISC_LOCKING_FEAT_MBR_DONE);
	if (!locked && !mbr)
		goto print_deinit;
#ifndef CONFIG_OPAL_DRIVER_DISCOVERY
	if (!opts->pass_thru) {
		/*
		 * until sed_ioctl() supports discovery, must re-init device for sed_ioctl().
		 */
		sed_deinit(dev);
		dev = NULL;
		ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
		if (ret) {
			sedcli_printf(LOG_ERR, "%s: Error initializing device\n", opts->dev_path);
			return -EINVAL;
		}
	}
#endif
	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error getting password\n", opts->dev_path);
		goto deinit;
	}
	if (locked) {
		ret = sed_lock_unlock(dev, &opts->pwd, SED_RW_ACCESS);
		if (ret) {
			sedcli_printf(LOG_ERR, "%s: Error setting lock RW\n", opts->dev_path);
			goto print_deinit;
		}
	}
	if (mbr) {
		ret = sed_mbrdone(dev, &opts->pwd, true);
		if (ret) {
			sedcli_printf(LOG_ERR, "%s: Error setting MBRDone\n", opts->dev_path);
			goto print_deinit;
		}
	}
	ret = sed_dev_ioctl(dev, BLKRRPART, 0);
	if (ret < 0) {
		ret = -errno;
		sedcli_printf(LOG_ERR, "%s: Error re-reading partition info\n", opts->dev_path);
		goto print_deinit;
	}
print_deinit:
	print_sed_status(ret);
deinit:
	sed_deinit(dev);
	return ret;
}

static int handle_provision(void)
{
	int ret = 0;
	struct sed_device *dev = NULL;

	ret = sed_init(&dev, opts->dev_path, opts->pass_thru);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error initializing device\n", opts->dev_path);
		return -EINVAL;
	}
	ret = get_pwd_key(&opts->key_opts, SED_ADMIN1, &opts->pwd, false, false);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error getting password\n", opts->dev_path);
		goto print_deinit;
	}
	ret = sed_takeownership(dev, &opts->pwd);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error taking ownership\n", opts->dev_path);
		goto print_deinit;
	}
	ret = sed_activatelsp(dev, &opts->pwd);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error activating locking SP\n", opts->dev_path);
		goto print_deinit;
	}
	ret = sed_setup_global_range(dev, &opts->pwd);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error setting up global locking range\n", opts->dev_path);
		goto print_deinit;
	}
	ret = sed_shadowmbr(dev, &opts->pwd, true);
	if (ret) {
		sedcli_printf(LOG_ERR, "%s: Error enabling shadow MBR\n", opts->dev_path);
		goto print_deinit;
	}
	ret = sed_mbrdone(dev, &opts->pwd, true);
	if (ret)
		sedcli_printf(LOG_ERR, "%s: Error setting MBRDone\n", opts->dev_path);

print_deinit:
	print_sed_status(ret);
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

	opts = alloc_locked_buffer(sizeof(*opts));

	if (opts == NULL) {
		sedcli_printf(LOG_ERR, "Failed to allocated memory\n");
		return -ENOMEM;
	}
	opts->pass_thru = 0;

	status = args_parse(&app_values, sedcli_commands, argc, argv);

	free_locked_buffer(opts, sizeof(*opts));

	return status;
}
