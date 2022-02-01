/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>

#include <sys/syslog.h>
#include <sys/mman.h>

#include <kmip_bio.h>
#include <libsed.h>

#include "argp.h"
#include "kmip_lib.h"
#include "crypto_lib.h"
#include "config_file.h"
#include "metadata_serializer.h"
#include "sedcli_util.h"

#define BACKUP_FILE_MIN_LEN (10)
#define BACKUP_FILE_MAX_LEN (64)

#define ENC_KEY_LEN (SED_MAX_KEY_LEN / 8)

extern sedcli_printf_t sedcli_printf;

static int handle_provision_opts(char *opt, char **arg);
static int handle_backup_opts(char *opt, char **arg);
static int handle_lock_unlock_opts(char *opt, char **arg);

static int handle_provision(void);
static int handle_backup(void);
static int handle_lock_unlock(void);

static int extract_key_from_backup(struct sed_key *dek_key);

static struct sedcli_stat_conf _conf_stat_file;
static struct sedcli_stat_conf *conf_stat_file = &_conf_stat_file;

static struct sedcli_dyn_conf _conf_dyn_file;
static struct sedcli_dyn_conf *conf_dyn_file = &_conf_dyn_file;

static cli_option provision_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'f', "file", "Use key from file to authenticate to the drive", 1, "DEVICE", CLI_OPTION_OPTIONAL_ARG},
	{0}
};

static cli_option backup_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'f', "file", "Output file path where disk key will be stored", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{0}
};


static cli_option lock_unlock_opts[] = {
	{'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
	{'t', "accesstype", "String specifying access type to the data on drive. Allowed values: RO/RW/LK", 1, "FMT", CLI_OPTION_REQUIRED},
	{'f', "file", "Use key from file", 1, "DEVICE", CLI_OPTION_OPTIONAL_ARG},
	{0}
};

static cli_command sedcli_commands[] = {
	{
		.name = "provision",
		.short_name = 'P',
		.desc = "Provision disk for security",
		.long_desc = NULL,
		.options = provision_opts,
		.command_handle_opts = handle_provision_opts,
		.handle = handle_provision,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "backup",
		.short_name = 'B',
		.desc = "Backup disk key into password protected file",
		.long_desc = NULL,
		.options = backup_opts,
		.command_handle_opts = handle_backup_opts,
		.handle = handle_backup,
		.flags = 0,
		.help = NULL
	},
	{
		.name = "lock-unlock",
		.short_name = 'L',
		.desc = "Lock or unlock global locking range",
		.long_desc = "Lock or unlock global locking range in Locking "
			     "SP using key retrieved from KMS or read from "
			     "backup file.",
		.options = lock_unlock_opts,
		.command_handle_opts = handle_lock_unlock_opts,
		.handle = handle_lock_unlock,
		.flags = 0,
		.help = NULL
	},
	{0},
};

static char *dev_path;
static char *backup_file_path;
static int lock_type = -1;

struct sedcli_options {
	char pwd[BACKUP_FILE_MAX_LEN];
	uint8_t pwd_len;
	char repeated_pwd[BACKUP_FILE_MAX_LEN];
	uint8_t repeated_pwd_len;
};

static struct sedcli_options *opts;

static int handle_provision_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device"))
		dev_path = (char *) arg[0];
	else if (!strcmp(opt, "file"))
		backup_file_path = (char *) arg[0];

	return 0;
}

static int handle_backup_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device"))
		dev_path = (char *) arg[0];
	else if (!strcmp(opt, "file"))
		backup_file_path = (char *) arg[0];

	return 0;
}

static int handle_lock_unlock_opts(char *opt, char **arg)
{
	if (!strcmp(opt, "device")) {
		dev_path = (char *) arg[0];
	} else if (!strcmp(opt, "accesstype")) {
		lock_type = get_lock_type(arg[0]);
		if (lock_type == -1) {
			sedcli_printf(LOG_ERR, "Incorrect lock type\n");
			return -EINVAL;
		}
	} else if (!strcmp(opt, "file")) {
		backup_file_path = (char *) arg[0];
	}

	return 0;
}

static int write_to_file(char *path, uint8_t *buffer, uint32_t size)
{
	FILE *file = NULL;
	int bytes_written;

	file = fopen(path, "w+");

	if (!file)
		return -EIO;

	bytes_written = fwrite(buffer, 1, size, file);

	fclose(file);

	return bytes_written;
}

static int read_from_file(char *path, uint8_t *buffer, uint32_t size)
{
	FILE *file = NULL;
	int bytes_read;

	file = fopen(path, "r");

	if (!file)
		return -EIO;

	bytes_read = fread(buffer, 1, size, file);

	fclose(file);

	return bytes_read;
}

static int handle_provision(void)
{
	struct sed_kmip_ctx *ctx = NULL;
	struct sed_device *sed_dev = NULL;
	struct sed_key *key = NULL; /* [0] - DEK, [1] - existing key*/
	struct sedcli_metadata *meta = NULL;
	int pek_id_size = 0, pek_size = 0, status = 0, auth_len;
	uint8_t *iv = NULL, *pek = NULL, *enc_dek = NULL, *pek_id = NULL,
		*tag = NULL;

	memset(conf_stat_file, 0, sizeof(*conf_stat_file));
	memset(conf_dyn_file, 0, sizeof(*conf_dyn_file));

	status = read_stat_config(conf_stat_file);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while reading sedcli config "
				       "file\n");
		return -1;
	}

	status = read_dyn_config(conf_dyn_file);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while reading sedcli dynamic "
				       "config file\n");
		return -1;
	}

	key = alloc_locked_buffer(2 * sizeof(*key));
	if (!key) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		status = -ENOMEM;
		goto deinit;
	}

	status = sed_kmip_init(ctx, conf_stat_file->kmip_ip,
			       conf_stat_file->kmip_port,
			       conf_stat_file->client_cert_path,
			       conf_stat_file->client_key_path,
			       conf_stat_file->ca_cert_path);

	if (status == -1) {
		sedcli_printf(LOG_ERR, "Can't initialize KMIP connection\n");
		goto deinit;
	}

	status = sed_kmip_connect(ctx);
	if (status) {
		sedcli_printf(LOG_ERR, "Can't connect to KMIP\n");
		goto deinit;
	}

	if (conf_dyn_file->pek_id_size == 0) {
		status = sed_kmip_gen_platform_key(ctx, (char **) &pek_id,
						   &pek_id_size);

		if (!status) {
			memcpy(conf_dyn_file->pek_id, pek_id, pek_id_size);
			conf_dyn_file->pek_id_size = pek_id_size;

			status = write_dyn_conf(conf_dyn_file->pek_id,
						pek_id_size);

			if (status) {
				sedcli_printf(LOG_ERR, "Error while updating "
						       "sedcli dynamic config "
						       "file\n");
				goto deinit;
			}
		} else {
			sedcli_printf(LOG_ERR, "Can't create PEK from KMIP\n");
			goto deinit;
		}
	}

	status = sed_kmip_get_platform_key(ctx, conf_dyn_file->pek_id,
					   conf_dyn_file->pek_id_size,
					   (char **) &pek, &pek_size);
	if (status) {
		sedcli_printf(LOG_ERR, "Can't get PEK from KMIP\n");
		goto deinit;
	}

	sed_kmip_deinit(ctx);

	meta = sedcli_metadata_alloc_buffer();
	if (!meta) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		status = -ENOMEM;
		goto deinit;
	}

	sedcli_metadata_init(meta, conf_dyn_file->pek_id_size,
			     IV_SIZE, SED_MAX_KEY_LEN, TAG_SIZE);

	pek_id = sedcli_meta_get_pek_id_addr(meta);
	iv = sedcli_meta_get_iv_addr(meta);
	enc_dek = sedcli_meta_get_enc_dek_addr(meta);
	tag = sedcli_meta_get_tag_addr(meta);

	auth_len = (enc_dek - (uint8_t *) meta);

	memcpy(pek_id, conf_dyn_file->pek_id, conf_dyn_file->pek_id_size);

	status = get_random_bytes(iv, IV_SIZE);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while generating IV\n");
		goto deinit;
	}

	status = get_random_bytes(key[0].key, SED_MAX_KEY_LEN);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while generating DEK\n");
		goto deinit;
	}
	key[0].len = SED_MAX_KEY_LEN;

	status = encrypt_dek(key[0].key, key[0].len, (uint8_t *) meta,
			     auth_len, enc_dek, SED_MAX_KEY_LEN, pek, pek_size,
			     iv, IV_SIZE, tag, TAG_SIZE);
	if (status < 0) {
		sedcli_printf(LOG_ERR, "Error while encrypting DEK\n");
		goto deinit;
	}

	status = sed_init(&sed_dev, dev_path, true);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while initializing SED "
				       "library\n");
		goto deinit;
	}

	/*
	 * If backup_file_path is set that means that we want to rekey.
	 * Otherwise it is initial provision path/
	 */
	if (!backup_file_path) {
		status = sed_get_msid_pin(sed_dev, &key[1]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while reading MSID "
					       "PIN\n");
			goto deinit;
		}

		status = sed_activatelsp(sed_dev, &key[1]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while activating LSP\n");
			goto deinit;
		}

		status = sed_ds_add_anybody_get(sed_dev, &key[1]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while updating "
					       "permissions for anybody "
					       "authority\n");
			goto deinit;
		}

		status = sed_ds_write(sed_dev, SED_ADMIN1, &key[1],
				      (uint8_t *) meta, SEDCLI_METADATA_SIZE,
				      0);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while storing sedcli "
					       "metadata in datastore\n");
			goto deinit;
		}

		status = sed_setpw(sed_dev, SED_SID, &key[1], &key[0]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while updating pin for "
					       "SID authority\n");
			goto deinit;
		}

		status = sed_setpw(sed_dev, SED_ADMIN1, &key[1], &key[0]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while updating pin for "
					       "Admin1 authority\n");
			goto deinit;
		}

		status = sed_setup_global_range(sed_dev, &key[0]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while setting up global "
					       "locking range\n");
			goto deinit;
		}

	} else {
		status = extract_key_from_backup(&key[1]);
		if (status)
			goto deinit;

		status = sed_ds_write(sed_dev, SED_ADMIN1, &key[1],
				      (uint8_t *) meta, SEDCLI_METADATA_SIZE,
				      0);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while storing sedcli "
					       "metadata in datastore\n");
			goto deinit;
		}

		status = sed_setpw(sed_dev, SED_SID, &key[1], &key[0]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while updating pin for "
					       "SID authority\n");
			goto deinit;
		}

		status = sed_setpw(sed_dev, SED_ADMIN1, &key[1], &key[0]);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while updating pin for "
					       "Admin1 authority\n");
			goto deinit;
		}
	}

deinit:
	sed_kmip_deinit(ctx);

	sed_deinit(sed_dev);

	sedcli_metadata_free_buffer(meta);

	if (pek)
		free(pek);

	if (ctx)
		free(ctx);

	if (key)
		free_locked_buffer(key, 2 * sizeof(*key));

	return status;
}

static int read_key_from_datastore(struct sed_device *sed_dev,
				   struct sed_key *dek_key)
{
	struct sed_kmip_ctx *ctx = NULL;
	int status = 0, ret = 0;
	int pek_size = 0, auth_len;
	struct sedcli_metadata *meta = NULL;
	uint8_t *iv = NULL, *pek = NULL, *pek_id = NULL, *enc_dek = NULL,
		*tag = NULL;
	uint32_t pek_id_size, iv_size, tag_size, enc_dek_size;

	status = read_stat_config(conf_stat_file);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while reading sedcli config "
				       "file\n");
		return -1;
	}

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto deinit;
	}

	meta = sedcli_metadata_alloc_buffer();
	if (!meta) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto deinit;
	}

	status = sed_ds_read(sed_dev, SED_ANYBODY, NULL, (uint8_t *) meta,
			     SEDCLI_METADATA_SIZE, 0);
	if (status) {
		sedcli_printf(LOG_ERR, "Can't read sedcli metadata from "
				       "datastore\n");
		ret = -1;
		goto deinit;
	}

	pek_id = sedcli_meta_get_pek_id_addr(meta);
	pek_id_size = sedcli_meta_get_pek_id_size(meta);

	iv = sedcli_meta_get_iv_addr(meta);
	iv_size = sedcli_meta_get_iv_size(meta);

	enc_dek = sedcli_meta_get_enc_dek_addr(meta);
	enc_dek_size = sedcli_meta_get_enc_dek_size(meta);

	tag = sedcli_meta_get_tag_addr(meta);
	tag_size = sedcli_meta_get_tag_size(meta);

	auth_len = (enc_dek - (uint8_t *) meta);

	status = sed_kmip_init(ctx, conf_stat_file->kmip_ip,
			       conf_stat_file->kmip_port,
			       conf_stat_file->client_cert_path,
			       conf_stat_file->client_key_path,
			       conf_stat_file->ca_cert_path);

	if (status == -1) {
		sedcli_printf(LOG_ERR, "Can't initialize KMIP connection\n");
		ret = -1;
		goto deinit;
	}

	status = sed_kmip_connect(ctx);
	if (status) {
		sedcli_printf(LOG_ERR, "Can't connect to KMIP\n");
		ret = -1;
		goto deinit;
	}

	status = sed_kmip_get_platform_key(ctx, (char *) pek_id, pek_id_size,
					   (char **) &pek, &pek_size);
	if (status) {
		sedcli_printf(LOG_ERR, "Can't get PEK from KMIP\n");
		ret = -1;
		goto deinit;
	}

	status = decrypt_dek(enc_dek, enc_dek_size, (uint8_t *) meta, auth_len,
			     dek_key->key, SED_MAX_KEY_LEN, pek, pek_size,
			     iv, iv_size, tag, tag_size);
	if (status != SED_MAX_KEY_LEN) {
		sedcli_printf(LOG_ERR, "Error while decrypting DEK key\n");
		ret = -1;
		goto deinit;
	}
	dek_key->len = status;

deinit:
	sed_kmip_deinit(ctx);

	if (meta)
		sedcli_metadata_free_buffer(meta);

	if (pek)
		free(pek);

	if (ctx)
		free(ctx);

	return ret;
}

static int handle_backup(void)
{
	int ret = 0, status, offset;
	struct sed_key *key = NULL; /* [0] - DEK key, [1] - key derived from password */
	uint8_t *buffer = NULL, *tag = NULL, *salt = NULL, *enc_key = NULL,
		*iv = NULL;
	uint8_t buffer_len;
	struct sed_device *sed_dev = NULL;

	status = sed_init(&sed_dev, dev_path, true);
	if (status) {
		ret = -1;
		goto deinit;
	}

	key = alloc_locked_buffer(2 * sizeof(*key));
	if (!key) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto deinit;
	}

	status = read_key_from_datastore(sed_dev, &key[0]);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while accessing datastore\n");
		goto deinit;
	}

	buffer_len = SED_MAX_KEY_LEN + TAG_SIZE + SALT_SIZE + IV_SIZE;
	buffer = malloc(buffer_len);
	if (!buffer) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto deinit;
	}

	offset = 0;
	salt = &buffer[offset];
	offset += SALT_SIZE;

	iv = &buffer[offset];
	offset += IV_SIZE;

	enc_key = &buffer[offset];
	offset += SED_MAX_KEY_LEN;

	tag = &buffer[offset];

	sedcli_printf(LOG_INFO, "Enter new password for backup file: ");

	ret = get_password(opts->pwd, &opts->pwd_len, BACKUP_FILE_MIN_LEN,
			   BACKUP_FILE_MAX_LEN);
	if (ret) {
		ret = -1;
		goto deinit;
	}

	sedcli_printf(LOG_INFO, "Repeat password: ");

	ret = get_password(opts->repeated_pwd, &opts->repeated_pwd_len,
			   BACKUP_FILE_MIN_LEN, BACKUP_FILE_MAX_LEN);
	if (ret) {
		ret = -1;
		goto deinit;
	}

	if (strncmp(opts->pwd, opts->repeated_pwd, BACKUP_FILE_MAX_LEN)) {
		sedcli_printf(LOG_ERR, "Error: passwords don't match\n");
		ret = -1;
		goto deinit;
	}

	status = get_random_bytes(salt, SALT_SIZE);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while creating salt\n");
		ret = -1;
		goto deinit;
	}

	status = get_random_bytes(iv, IV_SIZE);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while creating IV\n");
		ret = -1;
		goto deinit;
	}

	status = derive_key((uint8_t *)opts->pwd, opts->pwd_len, salt,
			    SALT_SIZE, key[1].key, SED_MAX_KEY_LEN);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while deriving key\n");
		ret = -1;
		goto deinit;
	}

	status = encrypt_dek(key[0].key, SED_MAX_KEY_LEN, NULL, 0, enc_key,
			     SED_MAX_KEY_LEN, key[1].key, SED_MAX_KEY_LEN, iv,
			     IV_SIZE, tag, TAG_SIZE);

	if (status < 0) {
		sedcli_printf(LOG_ERR, "Error while encrypting key\n");
		ret = -1;
		goto deinit;
	}

	status = write_to_file(backup_file_path, buffer, buffer_len);

	if (status != buffer_len) {
		sedcli_printf(LOG_ERR, "Error while storing encrypted key "
				       "in file\n");
		ret = -1;
		goto deinit;
	}

	sedcli_printf(LOG_INFO, "Backup of DEK key finished. Key written to "
				"file: %s\n", backup_file_path);

deinit:
	if (buffer)
		free(buffer);

	if (key)
		free_locked_buffer(key, 2 * sizeof(*key));

	sed_deinit(sed_dev);

	return ret;
}

static int extract_key_from_backup(struct sed_key *dek_key)
{
	int status, ret = 0, read_buffer_len, offset;
	uint8_t buffer[SED_MAX_KEY_LEN];
	uint8_t read_buffer[SED_MAX_KEY_LEN + TAG_SIZE + SALT_SIZE + IV_SIZE];
	uint8_t *tag, *enc_key, *salt, *key = NULL, *iv;

	read_buffer_len = SALT_SIZE + IV_SIZE + SED_MAX_KEY_LEN + TAG_SIZE;

	read_from_file(backup_file_path, read_buffer, read_buffer_len);

	offset = 0;

	salt = &read_buffer[offset];
	offset += SALT_SIZE;

	iv = &read_buffer[offset];
	offset += IV_SIZE;

	enc_key = &read_buffer[offset];
	offset += SED_MAX_KEY_LEN;

	tag = &read_buffer[offset];

	sedcli_printf(LOG_INFO, "Enter password: ");

	key = alloc_locked_buffer(SED_MAX_KEY_LEN);
	if (!key) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto deinit;
	}

	status = get_password(opts->pwd, &opts->pwd_len, BACKUP_FILE_MIN_LEN,
			      BACKUP_FILE_MAX_LEN);
	if (status) {
		ret = status;
		goto deinit;
	}

	status = derive_key((uint8_t *) opts->pwd, opts->pwd_len, salt,
			    SALT_SIZE, key, SED_MAX_KEY_LEN);
	if (status) {
		sedcli_printf(LOG_ERR, "Error while deriving key\n");
		ret = -1;
		goto deinit;
	}

	status = decrypt_dek(enc_key, SED_MAX_KEY_LEN, NULL, 0, buffer,
			     SED_MAX_KEY_LEN, key, SED_MAX_KEY_LEN,
			     iv, IV_SIZE, tag, TAG_SIZE);
	if (status != SED_MAX_KEY_LEN) {
		sedcli_printf(LOG_ERR, "Error while decrypting DEK\n");
		ret = -1;
		goto deinit;
	}

	memcpy(dek_key->key, buffer, SED_MAX_KEY_LEN);
	dek_key->len = SED_MAX_KEY_LEN;

deinit:
	if (key)
		free_locked_buffer(key, SED_MAX_KEY_LEN);

	return ret;
}

static int handle_lock_unlock(void)
{
	struct sed_device *dev = NULL;
	int ret, status;
	struct sed_key *dek = NULL;

	dek = alloc_locked_buffer(sizeof(*dek));

	if (!dek) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	ret = sed_init(&dev, dev_path, true);
	if (ret) {
		sedcli_printf(LOG_ERR, "Error in initializing the "
				       "dev: %s\n", dev_path);
		goto deinit;
	}

	if (!backup_file_path) {
		status = read_key_from_datastore(dev, dek);
		if (status) {
			sedcli_printf(LOG_ERR, "Error while decrypting "
					       "DEK key\n");
			goto deinit;
		}

		ret = sed_lock_unlock(dev, dek, lock_type);
		if (ret)
			sedcli_printf(LOG_ERR, "Error while unlocking drive\n");
	} else {
		status = extract_key_from_backup(dek);

		if (status) {
			ret = -1;
			goto deinit;
		}

		ret = sed_lock_unlock(dev, dek, lock_type);
		if (ret) {
			sedcli_printf(LOG_ERR, "Error while changing lock "
					       "state\n");
		}

	}

deinit:
	if (dek)
		free_locked_buffer(dek, sizeof(*dek));

	sed_deinit(dev);

	return ret;
}

int main(int argc, char *argv[])
{
	int blocked = 0, status;
	app app_values;

	app_values.name = argv[0];
	app_values.info = "<command> [option...]";
	app_values.title = "sedcli-kmip";
	app_values.doc = "";
	app_values.man = "sedcli-kmip";
	app_values.block = blocked;

	opts = alloc_locked_buffer(sizeof(*opts));

	if (!opts) {
		sedcli_printf(LOG_ERR, "Failed to allocate memory\n");
		return -ENOMEM;
	}
	memset(opts, 0, sizeof(*opts));

	status = args_parse(&app_values, sedcli_commands, argc, argv);

	free_locked_buffer(opts, sizeof(*opts));

	return status;
}
