/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _CONFIG_FILE_H_
#define _CONFIG_FILE_H_

#define MAX_PATH_LEN (4096)
#define MAX_IP_LEN (255)
#define MAX_PORT_LEN (255)

#define MAX_PEK_ID_LEN (255)

#define SEDCLI_DEF_STAT_CONFIG_FILE "/etc/sedcli/sedcli.conf"
#define SEDCLI_BKP_STAT_CONFIG_FILE "../etc/sedcli/sedcli.conf"

#define SEDCLI_DEF_DYN_CONFIG_FILE "/etc/sedcli/sedcli_kmip"
#define SEDCLI_BKP_DYN_CONFIG_FILE "../etc/sedcli/sedcli_kmip"

struct sedcli_stat_conf {
	char kmip_ip[MAX_IP_LEN];
	char kmip_port[MAX_PORT_LEN];

	char client_cert_path[MAX_PATH_LEN];
	char client_key_path[MAX_PATH_LEN];

	char ca_cert_path[MAX_PATH_LEN];
};

struct sedcli_dyn_conf {
	char pek_id[MAX_PEK_ID_LEN];
	int pek_id_size;
};

int read_stat_config(struct sedcli_stat_conf *conf);

int read_dyn_config(struct sedcli_dyn_conf *conf);

int write_dyn_conf(const char *data, int data_size);

#endif /* _CONFIG_FILE_H_ */
