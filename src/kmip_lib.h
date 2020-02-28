/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _SEDCLI_KMIP_H_
#define _SEDCLI_KMIP_H_

#include <openssl/err.h>
#include <openssl/ssl.h>

#define MAX_IP_SIZE (255)
#define MAX_PORT_SIZE (255)
#define MAX_CLIENT_CERT_PATH_SIZE (255)
#define MAX_CLIENT_KEY_PATH_SIZE (255)
#define MAX_CA_CERT_PATH_SIZE (255)

struct sed_kmip_ctx {
	char ip[MAX_IP_SIZE];
	char port[MAX_PORT_SIZE];
	char client_cert_path[MAX_CLIENT_CERT_PATH_SIZE];
	char client_key_path[MAX_CLIENT_KEY_PATH_SIZE];
	char ca_cert_path[MAX_CA_CERT_PATH_SIZE];

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *bio;
};

int sed_kmip_init(struct sed_kmip_ctx *ctx, char *ip, char *port,
		  char *client_cert_path, char *client_key_path,
		  char *ca_cert_path);

int sed_kmip_connect(struct sed_kmip_ctx *ctx);

int sed_kmip_gen_platform_key(struct sed_kmip_ctx *ctx,
			      char **pek_id, int *pek_id_size);

int sed_kmip_get_platform_key(struct sed_kmip_ctx *ctx,
			      char *key_id, int key_id_size,
			      char **key, int *key_size);

void sed_kmip_deinit(struct sed_kmip_ctx *ctx);

#endif /* _SEDCLI_KMIP_H_ */
