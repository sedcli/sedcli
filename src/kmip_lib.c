/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <string.h>

#include <sys/syslog.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <kmip_bio.h>

#include "argp.h"
#include "kmip_lib.h"
#include "lib/sedcli_log.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

extern sedcli_printf_t sedcli_printf;

/* Use 256 bit key for symmetric encryption and decryption */
static enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
static int32 length = 256;
static int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;

static Attribute attribs[] = {
	{ .type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM, .value = &algorithm, .index = KMIP_UNSET },
	{ .type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH, .value = &length, .index = KMIP_UNSET },
	{ .type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK, .value = &mask, .index = KMIP_UNSET },
};

static TemplateAttribute templ_attr = {
	.attributes = attribs,
	.attribute_count = ARRAY_SIZE(attribs)
};

int sed_kmip_init(struct sed_kmip_ctx *ctx, char *ip, char *port,
		  char *client_cert_path, char *client_key_path,
		  char *ca_cert_path)
{
	int status;

	memset(ctx, 0, sizeof(*ctx));

	memcpy(ctx->ip, ip, strnlen(ip, MAX_IP_SIZE));
	memcpy(ctx->port, port, strnlen(port, MAX_PORT_SIZE));
	memcpy(ctx->client_cert_path, client_cert_path,
	       strnlen(client_cert_path, MAX_CLIENT_CERT_PATH_SIZE));
	memcpy(ctx->client_key_path, client_key_path,
	       strnlen(client_key_path, MAX_CLIENT_KEY_PATH_SIZE));
	memcpy(ctx->ca_cert_path, ca_cert_path,
	       strnlen(ca_cert_path, MAX_CA_CERT_PATH_SIZE));

	OPENSSL_init_ssl(0, NULL);
	ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());

	status = SSL_CTX_use_certificate_file(ctx->ssl_ctx,
					      ctx->client_cert_path,
					      SSL_FILETYPE_PEM);
	if (status != 1) {
		sedcli_printf(LOG_ERR, "Loading the client certificate "
					      "failed\n");
		goto error;
	}

	status = SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->client_key_path,
					     SSL_FILETYPE_PEM);
	if (status != 1) {
		sedcli_printf(LOG_ERR, "Loading the client key failed\n");
		goto error;
	}

	status = SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->ca_cert_path,
					       NULL);
	if (status != 1) {
		sedcli_printf(LOG_ERR, "Loading the CA file failed\n");
		goto error;
	}

	return status;

error:
	ERR_print_errors_fp(stderr);
	sed_kmip_deinit(ctx);

	return -ENOENT;
}

void sed_kmip_deinit(struct sed_kmip_ctx *ctx)
{
	if (ctx->bio) {
		BIO_free_all(ctx->bio);
		ctx->bio = NULL;
	}

	if (ctx->ssl_ctx) {
		SSL_CTX_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
	}

	if (ctx->ssl)
		ctx->ssl = NULL;
}

int sed_kmip_connect(struct sed_kmip_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	ctx->bio = BIO_new_ssl_connect(ctx->ssl_ctx);
	BIO_get_ssl(ctx->bio, &ctx->ssl);

	if (!ctx->ssl) {
		sedcli_printf(LOG_ERR, "Can't locate SSL pointer\n");
		goto error;
	}

	/* No retries */
	SSL_set_mode(ctx->ssl, SSL_MODE_AUTO_RETRY);

	/* Setup address */
	BIO_set_conn_hostname(ctx->bio, ctx->ip);
	BIO_set_conn_port(ctx->bio, ctx->port);

	if (BIO_do_connect(ctx->bio) <= 0) {
		sedcli_printf(LOG_ERR, "Error connecting to KMIP server\n");
		goto error;
	}

	return 0;

error:
	ERR_print_errors_fp(stderr);
	sed_kmip_deinit(ctx);
	return -ECONNREFUSED;
}

int sed_kmip_gen_platform_key(struct sed_kmip_ctx *ctx,
			      char **pek_id, int *pek_id_size)
{
	int result;

	if (!ctx || !pek_id || !pek_id_size)
		return -EINVAL;

	/* Send the request message. */
	result = kmip_bio_create_symmetric_key(ctx->bio, &templ_attr,
					       pek_id, pek_id_size);

	SEDCLI_DEBUG_PARAM("Creating symmetric key finished status=%d "
				   "pek_id=%s\n", result,
				   result == KMIP_STATUS_SUCCESS ? *pek_id : "");

	/* Handle the response results. */
	if (result < 0)
		sedcli_printf(LOG_ERR, "Error while creating new key: %d\n",
			      result);

	return result;
}

int sed_kmip_get_platform_key(struct sed_kmip_ctx *ctx,
			      char *pek_id, int pek_id_size,
			      char **pek, int *pek_size)
{
	int result;

	if (!ctx || !pek_id || !pek_id_size || !pek || !pek_size)
		return -EINVAL;

	/* Send the request message. */
	result = kmip_bio_get_symmetric_key(ctx->bio, pek_id, pek_id_size,
					    pek, pek_size);

	SEDCLI_DEBUG_PARAM("Retrieving symmetric key finished status=%d "
			   "key_size=%d[B]\n", result,
			   result == KMIP_STATUS_SUCCESS ? *pek_size : 0);

	/* Handle the response results. */
	if (result < 0)
		sedcli_printf(LOG_ERR, "Error while retrieving key: %d\n",
			      result);

	return result;
}

