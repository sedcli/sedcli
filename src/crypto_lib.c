/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <libsed.h>

#include "crypto_lib.h"

#define CRYPTO_BS (16)

int get_random_bytes(uint8_t *buffer, size_t bytes_no)
{
	if (RAND_priv_bytes(buffer, bytes_no))
		return 0;
	else
		return -EOPNOTSUPP;
}

int derive_key(uint8_t *buffer, int buffer_len, uint8_t *salt, int salt_len,
	       uint8_t *out, int out_len)
{
	int status;
	int iterations = 10000;

	status = PKCS5_PBKDF2_HMAC((char *) buffer, buffer_len, salt, salt_len,
				   iterations, EVP_sha512(), out_len, out);

	if (status == 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

/*
 * Crypto_block_size is 16B, key is 32B, IV is 16B, DEK key (plain text) is 32B.
 * Padding is disabled, so the encrypted DEK key (cipher) size should be 32B
 */
int encrypt_dek(uint8_t *plain, int plain_size,
		uint8_t *auth_data, int auth_data_len,
		uint8_t *cipher, int cipher_size,
		uint8_t *key, int key_size,
		uint8_t *iv, int iv_size,
		uint8_t *tag, int tag_size)
{
	int status, len, total_bytes = 0;
	EVP_CIPHER_CTX *ctx;

	/* Perform sanity checks for provided input */

	if (plain_size % CRYPTO_BS != 0 || iv_size != CRYPTO_BS ||
	    cipher_size != plain_size || key_size != SED_MAX_KEY_LEN ||
	    tag_size < TAG_SIZE)
		return -EINVAL;

	ctx = EVP_CIPHER_CTX_new();

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (auth_data_len > 0) {
		/* Provide additional authenticated data for encryption */
		status = EVP_EncryptUpdate(ctx, NULL, &len, auth_data,
					   auth_data_len);
		if (status != 1) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	status = EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_size);
	total_bytes += len;

	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_EncryptFinal_ex(ctx, &cipher[len], &len);
	total_bytes += len;

	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, tag);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	EVP_CIPHER_CTX_free(ctx);

	return total_bytes;
}

/*
 * Crypto_block_size is 16B, key is 32B, IV is 16B, encrypted DEK key (cipher
 * text) is 32B. Padding is disabled, so the plain text DEK key size should be
 * 32B.
 */
int decrypt_dek(uint8_t *cipher, int cipher_size,
		uint8_t *auth_data, int auth_data_len,
		uint8_t *plain, int plain_size,
		uint8_t *key, int key_size,
		uint8_t *iv, int iv_size,
		uint8_t *tag, int tag_size)
{
	int status, len, total_bytes = 0;
	EVP_CIPHER_CTX *ctx;

	/* Perform sanity checks for provided input */
	if (plain_size % CRYPTO_BS != 0 || iv_size != CRYPTO_BS ||
	    cipher_size != plain_size || key_size != SED_MAX_KEY_LEN ||
	    tag_size < TAG_SIZE)
		return -EINVAL;

	ctx = EVP_CIPHER_CTX_new();

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (auth_data_len > 0) {
		/* Provide additional authenticated data for encryption */
		status = EVP_DecryptUpdate(ctx, NULL, &len, auth_data,
					   auth_data_len);
		if (status !=  1) {
			ERR_print_errors_fp(stderr);
			return -1;
		}
	}

	status = EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_size);
	total_bytes = len;

	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, tag);
	if (status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	status = EVP_DecryptFinal_ex(ctx, &plain[len], &len);

	EVP_CIPHER_CTX_free(ctx);

	if (status > 0) {
		total_bytes += len;
		return total_bytes;
	}

	return -1;
}

