/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _SEDCLI_CRYPTO_LIB_H_
#define _SEDCLI_CRYPTO_LIB_H_

#define SALT_SIZE (16)
#define TAG_SIZE (16)
#define IV_SIZE (16)

int derive_key(uint8_t *buffer, int buffer_len, uint8_t *salt, int salt_len,
	       uint8_t *out, int out_len);

int get_random_bytes(uint8_t *buffer, size_t bytes);

int encrypt_dek(uint8_t *plain, int plain_size,
		uint8_t *auth_data, int auth_data_len,
		uint8_t *cipher, int cipher_size,
		uint8_t *key, int key_size,
		uint8_t *iv, int iv_size,
		uint8_t *tag, int tag_size);

int decrypt_dek(uint8_t *cipher, int cipher_size,
		uint8_t *auth_data, int auth_data_len,
		uint8_t *plain, int plain_size,
		uint8_t *key, int key_size,
		uint8_t *iv, int iv_size,
		uint8_t *tag, int tag_size);

#endif /* _SEDCLI_CRYPTO_LIB_H_ */
