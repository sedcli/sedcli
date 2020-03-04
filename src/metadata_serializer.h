/*
 * Copyright (C) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _SEDCLI_METADATA_H_
#define _SEDCLI_METADATA_H_

#include <stdint.h>

#define SEDCLI_META_MAGIC (0x41494C4344455341) /* "ASEDCLIA" */
#define SEDCLI_META_VERSION 0X01
#define SEDCLI_META_HEADER_SIZE (sizeof(uint64_t) + (4 * sizeof(uint32_t)))
#define SEDCLI_METADATA_SIZE (512)

struct sedcli_metadata {
	uint64_t magic_num; /* 8B size */
	uint32_t version; /* 4B size */
	uint32_t pek_id_size; /* 4B size */
	uint32_t iv_size; /* 4B size */
	uint32_t enc_dek_size; /* 4B size */
	uint32_t tag_size; /* 4B size */
	uint8_t data[]; /* Data contains: pek_id, IV, enc_key, tag remaining piece
	is filled with all-zeroes */
};

struct sedcli_metadata *sedcli_metadata_alloc_buffer();

void sedcli_metadata_free_buffer(struct sedcli_metadata *buffer);

void sedcli_metadata_init(struct sedcli_metadata *meta, uint32_t pek_id_size,
		uint32_t iv_size, uint32_t enc_dek_size, uint32_t tag_size);

uint32_t sedcli_meta_get_pek_id_size(struct sedcli_metadata *meta);

void sedcli_meta_set_pek_id_size(struct sedcli_metadata *meta, uint32_t pek_id_size);

uint32_t sedcli_meta_get_iv_size(struct sedcli_metadata *meta);

void sedcli_meta_set_iv_size(struct sedcli_metadata *meta, uint32_t iv_size);

uint32_t sedcli_meta_get_enc_dek_size(struct sedcli_metadata *meta);

void sedcli_meta_set_enc_dek_size(struct sedcli_metadata *meta, uint32_t enc_dek_size);

uint32_t sedcli_meta_get_tag_size(struct sedcli_metadata *meta);

void sedcli_meta_set_tag_size(struct sedcli_metadata *meta, uint32_t tag_size);

uint8_t *sedcli_meta_get_pek_id_addr(struct sedcli_metadata *meta);

uint8_t *sedcli_meta_get_iv_addr(struct sedcli_metadata *meta);

uint8_t *sedcli_meta_get_enc_dek_addr(struct sedcli_metadata *meta);

uint8_t *sedcli_meta_get_tag_addr(struct sedcli_metadata *meta);

#endif /* _SEDCLI_METADATA_H_ */
