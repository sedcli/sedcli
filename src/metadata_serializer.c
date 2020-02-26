#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "metadata_serializer.h"

struct sedcli_metadata *sedcli_metadata_alloc_buffer()
{
	uint8_t *buffer;

	buffer = malloc(SEDCLI_METADATA_SIZE);
	if (!buffer)
		return NULL;

	memset(buffer, 0, SEDCLI_METADATA_SIZE);

	return (struct sedcli_metadata *)buffer;
}

void sedcli_metadata_free_buffer(struct sedcli_metadata *buffer)
{
	if (!buffer)
		return;

	memset(buffer, 0, SEDCLI_METADATA_SIZE);
	free(buffer);
}

void sedcli_metadata_init(struct sedcli_metadata *meta, uint32_t pek_id_size,
		uint32_t iv_size, uint32_t enc_dek_size, uint32_t tag_size)
{
	if (!meta)
		return;

	meta->magic_num = htole64(SEDCLI_META_MAGIC);
	meta->version = htole32(SEDCLI_META_VERSION);

	meta->pek_id_size = htole32(pek_id_size);
	meta->iv_size = htole32(iv_size);
	meta->enc_dek_size = htole32(enc_dek_size);
	meta->tag_size = htole32(tag_size);
}

uint8_t *sedcli_meta_get_pek_id_addr(struct sedcli_metadata *meta)
{
	return meta == NULL ? NULL : meta->data;
}

uint8_t *sedcli_meta_get_iv_addr(struct sedcli_metadata *meta)
{
	uint32_t offset = 0;

	if (!meta)
		return NULL;

	offset += sedcli_meta_get_pek_id_size(meta);

	return &meta->data[offset];
}

uint8_t *sedcli_meta_get_enc_dek_addr(struct sedcli_metadata *meta)
{
	uint32_t offset = 0;

	if (!meta)
		return NULL;

	offset += sedcli_meta_get_pek_id_size(meta);
	offset += sedcli_meta_get_iv_size(meta);

	return &meta->data[offset];
}

uint8_t *sedcli_meta_get_tag_addr(struct sedcli_metadata *meta)
{
	uint32_t offset = 0;

	if (!meta)
		return NULL;

	offset += sedcli_meta_get_pek_id_size(meta);
	offset += sedcli_meta_get_iv_size(meta);
	offset += sedcli_meta_get_enc_dek_size(meta);

	return &meta->data[offset];
}

uint32_t sedcli_meta_get_pek_id_size(struct sedcli_metadata *meta)
{
	return meta != NULL ? le32toh(meta->pek_id_size) : 0;
}

void sedcli_meta_set_pek_id_size(struct sedcli_metadata *meta, uint32_t pek_id_size)
{
	if (!meta)
		return;

	meta->pek_id_size = htole32(pek_id_size);
}

uint32_t sedcli_meta_get_iv_size(struct sedcli_metadata *meta)
{
	return meta != NULL ? le32toh(meta->iv_size) : 0;
}

void sedcli_meta_set_iv_size(struct sedcli_metadata *meta, uint32_t iv_size)
{
	if (!meta)
		return ;

	meta->iv_size = htole32(iv_size);
}

uint32_t sedcli_meta_get_enc_dek_size(struct sedcli_metadata *meta)
{
	return meta != NULL ? le32toh(meta->enc_dek_size) : 0;
}

void sedcli_meta_set_enc_dek_size(struct sedcli_metadata *meta, uint32_t enc_dek_size)
{
	if (!meta)
		return ;

	meta->enc_dek_size = htole32(enc_dek_size);
}

uint32_t sedcli_meta_get_tag_size(struct sedcli_metadata *meta)
{
	return meta != NULL ? le32toh(meta->tag_size) : 0;
}

void sedcli_meta_set_tag_size(struct sedcli_metadata *meta, uint32_t tag_size)
{
	if (!meta)
		return ;

	meta->tag_size = htole32(tag_size);
}

