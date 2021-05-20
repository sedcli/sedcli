/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "opal_parser.h"
#include "sedcli_log.h"

#define msb64(x) (64 - __builtin_clzll(x))

#define MAX_SHORT_ATOM_DATA_LEN         16
#define MAX_MEDIUM_ATOM_DATA_LEN        2048
#define MAX_LONG_ATOM_DATA_LEN          16777216

struct _opal_token {
	struct opal_token token;
	struct _opal_token *next;
};

/* Token data storage  */
static struct _opal_token free_token_list = { .next = NULL };
static struct _opal_token *token_storage = NULL;

static int div_roundup(int n, int d)
{
	if (n % d == 0)
		return (n / d);
	return (n / d + 1);
}

int opal_parser_init(void)
{
	int i;

	token_storage = (struct _opal_token *) malloc(sizeof(*token_storage) * OPAL_MAX_TOKENS);

	if (token_storage == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < OPAL_MAX_TOKENS; i++) {
		token_storage[i].next = free_token_list.next;
		token_storage[i].token.priv = &token_storage[i];
		free_token_list.next = &token_storage[i];
	}

	return 0;
}

void opal_parser_deinit(void)
{
	if (token_storage != NULL) {
		free(token_storage);
		token_storage = NULL;
	}
	free_token_list.next = NULL;
}

static int append_short_atom_bytes_header(uint8_t *buf, size_t len, int data_len)
{
	uint8_t val = 0;

	if (len >= 1) {
		val |= OPAL_ATOM_SHORT_CODE;
		val |= OPAL_ATOM_SHORT_BYTESTRING;
		val |= 0;
		val |= data_len & OPAL_ATOM_SHORT_LEN_MASK;

		buf[0] = val;

		return 1;
	}

	return 0;
}

static int append_short_atom_uint_header(uint8_t *buf, size_t len, int data_len)
{
	uint8_t val = 0;

	if (len >= 1) {
		val |= OPAL_ATOM_SHORT_CODE;
		val |= 0;
		val |= 0;
		val |= data_len & OPAL_ATOM_SHORT_LEN_MASK;

		buf[0] = val;

		return 1;
	}

	return 0;
}

static int append_medium_atom_bytes_header(uint8_t *buf, size_t len, int data_len)
{
	uint8_t val = 0;

	if (len >= 2) {
		val = OPAL_ATOM_MEDIUM_CODE;
		val |= OPAL_ATOM_MEDIUM_BYTESTRING;
		val |= 0;
		val |= (data_len >> 8) & OPAL_ATOM_MEDIUM_LEN_MASK;

		buf[0] = val;
		buf[1] = data_len;

		return 2;
	}

	return 0;
}

static int append_long_atom_bytes_header(uint8_t *buf, size_t len, int data_len)
{
	uint8_t val = 0;

	if (len >= 4) {
		val = OPAL_ATOM_LONG_CODE;
		val |= OPAL_ATOM_LONG_BYTESTRING;

		buf[0] = val;
		buf[1] = (data_len >> 16) & 0xff;
		buf[2] = (data_len >> 8) & 0xff;
		buf[3] = (data_len >> 0) & 0xff;

		return 4;
	}

	return 0;
}

int append_u8(uint8_t *buf, size_t len, uint8_t val)
{
	if (len >= 1) {
		buf[0] = val;
		return 1;
	}
	else
		return 0;
}

/*assumption is that val is Little Endian*/
int append_u64(uint8_t *buf, size_t len, uint64_t val)
{
	int ret = 0;

	/* number fits into tiny atom */
	if (!(val & ~OPAL_ATOM_TINY_DATA_MASK)) {
		if (len >= 1) {
			buf[0] = val;
		 	ret += 1;
		}
	/* number fits into short atom */
	}
	else {
		int bytes_no = 0;

		/* round up number of bytes needed */
		bytes_no = div_roundup(val ? msb64(val) : 0, 8);

		if (len >= (bytes_no + 1)) {
			ret += append_short_atom_uint_header(buf, len, bytes_no);
			/* put number into buffer as big endian */
			while (bytes_no--) {
				ret += append_u8(buf + ret, len - ret, val >>
						(bytes_no * 8));
			}
		}
	}

	return ret;
}

int append_bytes(uint8_t *buf, size_t len, const uint8_t *src, int src_len)
{
	int ret = 0;

	assert(src_len < MAX_LONG_ATOM_DATA_LEN);

	/* data fits into opal short atom */
	if (src_len < MAX_SHORT_ATOM_DATA_LEN) {
		if (len >= src_len + 1)
			ret += append_short_atom_bytes_header(buf, len, src_len);

	/* data fits into opal medium atom */
	} else if (src_len < MAX_MEDIUM_ATOM_DATA_LEN) {
		if (len >= src_len + 2)
			ret += append_medium_atom_bytes_header(buf, len, src_len);

	/* data fits into opal long atom */
	} else if (src_len < MAX_LONG_ATOM_DATA_LEN) {
		if (len >= src_len + 4)
			ret += append_long_atom_bytes_header(buf, len, src_len);
	}

	memcpy(buf + ret, src, src_len);
	ret += src_len;

	return ret;
}

static void parse_tiny_token(struct opal_token *token, uint8_t curr_byte)
{
	token->width = OPAL_WIDTH_TINY;
	token->len = 1;

	if ((curr_byte >> 6) & 1)
		token->type = OPAL_DTA_TOKENID_SINT;
	else {
		token->type = OPAL_DTA_TOKENID_UINT;
		token->vals.uint = curr_byte & 0x3f;
	}
}

static size_t parse_short_token(struct opal_token *token, const uint8_t *buf, int len)
{
	uint8_t curr_byte;
	int i, idx = 0;

	curr_byte = buf[0];
	token->vals.uint = 0;
	token->width = OPAL_WIDTH_SHORT;
	token->len = (curr_byte & OPAL_ATOM_SHORT_LEN_MASK) + 1;
	token->pos = buf;

	if (len - token->len <= 0)
		return -1;

	if (curr_byte & OPAL_ATOM_SHORT_BYTESTRING)
		token->type = OPAL_DTA_TOKENID_BYTESTRING;
	else {
		if (curr_byte & OPAL_ATOM_SHORT_SIGNED)
			token->type = OPAL_DTA_TOKENID_SINT;
		else {
			token->type = OPAL_DTA_TOKENID_UINT;
			if (token->len < 9) {
				for (i = token->len - 1; i > 0; i--) {
					token->vals.uint |=
						(uint64_t)buf[i] << (8 * idx);
					idx++;
				}
			}
			else {
				SEDCLI_DEBUG_MSG("unsigned integer exceeds 8 bytes.\n");
				return -EINVAL;
			}
		}
	}

	return token->len;
}

static size_t parse_medium_token(struct opal_token *token, const uint8_t *buf, int len)
{
	token->width = OPAL_WIDTH_MEDIUM;
	token->len = (((buf[0] & OPAL_ATOM_MEDIUM_LEN_MASK) << 8) | buf[1]) + 2;
	token->pos = buf;

	if (len - token->len <= 0)
		return -1;

	if (buf[0] & OPAL_ATOM_MEDIUM_BYTESTRING)
		token->type = OPAL_DTA_TOKENID_BYTESTRING;
	else if (buf[0] & OPAL_ATOM_MEDIUM_SIGNED)
		token->type = OPAL_DTA_TOKENID_SINT;
	else
		token->type = OPAL_DTA_TOKENID_UINT;

	return token->len;
}

static size_t parse_long_token(struct opal_token *token, const uint8_t *buf, int len)
{
	token->width = OPAL_WIDTH_LONG;
	token->len = ((buf[1] << 16) | (buf[2] << 8) | buf[3]) + 4;
	token->pos = buf;

	if (len - token->len <= 0) {
		return -1;
	}

	/* Check if the token is a byte_string or unsigned or signed */
	if (buf[0] & OPAL_ATOM_LONG_BYTESTRING)
		token->type = OPAL_DTA_TOKENID_BYTESTRING;
	else if (buf[0] & OPAL_ATOM_LONG_SIGNED)
		token->type = OPAL_DTA_TOKENID_SINT;
	else
		token->type = OPAL_DTA_TOKENID_UINT;

	return token->len;
}

static struct opal_token *alloc_token(struct _opal_token *free_head)
{
	struct _opal_token *ret;

	ret = free_head->next;
	if (ret == NULL)
		return NULL;

	free_head->next = ret->next;
	ret->next = NULL;

	return &ret->token;
}

static void dealloc_token(struct _opal_token *free_head, struct opal_token *item)
{
	struct _opal_token *ret_item = (struct _opal_token *) item->priv;

	ret_item->next = free_head->next;
	free_head->next = ret_item;
}

static void opal_put_token(struct opal_token *token)
{
	dealloc_token(&free_token_list, token);
}

void opal_put_all_tokens(struct opal_token **tokens, int *len)
{
	int i;

	for (i = 0; i < *len; i++) {
		if(tokens[i] != NULL) {
			opal_put_token(tokens[i]);
			tokens[i] = NULL;
		}
	}
	*len = 0;
}

/* Assumptions:
 * 1. TCG reserved tokens are ignored,
 * 2. Buffer pointer "pos" points to begining of the token
 * 3. Last position in buffer is returned in the last parameter
 * 4. NULL is returned if buffer is too small
 */
static struct opal_token *opal_get_next_token(uint8_t *buf, int len, int *pos)
{
	struct opal_token *token;
	uint8_t curr_byte;
	int offset = 0, done;
	size_t status;

	token = alloc_token(&free_token_list);
	if (token == NULL) {
		return NULL;
	}

	offset = *pos;

	/* iterate until non-empty and non-reserved token has been found */
	done = 0;
	while (!done) {
		if ((len - offset) <= 0) {
			*pos = offset;
			return NULL;
		}

		curr_byte = buf[0];
		done = 1;

		switch (curr_byte) {
		case 0x00 ... 0x7F:
			parse_tiny_token(token, curr_byte);
			token->pos = buf;
			offset++;
			break;
		case 0x80 ... 0xBF:
			status = parse_short_token(token, buf, len - offset);
			if (status > 0)
				offset += status;
			else
				return NULL;

			break;
		case 0xC0 ... 0xDF:
			status = parse_medium_token(token, buf, len - offset);
			if (status > 0)
				offset += status;
			else
				return NULL;
			break;
		case 0xE0 ... 0xE3:
			status = parse_long_token(token, buf, len - offset);
			if (status > 0)
				offset += status;
			else
				return NULL;

			break;
		default:
			token->width = OPAL_WIDTH_TOKEN;
			/* the actual token is returned */
			token->type = OPAL_DTA_TOKENID_TOKEN;

			token->len = 1;
			token->pos = buf;
			offset++;
			break;
		}
	}

	*pos = offset;

	return token;
}

int opal_parse_data_payload(uint8_t *buf, size_t len, struct opal_parsed_payload *payload)
{
	struct opal_token *token;
	int offset = 0, i = 0;

	payload->len = 0;
	while ((token = opal_get_next_token(buf + offset, len, &offset)) != NULL) {
		payload->tokens[i] = &(*token);
		i++;
	}
	/* TODO: check if any errors while parsing data payload */
	if (i == 0) {
		SEDCLI_DEBUG_MSG("The no. of tokens is 0 and the response can't be parsed.\n");
		return -EINVAL;
	}

	payload->len = i;

	return i;
}
