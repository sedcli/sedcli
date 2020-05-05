/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _OPAL_PARSER_H_
#define _OPAL_PARSER_H_

#define OPAL_MAX_TOKENS 64
#define OPAL_MAX_LRS 9

#define OPAL_ATOM_TINY_CODE 0X00
#define OPAL_ATOM_TINY_DATA_MASK 0x3F
#define OPAL_ATOM_TINY_SIGNED 0x40

#define OPAL_ATOM_SHORT_CODE 0x80
#define OPAL_ATOM_SHORT_LEN_MASK 0x0F
#define OPAL_ATOM_SHORT_SIGNED 0x10
#define OPAL_ATOM_SHORT_BYTESTRING 0x20

#define OPAL_ATOM_MEDIUM_CODE 0xC0
#define OPAL_ATOM_MEDIUM_LEN_MASK 0x07
#define OPAL_ATOM_MEDIUM_SIGNED 0x8
#define OPAL_ATOM_MEDIUM_BYTESTRING 0x10

#define OPAL_ATOM_LONG_CODE 0xe0
#define OPAL_ATOM_LONG_SIGNED 0x1
#define OPAL_ATOM_LONG_BYTESTRING 0x2

#define OPAL_U8 (1)
#define OPAL_U64 (2)
#define OPAL_BYTES (3)

enum opal_atom_width {
	OPAL_WIDTH_TINY,
	OPAL_WIDTH_SHORT,
	OPAL_WIDTH_MEDIUM,
	OPAL_WIDTH_LONG,
	OPAL_WIDTH_TOKEN
};

enum opal_token_type {
	OPAL_DTA_TOKENID_BYTESTRING = 0xE0,
	OPAL_DTA_TOKENID_SINT = 0xE1,
	OPAL_DTA_TOKENID_UINT = 0xE2,
	OPAL_DTA_TOKENID_TOKEN = 0xE3, /* actual token is returned */
	OPAL_DTA_TOKENID_INVALID = 0X0
};

enum opal_mbr {
	OPAL_MBR_ENABLE = 0x00,
	OPAL_MBR_DISABLE = 0x01,
};

enum opal_user {
	OPAL_ADMIN1 = 0x0,
	OPAL_USER1 = 0x01,
	OPAL_USER2 = 0x02,
	OPAL_USER3 = 0x03,
	OPAL_USER4 = 0x04,
	OPAL_USER5 = 0x05,
	OPAL_USER6 = 0x06,
	OPAL_USER7 = 0x07,
	OPAL_USER8 = 0x08,
	OPAL_USER9 = 0x09,
};

enum opal_lock_state {
	OPAL_RO = 0x01, /* 0001 */
	OPAL_RW = 0x02, /* 0010 */
	OPAL_LK = 0x04, /* 0100 */
};

struct opal_token {
	void *priv;
	int len;
	const uint8_t *pos;
	enum opal_atom_width width;
	enum opal_token_type type;
	union {
		int64_t sint;
		uint64_t uint;
	} vals;
};

struct opal_parsed_payload {
	struct opal_token *tokens[OPAL_MAX_TOKENS];
	int len;
};

int opal_parser_init(void);
void opal_parser_deinit(void);

int append_u8(uint8_t *buf, size_t len, uint8_t val);
int append_u64(uint8_t *buf, size_t len, uint64_t val);
int append_bytes(uint8_t *buf, size_t len, const uint8_t *src, int src_len);

int opal_parse_data_payload(uint8_t *buf, size_t len, struct opal_parsed_payload *payload);
void opal_put_all_tokens(struct opal_token **tokens, int *len);

#endif /* _OPAL_PARSER_H_ */
