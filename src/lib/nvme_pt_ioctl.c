/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <linux/fs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include "nvme_pt_ioctl.h"
#include "nvme_access.h"
#include "sed_util.h"
#include "sedcli_log.h"
#include "opal_parser.h"

#define OPAL_FEAT_TPER       0x0001
#define OPAL_FEAT_LOCKING    0x0002
#define OPAL_FEAT_GEOMETRY   0x0003
#define OPAL_FEAT_DATASTORE  0x0202
#define OPAL_FEAT_SUM        0x0201
#define OPAL_FEAT_OPALV100   0x0200
#define OPAL_FEAT_OPALV200   0x0203
#define OPAL_FEAT_BLOCKSID   0x0402
#define OPAL_FEAT_CNL        0x0403

#define SUM_SELECTION_LIST   0x060000

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MIN(x,y)  (((x - y) >> 63) & 1) ? x : y

#define MIN_IO_BUFFER_LEN 2048

/* #define TPer property name strings here */
#define MCPS "MaxComPacketSize"

struct opal_device {
	uint16_t comid;

	uint8_t *req_buf;
	uint8_t *resp_buf;
	uint64_t req_buf_size;
	uint64_t resp_buf_size;

	struct opal_parsed_payload payload;

	struct {
		uint32_t hsn;
		uint32_t tsn;
	} session;
};

static int sed2opal_map[] = {
	[SED_ADMIN1] = OPAL_ADMIN1_UID,
	[SED_USER1] = OPAL_USER1_UID,
	[SED_USER2] = OPAL_USER2_UID,
	[SED_USER3] = -1,
	[SED_USER4] = -1,
	[SED_USER5] = -1,
	[SED_USER6] = -1,
	[SED_USER7] = -1,
	[SED_USER8] = -1,
	[SED_USER9] = -1,
	[SED_SID] = OPAL_SID_UID,
	[SED_PSID] = OPAL_PSID_UID,
	[SED_ANYBODY] = OPAL_ANYBODY_UID,
};

static uint8_t opal_uid[][OPAL_UID_LENGTH] = {
	[OPAL_SM_UID] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff },
	[OPAL_THISSP_UID] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_ADMIN_SP_UID] =
		{ 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_LOCKING_SP_UID] =
		{ 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02 },
	[OPAL_ENTERPRISE_LOCKING_SP_UID] =
		{ 0x00, 0x00, 0x02, 0x05, 0x00, 0x01, 0x00, 0x01 },
	[OPAL_ANYBODY_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_SID_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06 },
	[OPAL_ADMIN1_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01 },
	[OPAL_USER1_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01 },
	[OPAL_USER2_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x02 },
	[OPAL_PSID_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0xff, 0x01 },
	[OPAL_ENTERPRISE_BANDMASTER0_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x80, 0x01 },
	[OPAL_ENTERPRISE_ERASEMASTER_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x84, 0x01 },

	/* tables UIDs*/
	[OPAL_TABLE_TABLE_UID] =
		{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_LOCKINGRANGE_GLOBAL_UID] =
		{ 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID] =
		{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xE0, 0x01 },
	[OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID] =
		{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xE8, 0x01 },
	[OPAL_MBRCONTROL_UID] =
		{ 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_MBR_UID] =
		{ 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00 },
	[OPAL_AUTHORITY_TABLE_UID] =
		{ 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
	[OPAL_C_PIN_TABLE_UID] =
		{ 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00},
	[OPAL_LOCKING_INFO_TABLE_UID] =
		{ 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01 },
	[OPAL_ENTERPRISE_LOCKING_INFO_TABLE_UID] =
		{ 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00 },
	[OPAL_DATASTORE_UID] =
		{ 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00 },

	/* C_PIN_TABLE object UIDs */
	[OPAL_C_PIN_MSID_UID] =
		{ 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x84, 0x02},
	[OPAL_C_PIN_SID_UID] =
		{ 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01},
	[OPAL_C_PIN_ADMIN1_UID] =
		{ 0x00, 0x00, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x01},

	/* half UID's (only first 4 bytes used) */
	[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] =
		{ 0x00, 0x00, 0x0C, 0x05, 0xff, 0xff, 0xff, 0xff },
	[OPAL_HALF_UID_BOOLEAN_ACE_UID] =
		{ 0x00, 0x00, 0x04, 0x0E, 0xff, 0xff, 0xff, 0xff },

	/* ACE DS UIDs */
	[OPAL_ACE_DS_GET_ALL_UID] =
		{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xfc, 0x00 },
	[OPAL_ACE_DS_SET_ALL_UID] =
		{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xfc, 0x01 },

	/* special value for omitted optional parameter */
	[OPAL_UID_HEXFF_UID] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};

static uint8_t opal_method[][OPAL_UID_LENGTH] = {
	[OPAL_PROPERTIES_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01 },
	[OPAL_STARTSESSION_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02 },
	[OPAL_REVERT_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x02 },
	[OPAL_ACTIVATE_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x03 },
	[OPAL_EGET_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06 },
	[OPAL_ESET_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07 },
	[OPAL_NEXT_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08 },
	[OPAL_EAUTHENTICATE_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0c },
	[OPAL_GETACL_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d },
	[OPAL_GENKEY_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x10 },
	[OPAL_REVERTSP_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x11 },
	[OPAL_GET_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16 },
	[OPAL_SET_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17 },
	[OPAL_AUTHENTICATE_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1c },
	[OPAL_RANDOM_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x06, 0x01 },
	[OPAL_ERASE_METHOD_UID] =
		{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0x03 },
};

struct opal_req_item {
	int type;
	int len;
	union {
		uint8_t byte;
		uint64_t uint;
		const uint8_t *bytes;
	} val;
};

static int opal_dev_discv(struct sed_device *dev);
static int opal_tper_host_prep(struct sed_device *dev);

static int get_opal_auth_uid(enum SED_AUTHORITY auth)
{
	if (auth > ARRAY_SIZE(sed2opal_map)) {
		return -1;
	}

	return sed2opal_map[auth];
}

static void cpy_tper_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_tper, (struct tper_supported_feat *)feat,
		sizeof(struct tper_supported_feat));
}

static void cpy_locking_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_locking, (struct locking_supported_feat *)feat,
		sizeof(struct locking_supported_feat));
}

static void cpy_geometry_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_geo, (struct geometry_supported_feat *)feat,
		sizeof(struct geometry_supported_feat));
}

static void cpy_datastr_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_datastr, (struct datastr_table_supported_feat *)feat,
		sizeof(struct datastr_table_supported_feat));
}

static void cpy_opalv100_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_opalv100, (struct opalv100_supported_feat *)feat,
		sizeof(struct opalv100_supported_feat));
}

static void cpy_blocksid_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_blocksid, (struct blocksid_supported_feat *)feat,
		sizeof(struct blocksid_supported_feat));
}

static void cpy_opalv200_feat(struct sed_opal_level0_discovery *discv,
				void *feat)
{
	memcpy(&discv->sed_opalv200, (struct opalv200_supported_feat *)feat,
		sizeof(struct opalv200_supported_feat));
}

static void cpy_cnl_feat(struct sed_opal_level0_discovery *discv, void *feat)
{
	memcpy(&discv->sed_cnl, (struct cnl_feat *) feat,
			sizeof(discv->sed_cnl));
}

static int opal_level0_disc_pt(struct sed_device *device)
{
	struct opal_l0_feat *curr_feat;
	struct opal_level0_header *header;
	struct opal_level0_feat_desc *desc;
	struct opal_l0_disc *disc_data;
	struct opal_device *dev = device->priv;
	struct sed_opal_level0_discovery *discv = &device->discv.sed_lvl0_discv;
	int fd = device->fd;

	int ret, pos, end, feat_no;
	uint16_t feat_code;
	uint8_t *buffer;

	ret = opal_recv(fd, OPAL_DISCOVERY_COMID, dev->resp_buf,
			dev->resp_buf_size);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in Level 0 Discovery. Returning early\n");
		return ret;
	}

	buffer = dev->resp_buf;

	disc_data = malloc(sizeof(*disc_data));
	if (disc_data == NULL) {
		SEDCLI_DEBUG_MSG("Error in creating memory for disc_data\n");
		return -ENOMEM;
	}
	memset(disc_data, 0, sizeof(*disc_data));

	header = (struct opal_level0_header *) buffer;
	disc_data->rev = be32toh(header->rev);

	/* processing level 0 features */
	pos = 0;
	feat_no = 0;
	pos += sizeof(*header);
	end = be32toh(header->len);

	while (pos < end) {
		desc = (struct opal_level0_feat_desc *) (buffer + pos);
		feat_code = be16toh(desc->code);

		pos += desc->len + 4;

		switch (feat_code) {
		case OPAL_FEAT_TPER:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_tper_feat(discv, &desc->feat.tper.flags);
			discv->feat_avail_flag.feat_tper = 1;

			feat_no++;
			break;
		case OPAL_FEAT_LOCKING:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_locking_feat(discv, &desc->feat.locking.flags);
			discv->feat_avail_flag.feat_locking = 1;

			feat_no++;
			break;
		case OPAL_FEAT_GEOMETRY:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_geometry_feat(discv, &desc->feat.geo);
			discv->feat_avail_flag.feat_geometry = 1;

			feat_no++;
			break;
		case OPAL_FEAT_DATASTORE:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_datastr_feat(discv, &desc->feat.datastr.datastr_tbl);
			discv->feat_avail_flag.feat_datastr_table = 1;

			feat_no++;
			break;
		case OPAL_FEAT_SUM:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			discv->feat_avail_flag.feat_sum = 1;

			feat_no++;
			break;
		case OPAL_FEAT_BLOCKSID:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_blocksid_feat(discv, &desc->feat.blocksid);
			discv->feat_avail_flag.feat_blocksid = 1;

			feat_no++;
			break;
		case OPAL_FEAT_OPALV100:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_opalv100_feat(discv, &desc->feat.opalv100);
			discv->feat_avail_flag.feat_opalv100 = 1;

			feat_no++;
			break;
		case OPAL_FEAT_OPALV200:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_opalv200_feat(discv, &desc->feat.opalv200);
			discv->feat_avail_flag.feat_opalv200 = 1;

			curr_feat->feat.opalv200.base_comid =
				be16toh(desc->feat.opalv200.base_comid);
			disc_data->comid = curr_feat->feat.opalv200.base_comid;

			feat_no++;
			break;
		case OPAL_FEAT_CNL:
			curr_feat = &disc_data->feats[feat_no];
			curr_feat->type = feat_code;
			cpy_cnl_feat(discv, &desc->feat.cnl);
			discv->feat_avail_flag.feat_cnl = 1;

			feat_no++;
			break;
		default:
			break;
		}
	}
	disc_data->feats_size = feat_no;
	dev->comid = disc_data->comid;

	free(disc_data);

	return 0;
}

void opal_deinit_pt(struct sed_device *dev)
{
	if (dev->fd != 0) {
		close(dev->fd);
		dev->fd = 0;
	}

	if (dev->priv != NULL) {
		struct opal_device *opal_dev = dev->priv;

		if (opal_dev->req_buf != NULL) {
			free(opal_dev->req_buf);
			opal_dev->req_buf = NULL;
		}

		free(dev->priv);
		dev->priv = NULL;
	}

	opal_parser_deinit();
}

static uint64_t tper_prop_to_val(struct sed_device *dev, const char *tper_prop_name)
{
	struct sed_tper_properties *tper = &dev->discv.sed_tper_props;

	for (int j = 0; j < NUM_TPER_PROPS; j++) {
		if (strncmp(tper_prop_name, tper->property[j].key_name,
				strlen(tper_prop_name)) == 0)
			return tper->property[j].value;
	}

	SEDCLI_DEBUG_MSG("Invalid TPer property name!\n");

	return -EINVAL;
}

static int resize_io_buf(struct opal_device *dev, uint64_t size)
{
	uint8_t *ptr;

	if (dev == NULL)
		return -EINVAL;

	if (dev->req_buf != NULL)
		free(dev->req_buf);

	/*
	 * Allocate memory for request and response buffers in a
	 * single malloc request and split it later.
	 */
	ptr = malloc(sizeof(*dev->req_buf) * 2 * size);
	if (!ptr)
		return -ENOMEM;
	memset(ptr, 0, sizeof(*ptr) * 2 * size);

	dev->req_buf = &ptr[0];
	dev->resp_buf = &ptr[size];
	dev->req_buf_size = sizeof(*dev->req_buf) * size;
	dev->resp_buf_size = sizeof(*dev->resp_buf) * size;

	return 0;
}

int opal_init_pt(struct sed_device *dev, const char *device_path)
{
	int ret = 0;
	uint64_t max_com_pkt_sz;
	struct opal_device *opal_dev = NULL;

	dev->fd = 0;
	dev->priv = NULL;

	ret = open_dev(device_path);
	if (ret < 0)
		return -ENODEV;

	dev->fd = ret;

	/* Initializing the parser list */
	ret = opal_parser_init();
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in initializing the parser list.\n");
		ret = -EINVAL;
		goto init_deinit;
	}

	opal_dev = malloc(sizeof(*opal_dev));
	if (opal_dev == NULL) {
		SEDCLI_DEBUG_MSG("Unable to allocate memory\n");
		dev->priv = NULL;
		ret = -ENOMEM;
		goto init_deinit;
	}
	memset(opal_dev, 0, sizeof(*opal_dev));
	dev->priv = opal_dev;

	opal_dev->session.tsn = opal_dev->session.hsn = 0;
	opal_dev->req_buf = opal_dev->resp_buf = NULL;

	ret = resize_io_buf(opal_dev, MIN_IO_BUFFER_LEN);
	if (ret)
		goto init_deinit;

	ret = opal_dev_discv(dev);
	if (ret)
		goto init_deinit;

	max_com_pkt_sz = tper_prop_to_val(dev, MCPS);
	if (max_com_pkt_sz == -EINVAL)
		goto init_deinit;

	ret = resize_io_buf(opal_dev, max_com_pkt_sz);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error re-sizing the IO buffer\n");
		return ret;
	}

	SEDCLI_DEBUG_PARAM("The device comid is: %u, MaxComPacketSize = %ld\n",
				opal_dev->comid, max_com_pkt_sz);

init_deinit:
	if(ret)
		opal_deinit_pt(dev);

	return ret;
}

static int opal_dev_discv(struct sed_device *dev)
{
	int ret;

	if (dev == NULL)
		return -EINVAL;

	ret = opal_level0_disc_pt(dev);
	if (ret)
		return ret;

	return opal_tper_host_prep(dev);
}

int opal_dev_discv_info_pt(struct sed_device *dev,
			   struct sed_opal_device_discv *discv)
{
	int ret;

	if (dev == NULL || discv == NULL)
		return -EINVAL;

	ret = opal_dev_discv(dev);
	if (ret)
		return ret;

	memcpy(discv, &dev->discv, sizeof(*discv));

	return 0;
}

static void init_req(struct opal_device *dev)
{
	struct opal_header *header;

	memset(dev->req_buf, 0, dev->req_buf_size);
	header = (struct opal_header*) dev->req_buf;

	header->compacket.ext_comid[0] = dev->comid >> 8;
	header->compacket.ext_comid[1] = dev->comid & 0xFF;
	header->compacket.ext_comid[2] = 0;
	header->compacket.ext_comid[3] = 0;
}

/* Building a Global Locking Range based on the lr value passed by the user */
static int build_lr(uint8_t *uid, size_t len, uint8_t lr)
{
	if (len > OPAL_UID_LENGTH) {
		SEDCLI_DEBUG_MSG("Length Out of Boundary\n");
		return -ERANGE;
	}

	memset(uid, 0, OPAL_UID_LENGTH);
	memcpy(uid, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);

	if (lr == 0)
		return 0;

	uid[5] = LOCKING_RANGE_NON_GLOBAL;
	uid[7] = lr;

	return 0;
}

/* Building a User Locking Range based on the lr value passed by the user */
static int build_locking_usr(uint8_t *buf, size_t len, uint8_t lr)
{
	if(len > OPAL_UID_LENGTH) {
		SEDCLI_DEBUG_MSG("Length out of boundary \n");
		return -ERANGE;
	}

	memcpy(buf, opal_uid[OPAL_USER1_UID], OPAL_UID_LENGTH);
	buf[7] = lr + 1;

	return 0;
}

static int opal_rw_lock(struct opal_device *dev, uint8_t *lr_buff, size_t len,
		uint32_t l_state, uint8_t lr, uint8_t *rl, uint8_t *wl)
{
	init_req(dev);

	if (build_lr(lr_buff, len, lr) < 0)
		return -ERANGE;

	switch (l_state) {
	case SED_RO_ACCESS:
		*rl = 0;
		*wl = 1;
		break;
	case SED_RW_ACCESS:
		*rl = *wl = 0;
		break;
	case SED_NO_ACCESS:
		*rl = *wl = 1;
		break;
	default:
		SEDCLI_DEBUG_MSG("Invalid locking state.\n");
		return OPAL_INVAL_PARAM;
	}

	return 0;
}

static void prepare_cmd_init(struct opal_device *dev, uint8_t *buf, size_t buf_len,
					int *pos, const uint8_t *uid, const uint8_t *method)
{
	/* setting up the comid */
	init_req(dev);

	/* Initializing the command */
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_CALL);
	*pos += append_bytes(buf + *pos, buf_len - *pos, uid, OPAL_UID_LENGTH);
	*pos += append_bytes(buf + *pos, buf_len - *pos, method, OPAL_METHOD_LENGTH);
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_STARTLIST);
}

static void prepare_cmd_end(uint8_t *buf, size_t buf_len, int *pos)
{
	/* Ending the command */
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDLIST);
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDOFDATA);
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_STARTLIST);
	*pos += append_u8(buf + *pos, buf_len - *pos, 0);
	*pos += append_u8(buf + *pos, buf_len - *pos, 0);
	*pos += append_u8(buf + *pos, buf_len - *pos, 0);
	*pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDLIST);
}

static void prepare_cmd_header(struct opal_device *dev, uint8_t *buf, int pos)
{
	struct opal_header *header;

	/* Update the request buffer pointer */
	buf += pos;

	pos += sizeof(*header);

	header = (struct opal_header *)dev->req_buf;

	/* Update the sessions to the headers */
	header->packet.session.tsn = htobe32(dev->session.tsn);
	header->packet.session.hsn = htobe32(dev->session.hsn);

	/* Update lengths and padding in Opal packet constructs */
	header->subpacket.length = htobe32(pos - sizeof(*header));
	while (pos % 4) {
		if (pos >= dev->req_buf_size)
			break;
		pos += append_u8(buf + (pos % 4), dev->req_buf_size - pos, 0);
	}

	header->packet.length =
		htobe32(pos - sizeof(header->compacket) - sizeof(header->packet));

	header->compacket.length = htobe32(pos - sizeof(header->compacket));
}

static void prepare_req_buf(struct opal_device *dev, struct opal_req_item *data,
				int data_len, const uint8_t *uid, const uint8_t *method)
{
	int i, pos = 0;
	uint8_t *buf;
	size_t buf_len;

	buf = dev->req_buf + sizeof(struct opal_header);
	buf_len = dev->req_buf_size - sizeof(struct opal_header);

	prepare_cmd_init(dev, buf, buf_len, &pos, uid, method);

	if (data == NULL || data_len == 0)
		goto prep_end;

	for (i = 0; i < data_len; i++) {
		switch (data[i].type) {
		case OPAL_U8:
			pos += append_u8(buf + pos, buf_len - pos,
					data[i].val.byte);
			break;
		case OPAL_U64:
			pos += append_u64(buf + pos, buf_len - pos,
					data[i].val.uint);
			break;
		case OPAL_BYTES:
			pos += append_bytes(buf + pos, buf_len - pos,
					data[i].val.bytes, data[i].len);
			break;
		}
	}

prep_end:
	prepare_cmd_end(buf, buf_len, &pos);

	prepare_cmd_header(dev, buf, pos);
}

static int check_header_lengths(struct opal_device *dev)
{
	size_t com_len, pack_len, sub_len;
	struct opal_header *header;

	header = (struct opal_header *) dev->resp_buf;

	com_len = be32toh(header->compacket.length);
	pack_len = be32toh(header->packet.length);
	sub_len = be32toh(header->subpacket.length);

	SEDCLI_DEBUG_PARAM("Response size: compacket: %ld, packet: %ld, subpacket: %ld\n",
			com_len, pack_len, sub_len);

	if (com_len == 0 || pack_len == 0 || sub_len == 0) {
		SEDCLI_DEBUG_PARAM("Bad header length. Compacket: %ld, Packet: %ld, "\
				"Subpacket: %ld\n", com_len, pack_len, sub_len);
			SEDCLI_DEBUG_MSG("The response can't be parsed.\n");
		return -EINVAL;
	}

	return sub_len;
}


static bool resp_token_match(const struct opal_token *token, uint8_t match)
{
	if (token == NULL || token->type != OPAL_DTA_TOKENID_TOKEN ||
	    token->pos[0] != match)
		return false;

	return true;
}

static uint8_t check_resp_status(struct opal_parsed_payload *payload)
{
	struct opal_token *token;
	int num = payload->len;

	token = payload->tokens[0];
	if (resp_token_match(token, OPAL_ENDOFSESSION))
		return 0;

	if (num < 5)
		return DTAERROR_NO_METHOD_STATUS;

	token = payload->tokens[num - 5];
	if (!resp_token_match(token, OPAL_STARTLIST))
		return DTAERROR_NO_METHOD_STATUS;

	token = payload->tokens[num - 1];
	if (!resp_token_match(token, OPAL_ENDLIST))
		return DTAERROR_NO_METHOD_STATUS;

	return payload->tokens[num - 4]->vals.uint;
}

static int opal_snd_rcv_cmd_parse_chk(int fd, struct opal_device *dev, bool end_sessn)
{
	uint8_t *data_buf;
	int ret = 0, data_buf_len = 0,subpacket_len = 0;

	/* Send command and receive results */
	ret = opal_send_recv(fd, dev->comid, dev->req_buf,
			dev->req_buf_size, dev->resp_buf, dev->resp_buf_size);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in NVMe passthrough ops\n");
		return ret;
	}

	subpacket_len = check_header_lengths(dev);
	if (ret < 0)
		return subpacket_len;

	if (end_sessn) {
		dev->session.tsn = 0;
		dev->session.hsn = 0;
	}

	data_buf = dev->resp_buf + sizeof(struct opal_header);
	data_buf_len = subpacket_len;

	ret = opal_parse_data_payload(data_buf, data_buf_len, &dev->payload);
	if (ret == -EINVAL) {
		SEDCLI_DEBUG_MSG("Error in parsing the response\n");
		return ret;
	}

	ret = check_resp_status(&dev->payload);

	return ret;
}

static uint8_t get_payload_string(struct opal_device *dev, uint8_t num)
{
	uint8_t jmp;

	if (dev->payload.tokens[num]->type != OPAL_DTA_TOKENID_BYTESTRING) {
		SEDCLI_DEBUG_MSG("Token is not a byte string.\n");
		return 0;
	}

	switch (dev->payload.tokens[num]->width) {
		case OPAL_WIDTH_TINY:
		case OPAL_WIDTH_SHORT:
			jmp = 1;
			break;
		case OPAL_WIDTH_MEDIUM:
			jmp = 2;
			break;
		case OPAL_WIDTH_LONG:
			jmp = 4;
			break;
		default:
			SEDCLI_DEBUG_MSG("Token has invalid width and can't be parsed\n");
			return 0;
	}

	return jmp;
}

static int validate_sessn(struct opal_device *dev)
{
	dev->session.hsn = dev->payload.tokens[4]->vals.uint;
	dev->session.tsn = dev->payload.tokens[5]->vals.uint;

	if (dev->session.hsn != GENERIC_HOST_SESSION_NUM ||
	    dev->session.tsn < RSVD_TPER_SESSION_NUM) {
		SEDCLI_DEBUG_MSG("Error syncing session(invalid session numbers)\n");
		return -EINVAL;
	}

	return 0;
}

static void parse_tper_host_prop(struct sed_device *device)
{
	struct opal_device *dev = device->priv;
	int payload_len = dev->payload.len;
	struct sed_tper_properties *tper = &device->discv.sed_tper_props;

	/* TPer properties are returned as key-value pairs */
	for (int i = 0, j = 0; i < payload_len; i++) {
		if (resp_token_match(dev->payload.tokens[i], OPAL_STARTNAME)) {
			int jmp = get_payload_string(dev, i + 1);
			int key_len = dev->payload.tokens[i + 1]->len - jmp;

			assert(j < NUM_TPER_PROPS);
			memcpy(tper->property[j].key_name,
				dev->payload.tokens[i + 1]->pos + jmp,
				key_len);
			tper->property[j].value =
					dev->payload.tokens[i + 2]->vals.uint;
			j++;
		}
	}
}

static int opal_tper_host_prep(struct sed_device *device)
{
	int ret, fd = device->fd;
	struct opal_device *dev = device->priv;

	prepare_req_buf(dev, NULL, 0, opal_uid[OPAL_SM_UID],
			opal_method[OPAL_PROPERTIES_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
	if (ret != DTAERROR_NO_METHOD_STATUS)
		goto put_tokens;

	parse_tper_host_prop(device);
	ret = 0;

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item start_sess_cmd[] = {
	{ .type = OPAL_U64, .len = 8, .val = { .uint = GENERIC_HOST_SESSION_NUM } },
	{ .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, /*Admin SP | Locking SP*/
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
	{ .type = OPAL_BYTES, .len = 1, .val = { .bytes = NULL } }, /* Host Challenge -> key; key_len */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 3 } },
	{ .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, /* Host Signing Authority: MSID, SID, PSID */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static void prep_sessn_buff(int sp, const struct sed_key *key, uint8_t *buf)
{
	/* SP */
	start_sess_cmd[1].val.bytes = opal_uid[sp];

	if (!key)
		return;

	/* Host Challenge */
	start_sess_cmd[5].val.bytes = key->key;
	start_sess_cmd[5].len = key->len;

	/* Host Signing Authority */
	start_sess_cmd[9].val.bytes = buf;
}

static int opal_start_generic_session(int fd, struct opal_device *dev, int sp,
				      int auth, const struct sed_key *key)
{
	int ret = 0;
	int cmd_len = ARRAY_SIZE(start_sess_cmd);

	if (auth != OPAL_ANYBODY_UID && key == NULL) {
		SEDCLI_DEBUG_MSG("Must provide password for this authority\n");
		return -EINVAL;
	}

	if (auth != OPAL_ANYBODY_UID) {
		prep_sessn_buff(sp, key, opal_uid[auth]);
	} else {
		prep_sessn_buff(sp, NULL, NULL);
		/* Only the first 3 tokens are required for anybody authority */
		cmd_len = 3;
	}

	prepare_req_buf(dev, start_sess_cmd, cmd_len, opal_uid[OPAL_SM_UID],
			opal_method[OPAL_STARTSESSION_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in Starting a SIDASP session\n");
		goto put_tokens;
	}

	ret = validate_sessn(dev);

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_start_sid_asp_session(int fd, struct opal_device *dev,
		uint8_t *msid_pin, size_t msid_pin_len)
{
	struct sed_key key;

	if (msid_pin_len > sizeof(key.key)) {
		SEDCLI_DEBUG_MSG("MSID_PIN Length Out of Boundary\n");
		return -ERANGE;
	}

	sed_key_init(&key, (char *) msid_pin, msid_pin_len);

	return opal_start_generic_session(fd, dev, OPAL_ADMIN_SP_UID, OPAL_SID_UID, &key);
}

static int opal_start_admin1_lsp_session(int fd, struct opal_device *dev,
		const struct sed_key *key)
{
	return opal_start_generic_session(fd, dev, OPAL_LOCKING_SP_UID,
			OPAL_ADMIN1_UID, key);
}

static int opal_start_auth_session(int fd, struct opal_device *dev,
		uint32_t sum, uint8_t lr, uint32_t who, const struct sed_key *key)
{
	uint8_t lk_ulk_usr[OPAL_UID_LENGTH];
	int ret = 0;

	if (sum) {
		ret = build_locking_usr(lk_ulk_usr, sizeof(lk_ulk_usr), lr);
	} else if (who != OPAL_ADMIN1 && !sum) {
		ret = build_locking_usr(lk_ulk_usr, sizeof(lk_ulk_usr), who - 1);
	} else {
		memcpy(lk_ulk_usr, opal_uid[OPAL_ADMIN1_UID], OPAL_UID_LENGTH);
	}

	if (ret) {
		SEDCLI_DEBUG_MSG("Error in building Locking Range for the given user\n");
		return ret;
	}

	prep_sessn_buff(OPAL_LOCKING_SP_UID, key, lk_ulk_usr);

	prepare_req_buf(dev, start_sess_cmd, ARRAY_SIZE(start_sess_cmd),
			opal_uid[OPAL_SM_UID],
			opal_method[OPAL_STARTSESSION_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in Starting a auth session\n");
		goto put_tokens;
	}

	ret = validate_sessn(dev);

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_end_session(int fd, struct opal_device *dev)
{
	uint8_t *buf;
	int pos = 0, ret = 0;
	size_t buf_len;

	buf = dev->req_buf + sizeof(struct opal_header);
	buf_len = sizeof(dev->req_buf) - sizeof(struct opal_header);

	init_req(dev);

	pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDOFSESSION);

	prepare_cmd_end(buf, buf_len, &pos);

	prepare_cmd_header(dev, buf, pos);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, true);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_revert_tper_local(int fd, struct opal_device *dev)
{
	int ret = 0;

	prepare_req_buf(dev, NULL, 0, opal_uid[OPAL_ADMIN_SP_UID],
			opal_method[OPAL_REVERT_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item opal_revert_sp_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U64, .len = 4, .val = { .uint = KEEP_GLOBAL_RANGE_KEY } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_FALSE } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_revertlsp_local(int fd, struct opal_device *dev, bool keep_global_rn_key)
{
	int ret = 0;

	opal_revert_sp_cmd[2].val.byte = keep_global_rn_key ? OPAL_TRUE : OPAL_FALSE;

	prepare_req_buf(dev, opal_revert_sp_cmd, ARRAY_SIZE(opal_revert_sp_cmd),
			opal_uid[OPAL_THISSP_UID],
			opal_method[OPAL_REVERTSP_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item opal_generic_get_column_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTCOLUMN } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* start column */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDCOLUMN } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* end column */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
};

static int opal_generic_get_column(int fd, struct opal_device *dev, const uint8_t *uid,
				   uint64_t start_col, uint64_t end_col)
{
	opal_generic_get_column_cmd[3].val.uint = start_col;
	opal_generic_get_column_cmd[7].val.uint = end_col;

	prepare_req_buf(dev, opal_generic_get_column_cmd, ARRAY_SIZE(opal_generic_get_column_cmd),
			uid, opal_method[OPAL_GET_METHOD_UID]);

	return opal_snd_rcv_cmd_parse_chk(fd, dev, false);
}

static int opal_get_msid(int fd, struct opal_device *dev, uint8_t *key, uint8_t *key_len)
{
	uint8_t jmp;
	int ret = 0;

	ret = opal_generic_get_column(fd, dev, opal_uid[OPAL_C_PIN_MSID_UID], OPAL_PIN, OPAL_PIN);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error parsing payload\n");
		goto put_tokens;
	}

	jmp = get_payload_string(dev, 4);
	*key_len = dev->payload.tokens[4]->len - jmp;
	memcpy(key, dev->payload.tokens[4]->pos + jmp, *key_len);

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_get_lsp_lifecycle(int fd, struct opal_device *dev)
{
	uint8_t lc_status;
	int ret = 0;

	ret = opal_generic_get_column(fd, dev, opal_uid[OPAL_LOCKING_SP_UID],
				      OPAL_LIFECYCLE, OPAL_LIFECYCLE);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error parsing payload\n");
		goto put_tokens;
	}

	lc_status = dev->payload.tokens[4]->vals.uint;
	if (lc_status != OPAL_MANUFACTURED_INACTIVE) {
		SEDCLI_DEBUG_MSG("Couldn't determine the status of the Lifecycle state\n");
		ret = -ENODEV;
	}

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_activate_lsp(int fd, struct opal_device *dev, bool sum, uint8_t *lr, int num_lrs)
{
	int pos = 0, ret = 0;
	size_t buf_len;
	uint8_t usr_lr[OPAL_UID_LENGTH], *buf;

	buf = dev->req_buf + sizeof(struct opal_header);
	buf_len = sizeof(dev->req_buf) - sizeof(struct opal_header);

	prepare_cmd_init(dev, buf, buf_len, &pos, opal_uid[OPAL_LOCKING_SP_UID],
			opal_method[OPAL_ACTIVATE_METHOD_UID]);

	if (sum) {
		if (sizeof(usr_lr) > OPAL_UID_LENGTH) {
			SEDCLI_DEBUG_MSG("Length Out of Boundary\n");
			return -ERANGE;
		}
		memcpy(usr_lr, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID],
				OPAL_UID_LENGTH);
		if (lr[0] == 0)
			return 0;
		usr_lr[5] = LOCKING_RANGE_NON_GLOBAL;
		usr_lr[7] = lr[0];

		pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
		pos += append_u64(buf + pos, buf_len - pos, SUM_SELECTION_LIST);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTLIST);
		pos += append_bytes(buf + pos, buf_len - pos, usr_lr,
				OPAL_UID_LENGTH);
		for (int i = 1; i < num_lrs; i++) {
			usr_lr[7] = lr[i];
			pos += append_bytes(buf + pos, buf_len - pos, usr_lr,
					OPAL_UID_LENGTH);
		}
		pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDLIST);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
	}

	prepare_cmd_end(buf, buf_len, &pos);

	prepare_cmd_header(dev, buf, pos);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item add_usr_to_lr_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 3 } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
	{ .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
	{ .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_BOOLEAN_ACE_UID] } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int add_usr_to_lr(int fd, struct opal_device *dev, uint32_t l_state, uint8_t lr, uint32_t who)
{
	uint8_t lr_buff[OPAL_UID_LENGTH], usr_uid[OPAL_UID_LENGTH];
	int ret = 0;

	memcpy(lr_buff, opal_uid[OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID],
			OPAL_UID_LENGTH);

	if (l_state == OPAL_RW) {
		memcpy(lr_buff, opal_uid[OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID],
				OPAL_UID_LENGTH);
	}
	lr_buff[7] = lr;

	memcpy(usr_uid, opal_uid[OPAL_USER1_UID], OPAL_UID_LENGTH);
	usr_uid[7] = who;

	add_usr_to_lr_cmd[8].val.bytes = usr_uid;
	add_usr_to_lr_cmd[12].val.bytes = usr_uid;

	prepare_req_buf(dev, add_usr_to_lr_cmd, ARRAY_SIZE(add_usr_to_lr_cmd),
			lr_buff, opal_method[OPAL_SET_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item internal_activate_usr_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 5 } }, /* Enable */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_TRUE } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_internal_activate_usr(int fd, struct opal_device *dev, uint32_t who)
{
	uint8_t uid[OPAL_UID_LENGTH];
	int ret = 0;

	memcpy(uid, opal_uid[OPAL_USER1_UID], OPAL_UID_LENGTH);
	uid[7] = who;

	prepare_req_buf(dev, internal_activate_usr_cmd, ARRAY_SIZE(internal_activate_usr_cmd),
			uid, opal_method[OPAL_SET_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item generic_enable_disable_global_lr_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKENABLED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Lock Enabled */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKENABLED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Lock Enabled*/
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Locked */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Locked */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static void generic_enable_disable_global_lr(struct opal_device *dev,
		const uint8_t *uid, bool rle, bool wle, bool rl, bool wl)
{
	generic_enable_disable_global_lr_cmd[5].val.byte = rle;
	generic_enable_disable_global_lr_cmd[9].val.byte = wle;
	generic_enable_disable_global_lr_cmd[13].val.byte = rl;
	generic_enable_disable_global_lr_cmd[17].val.byte = wl;

	prepare_req_buf(dev, generic_enable_disable_global_lr_cmd, ARRAY_SIZE(generic_enable_disable_global_lr_cmd),
			uid, opal_method[OPAL_SET_METHOD_UID]);
}

int opal_setup_global_range_pt(struct sed_device *dev, const struct sed_key *key)
{
	int status;
	struct opal_device *opal_dev;

	opal_dev = dev->priv;

	status = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (status)
		goto end_sessn;

	/* Read Locking Enabled*/
	generic_enable_disable_global_lr_cmd[5].val.byte = true;
	/* Write Locking Enabled*/
	generic_enable_disable_global_lr_cmd[9].val.byte = true;

	prepare_req_buf(opal_dev, generic_enable_disable_global_lr_cmd, ARRAY_SIZE(generic_enable_disable_global_lr_cmd),
			opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], opal_method[OPAL_SET_METHOD_UID]);

	status = opal_snd_rcv_cmd_parse_chk(dev->fd, opal_dev, false);

	opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

end_sessn:
	opal_end_session(dev->fd, opal_dev);

	return status;
}

static struct opal_req_item setup_locking_range_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGESTART } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Range Start */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGELENGTH } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Range Length */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKENABLED } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Read Lock Enabled */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKENABLED } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Write Lock Enabled */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_setup_locking_range(int fd, struct opal_device *dev, uint8_t lr,
		uint64_t range_start, uint64_t range_length, uint32_t RLE, uint32_t WLE)
{
	uint8_t uid[OPAL_UID_LENGTH];
	int ret = 0;

	ret = build_lr(uid, sizeof(uid), lr);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error in building the locking range\n");
		return ret;
	}

	if (lr == 0) {
		generic_enable_disable_global_lr(dev, uid, !!RLE, !!WLE, 0, 0);
	} else {
		setup_locking_range_cmd[5].val.uint = range_start;
		setup_locking_range_cmd[9].val.uint = range_length;
		setup_locking_range_cmd[13].val.uint = !!RLE;
		setup_locking_range_cmd[17].val.uint = !!WLE;

		prepare_req_buf(dev, setup_locking_range_cmd, ARRAY_SIZE(setup_locking_range_cmd),
				uid, opal_method[OPAL_SET_METHOD_UID]);
	}

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_lock_unlock_sum(int fd, struct opal_device *dev,
		uint32_t locktype, uint8_t lr)
{
	uint8_t lr_buff[OPAL_UID_LENGTH];
	uint8_t read_lock = 1, write_lock = 1;
	int ret = 0;

	ret = opal_rw_lock(dev, lr_buff, sizeof(lr_buff), locktype, lr, &read_lock, &write_lock);
	if (ret)
		return ret;

	generic_enable_disable_global_lr(dev, lr_buff, 1, 1,
			read_lock, write_lock);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item opal_lock_unlock_no_sum_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Locked */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKED } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Locked */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_lock_unlock_no_sum(int fd, struct opal_device *dev,
		uint32_t lock_type, uint8_t lr)
{
	uint8_t lr_buff[OPAL_UID_LENGTH];
	uint8_t read_lock = 1, write_lock = 1;
	int ret = 0;

	ret = opal_rw_lock(dev, lr_buff, sizeof(lr_buff), lock_type, lr,
			&read_lock, &write_lock);
	if (ret)
		return ret;

	opal_lock_unlock_no_sum_cmd[5].val.byte = read_lock;
	opal_lock_unlock_no_sum_cmd[9].val.byte = write_lock;

	prepare_req_buf(dev, opal_lock_unlock_no_sum_cmd, ARRAY_SIZE(opal_lock_unlock_no_sum_cmd),
			lr_buff, opal_method[OPAL_SET_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item generic_pwd_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_PIN } },
	{ .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } }, /* The new pwd */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static void generic_pwd_func(struct opal_device *dev, const struct sed_key *key,
		const uint8_t *auth_uid)
{
	generic_pwd_cmd[5].val.bytes = key->key;
	generic_pwd_cmd[5].len = key->len;

	prepare_req_buf(dev, generic_pwd_cmd, ARRAY_SIZE(generic_pwd_cmd),
			auth_uid, opal_method[OPAL_SET_METHOD_UID]);
}

static int set_new_admin1_pwd(int fd, struct opal_device *dev, uint32_t who, uint32_t sum, uint8_t lr, const struct sed_key *new_key)
{
	uint8_t uid[OPAL_UID_LENGTH];
	int ret = 0;

	memcpy(uid, opal_uid[OPAL_C_PIN_ADMIN1_UID], OPAL_UID_LENGTH);

	if (who != OPAL_ADMIN1) {
		uid[5] = 0x03;
		if (sum) {
			uid[7] = lr + 1;
		} else {
			uid[7] = who;
		}
	}

	generic_pwd_func(dev, new_key, uid);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_set_sid_pwd(int fd, struct opal_device *dev, const struct sed_key *key)
{
	int ret = 0;

	generic_pwd_func(dev, key, opal_uid[OPAL_C_PIN_SID_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static struct opal_req_item opal_set_mbr_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* MBR done or not */

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_set_mbr(int fd, struct opal_device *dev, uint8_t val,
			uint8_t en_disable)
{
	int ret = 0;

	opal_set_mbr_cmd[4].val.byte = val;
	opal_set_mbr_cmd[5].val.byte = en_disable;

	prepare_req_buf(dev, opal_set_mbr_cmd, ARRAY_SIZE(opal_set_mbr_cmd),
			opal_uid[OPAL_MBRCONTROL_UID],
			opal_method[OPAL_SET_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int opal_set_mbr_done(int fd, struct opal_device *dev,
			     uint8_t en_disable)
{
	return opal_set_mbr(fd, dev, OPAL_MBRDONE, en_disable);
}

static int opal_set_mbr_en_disable(int fd, struct opal_device *dev,
				   uint8_t en_disable)
{
	return opal_set_mbr(fd, dev, OPAL_MBRENABLE, en_disable);
}

static int opal_erase_lr(int fd, struct opal_device *dev, uint8_t lr)
{
	int ret = 0;
	uint8_t uid[OPAL_UID_LENGTH];

	if (build_lr(uid, sizeof(uid), lr) < 0)
		return -ERANGE;

	prepare_req_buf(dev, NULL, 0, uid, opal_method[OPAL_ERASE_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int get_table_length(int fd, struct opal_device *dev, enum opaluid table)
{
	uint8_t uid[OPAL_UID_LENGTH];
	const int half = OPAL_UID_LENGTH/2;
	int ret;

	memcpy(uid, opal_uid[OPAL_TABLE_TABLE_UID], half);
	memcpy(uid + half, opal_uid[table], half);

	ret = opal_generic_get_column(fd, dev, uid, OPAL_TABLE_ROW, OPAL_TABLE_ROW);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error parsing payload\n");
		ret = -1;
		goto put_tokens;
	}

	ret = dev->payload.tokens[4]->vals.uint;

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

/*
 * ENDLIST, ENDOFDATA, STARTLIST, 0, 0, 0 and ENDLIST.
 * These 7 bytes are always required to conclude the opal command.
 */
#define CMD_END_BYTES_NUM 7

static int opal_generic_write_table(int fd, struct opal_device *dev,
				    enum opaluid table, const uint8_t *data,
				    uint64_t offset, uint64_t size)
{
	uint8_t *buf;
	uint64_t len = 0, index = 0, remaining_buff_size;
	int ret = 0, pos = 0;
	size_t buf_len;

	if (size == 0)
		return 0;

	len = get_table_length(fd, dev, table);
	if (len < 0) {
		SEDCLI_DEBUG_MSG("Error retrieving table length\n");
		return len;
	}
	SEDCLI_DEBUG_PARAM("Table length is: %lu\n", len);

	if (size > len || offset > len - size) {
		SEDCLI_DEBUG_PARAM("The data doesn't fit in the table (%lu v/s "\
				"%lu)\n", offset + size, len);
		return -ENOSPC;
	}

	while (index < size) {
		buf = dev->req_buf + sizeof(struct opal_header);
		buf_len = dev->req_buf_size - sizeof(struct opal_header);

		prepare_cmd_init(dev, buf, buf_len, &pos, opal_uid[table],
				 opal_method[OPAL_SET_METHOD_UID]);

		pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_WHERE);
		pos += append_u64(buf + pos, buf_len - pos, offset + index);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);

		pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_VALUES);

		/*
		 * The append_bytes used below, dependng upon the len either uses
		 * short_atom_bytes_header (returns 1) or medium_atom_bytes_header
		 * (returns 2) or long_atom_bytes_header (returns 4).
		 * Hence we consider the MAX of the three i.e, 4.
		 *
		 * The 1 byte is for the following ENDNAME token.
		 */
		remaining_buff_size = buf_len - (pos + 4 + 1 + CMD_END_BYTES_NUM);

		len = MIN(remaining_buff_size, (size - index));

		pos += append_bytes(buf + pos, buf_len - pos, data, len);
		pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
		prepare_cmd_end(buf, buf_len, &pos);
		prepare_cmd_header(dev, buf, pos);

		ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

		opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

		if (ret)
			break;

		index += len;
		pos = 0;
	}

	return ret;
}

static int opal_write_datastr(int fd, struct opal_device *dev,
			const uint8_t *data, uint64_t offset, uint64_t size)
{
	return opal_generic_write_table(fd, dev, OPAL_DATASTORE_UID, data,
					offset, size);
}

static int opal_write_mbr(int fd, struct opal_device *dev, const uint8_t *data,
			uint64_t offset, uint64_t size)
{
	return opal_generic_write_table(fd, dev, OPAL_MBR_UID, data, offset,
					size);
}

static struct opal_req_item opal_generic_read_table_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTROW } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Start Reading from */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDROW } },
	{ .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* End reading here */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
};

/*
 * IO_BUFFER_LENGTH = 2048
 * sizeof(header) = 56
 * No. of Token Bytes in the Response = 11
 * MAX size of data that can be carried in response buffer
 * at a time is : 2048 - (56 + 11) = 1981 = 0x7BD.
 */
#define OPAL_MAX_READ_TABLE (0x7BD)

static int opal_generic_read_table(int fd, struct opal_device *dev,
				   enum opaluid table, uint8_t *data,
				   uint64_t offset, uint64_t size)
{
	int ret = 0;
	uint64_t len = 0, index = 0, end_row = size - 1;
	uint8_t jmp;
	size_t data_len;

	if (size == 0)
		return 0;

	len = get_table_length(fd, dev, table);
	if (len < 0) {
		SEDCLI_DEBUG_MSG("Error retrieving table length\n");
		return len;
	}

	SEDCLI_DEBUG_PARAM("Table Length is: %lu\n", len);

	if (size > len || offset > len - size) {
		SEDCLI_DEBUG_PARAM("Read size/offset exceeding the table limits"\
				"%lu in %lu\n", offset + size, len);
		return -EINVAL;
	}

	while (index < end_row) {
		opal_generic_read_table_cmd[3].val.uint = index + offset;

		len = MIN(OPAL_MAX_READ_TABLE, (end_row - index));
		opal_generic_read_table_cmd[7].val.uint = index + offset + len;

		prepare_req_buf(dev, opal_generic_read_table_cmd,
				ARRAY_SIZE(opal_generic_read_table_cmd),
				opal_uid[table],
				opal_method[OPAL_GET_METHOD_UID]);

		ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
		if (ret) {
			opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
			break;
		}

		/* Reading the Data from the response */
		jmp = get_payload_string(dev, 1);
		data_len = dev->payload.tokens[1]->len - jmp;
		memcpy(data + index, dev->payload.tokens[1]->pos + jmp, data_len);

		opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

		index += len;
	}

	return ret;
}

static int opal_read_datastr(int fd, struct opal_device *dev, uint8_t *data,
			     uint64_t offset, uint64_t size)
{
	return opal_generic_read_table(fd, dev, OPAL_DATASTORE_UID, data,
				       offset, size);
}

static int get_num_lrs(int fd, struct opal_device *dev)
{
	int ret;

	ret = opal_generic_get_column(fd, dev, opal_uid[OPAL_LOCKING_INFO_TABLE_UID],
				      OPAL_MAXRANGES, OPAL_MAXRANGES);
	if (ret) {
		SEDCLI_DEBUG_MSG("Error parsing payload\n");
		ret = -1;
		goto put_tokens;
	}

	ret = dev->payload.tokens[4]->vals.uint + 1;

put_tokens:
	opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

	return ret;
}

static int list_lr(int fd, struct opal_device *dev, struct sed_opal_lockingranges *lrs)
{
	int ret;
	uint8_t uid[OPAL_UID_LENGTH];

	lrs->lr_num = get_num_lrs(fd, dev);
	if (lrs->lr_num < 0)
		return lrs->lr_num;

	if (lrs->lr_num > SED_OPAL_MAX_LRS)
		lrs->lr_num = SED_OPAL_MAX_LRS;

	SEDCLI_DEBUG_PARAM("The number of ranges discovered is: %d\n",
			   lrs->lr_num);

	for (int i = 0; i < lrs->lr_num; i++) {

		ret = build_lr(uid, sizeof(uid), i);
		if (ret) {
			SEDCLI_DEBUG_MSG("Error building locking range\n");
			return ret;
		}

		ret = opal_generic_get_column(fd, dev, uid, OPAL_RANGESTART,
					      OPAL_WRITELOCKED);
		if (ret) {
			opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
			return ret;
		}

		struct sed_opal_lockingrange *lr = &lrs->lrs[i];

		lr->lr_id = i;
		lr->start = dev->payload.tokens[4]->vals.uint;
		lr->length = dev->payload.tokens[8]->vals.uint;
		lr->rle = dev->payload.tokens[12]->vals.uint;
		lr->wle = dev->payload.tokens[16]->vals.uint;
		lr->read_locked = dev->payload.tokens[20]->vals.uint;
		lr->write_locked = dev->payload.tokens[24]->vals.uint;

		opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
	}

	return 0;
}

int opal_get_msid_pin_pt(struct sed_device *dev, struct sed_key *msid_pin)
{
	struct opal_device *opal_dev;
	int ret;

	opal_dev = dev->priv;

	memset(msid_pin, 0, sizeof(*msid_pin));

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_ADMIN_SP_UID,
					 OPAL_ANYBODY_UID, NULL);
	if (ret)
		goto end_sessn;

	ret = opal_get_msid(dev->fd, opal_dev, msid_pin->key, &msid_pin->len);
	if (ret)
		goto end_sessn;

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_takeownership_pt(struct sed_device *dev, const struct sed_key *key)
{
	struct opal_device *opal_dev;
	int ret = 0;
	uint8_t msid_pin_len = 0;
	uint8_t msid_pin[SED_MAX_KEY_LEN];

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must Provide a password.\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	memset(msid_pin, 0, sizeof(msid_pin));

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_ADMIN_SP_UID,
					 OPAL_ANYBODY_UID, NULL);
	if (ret)
		goto end_sessn;

	ret = opal_get_msid(dev->fd, opal_dev, msid_pin, &msid_pin_len);
	if (ret)
		goto end_sessn;

	ret = opal_end_session(dev->fd, opal_dev);
	if (ret)
		goto end_sessn;

	ret = opal_start_sid_asp_session(dev->fd, opal_dev, msid_pin, msid_pin_len);
	if (ret)
		goto end_sessn;

	ret = opal_set_sid_pwd(dev->fd, opal_dev, key);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_reverttper_pt(struct sed_device *dev, const struct sed_key *key,
		bool psid)
{
	struct opal_device *opal_dev;
	int ret = 0, auth;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must Provide a password.\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	auth = psid ? OPAL_PSID_UID : OPAL_SID_UID;

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_ADMIN_SP_UID, auth,
			key);
	if (ret) {
		opal_end_session(dev->fd, opal_dev);
		return ret;
	}

	return opal_revert_tper_local(dev->fd, opal_dev);
}

int opal_activate_lsp_pt(struct sed_device *dev, const struct sed_key *key,
		char *lr_str, bool sum)
{
	int num_lrs = 0, ret = 0;
	char *num, *errchk;
	size_t count = 0;
	unsigned long parsed;
	uint8_t lr[OPAL_MAX_LRS];
	struct opal_device *opal_dev;

	if (key == NULL || (sum && lr_str)) {
		SEDCLI_DEBUG_MSG("Must Provide a password, and a LR string "\
				 " if SUM \n");
		return -EINVAL;
	}
	opal_dev = dev->priv;
	SEDCLI_DEBUG_PARAM("Sum is %d\n", sum);

	memset(lr, 0, sizeof(lr));

	if (!lr_str) {
		num_lrs = 1;
	} else {
		num = strtok(lr_str, ",");
		while (num != NULL && count < OPAL_MAX_LRS) {
			parsed = strtoul(num, &errchk, 10);
			if (errchk == num)
				continue;
			lr[count] = parsed;
			SEDCLI_DEBUG_PARAM("added %lu to lr at index %zu\n",
					parsed, count);
			num = strtok(NULL, ",");
			count++;
		}
		num_lrs = count;
	}

	if (!num_lrs || num_lrs > OPAL_MAX_LRS)
		return  -EINVAL;

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_ADMIN_SP_UID, OPAL_SID_UID,
			key);
	if (ret)
		goto end_sessn;

	ret = opal_get_lsp_lifecycle(dev->fd, opal_dev);
	if (ret)
		goto end_sessn;

	ret = opal_activate_lsp(dev->fd, opal_dev, sum, lr, num_lrs);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_revertlsp_pt(struct sed_device *dev, const struct sed_key *key, bool keep_global_rn_key)
{
	int ret = 0;
	struct opal_device *opal_dev;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must Provide a password.\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;
	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_LOCKING_SP_UID, OPAL_ADMIN1_UID, key);
	if (ret) {
		opal_end_session(dev->fd, opal_dev);
		return ret;
	}

	ret = opal_revertlsp_local(dev->fd, opal_dev, keep_global_rn_key);
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_add_usr_to_lr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *usr, enum SED_ACCESS_TYPE lock_type, uint8_t lr)
{
	struct sed_key disk_key;
	int ret = 0;
	struct opal_device *opal_dev;
	uint32_t who, lk_type = lock_type;

	if (lk_type > SED_NO_ACCESS || key == NULL || key_len == 0 || usr == NULL) {
		SEDCLI_DEBUG_MSG("Need to supply user, lock type and password!\n");
		return -EINVAL;
	}
	opal_dev = dev->priv;

	if (sed_get_user(usr, &who)) {
		return -EINVAL;
	}

	ret = sed_key_init(&disk_key, key, key_len);
	if (ret) {
		return ret;
	}

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, &disk_key);
	if (ret)
		goto end_sessn;

	ret = add_usr_to_lr(dev->fd, opal_dev, lk_type, lr, who);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_activate_usr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *user)
{
	struct sed_key disk_key;
	int ret = 0;
	struct opal_device *opal_dev;
	uint32_t who;

	if (user == NULL || key == NULL) {
		SEDCLI_DEBUG_PARAM("Invalid arguments for %s, need to provide "\
				"password and user.\n", __func__);
		return -EINVAL;
	}
	opal_dev = dev->priv;

	if (sed_get_user(user, &who)) {
		return -EINVAL;
	}

	if (who == OPAL_ADMIN1) {
		SEDCLI_DEBUG_MSG("Opal Admin is already activated by default!\n");
		return -EINVAL;
	}

	if(who > OPAL_USER9) {
		SEDCLI_DEBUG_MSG("Not a valid user.!!!\n");
		return -EINVAL;
	}

	ret = sed_key_init(&disk_key, key, key_len);
	if (ret) {
		return ret;
	}

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, &disk_key);
	if (ret)
		goto end_sessn;

	ret = opal_internal_activate_usr(dev->fd, opal_dev, who);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_setuplr_pt(struct sed_device *dev, const char *key, uint8_t key_len,
		const char *user, uint8_t lr, size_t range_start,
		size_t range_length, bool sum, bool RLE, bool WLE)

{
	struct sed_key disk_key;
	struct opal_device *opal_dev;
	uint32_t who = SED_ADMIN1;
	int ret = 0;

	if (range_start == ~0 || range_length == ~0 || (!sum && user == NULL) ||
			key == NULL) {
		SEDCLI_DEBUG_MSG("Incorrect parameters, please try again\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	if (!sum) {
		if (sed_get_user(user, &who)) {
			return -EINVAL;
		}
	}

	ret = sed_key_init(&disk_key, key, key_len);
	if (ret) {
		return ret;
	}

	ret = opal_start_auth_session(dev->fd, opal_dev, sum, lr, who, &disk_key);
	if (ret)
		goto end_sessn;

	ret = opal_setup_locking_range(dev->fd, opal_dev, lr, range_start, range_length, RLE, WLE);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_lock_unlock_pt(struct sed_device *dev, const struct sed_key *key,
		enum SED_ACCESS_TYPE lock_type)
{
	int ret = 0;
	struct opal_device *opal_dev;
	uint32_t lk_type = lock_type;

	if (lk_type > SED_NO_ACCESS || key == NULL) {
		SEDCLI_DEBUG_MSG("Need to supply lock type and password!\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	ret = opal_start_auth_session(dev->fd, opal_dev, false, 0, SED_ADMIN1, key);
	if (ret)
		goto end_sessn;

	ret = opal_lock_unlock_no_sum(dev->fd, opal_dev, lock_type, 0);

end_sessn:

	opal_end_session(dev->fd, opal_dev);
	return ret;
}


int opal_set_pwd_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *old_key,
		const struct sed_key *new_key)
{
	struct opal_device *opal_dev;
	int ret = 0;

	if (old_key == NULL || old_key->len == 0 || new_key == NULL ||
			new_key->len == 0 || !(auth == SED_ADMIN1 || auth == SED_SID)) {
		SEDCLI_DEBUG_MSG("Invalid arguments, please try again\n");
		return -EINVAL;
	}
	opal_dev = dev->priv;

	if (auth == SED_ADMIN1) {
		ret = opal_start_auth_session(dev->fd, opal_dev, 0, 0, SED_ADMIN1, old_key);
		if (ret)
			goto end_sessn;

		ret = set_new_admin1_pwd(dev->fd, opal_dev, SED_ADMIN1, 0, 0, new_key);
	} else {
		ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_ADMIN_SP_UID, OPAL_SID_UID, old_key);

		if (ret) {
			goto end_sessn;
		}

		ret = opal_set_sid_pwd(dev->fd, opal_dev, new_key);
	}

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_mbr_done_pt(struct sed_device *dev, const struct sed_key *key,
		     bool mbr_done)
{
	int ret;
	uint8_t done;
	struct opal_device *opal_dev;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("User must provide ADMIN1 password\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	done = mbr_done ? OPAL_TRUE : OPAL_FALSE;

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (ret)
		goto end_sessn;

	ret = opal_set_mbr_done(dev->fd, opal_dev, done);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key,
			bool enable)
{
	int ret = 0;
	uint8_t opal_enable;
	struct opal_device *opal_dev;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Need ADMIN1 password for mbr shadow enable/"
				 "disable\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	opal_enable = enable ? OPAL_TRUE : OPAL_FALSE;

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (ret)
		goto end_sessn;

	ret = opal_set_mbr_en_disable(dev->fd, opal_dev, opal_enable);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_eraselr_pt(struct sed_device *dev, const char *password,
		uint8_t key_len, const char *user, const uint8_t lr, bool sum)
{
	struct sed_key disk_key;
	struct opal_device *opal_dev;
	uint32_t who = SED_ADMIN1;
	int ret = 0;

	if ((!sum && user == NULL) || password == NULL) {
		SEDCLI_DEBUG_MSG("Must provide the password, user and locking "\
				"range to be erased.\n");
		return -EINVAL;
	}
	opal_dev = dev->priv;

	if (!sum) {
		if (sed_get_user(user, &who)) {
			return -EINVAL;
		}
	}

	ret = sed_key_init(&disk_key, password, key_len);
	if (ret) {
		return ret;
	}

	ret = opal_start_auth_session(dev->fd, opal_dev, sum, lr, who, &disk_key);
	if (ret)
		goto end_sessn;

	ret = opal_erase_lr(dev->fd, opal_dev, lr);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_ds_read(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, uint8_t *to, uint32_t size,
		uint32_t offset)
{
	int ret = 0, opal_auth;
	struct opal_device *opal_dev;

	if (to == NULL) {
		SEDCLI_DEBUG_MSG("Must provide a valid destination pointer\n");
		return -EINVAL;
	}

	opal_auth = get_opal_auth_uid(auth);
	if (opal_auth < 0) {
		SEDCLI_DEBUG_MSG("Authority not supported\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_LOCKING_SP_UID,
				opal_auth, key);

	if (ret) {
		goto end_sessn;
	}

	ret = opal_read_datastr(dev->fd, opal_dev, to, offset, size);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_ds_write(struct sed_device *dev, enum SED_AUTHORITY auth,
		const struct sed_key *key, const uint8_t *from, uint32_t size,
		uint32_t offset)
{
	int ret = 0, opal_auth;
	struct opal_device *opal_dev;

	if (from == NULL) {
		SEDCLI_DEBUG_MSG("Must provide a valid source pointer\n");
		return -EINVAL;
	}

	opal_auth = get_opal_auth_uid(auth);
	if (opal_auth < 0) {
		SEDCLI_DEBUG_MSG("Authority not supported\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	ret = opal_start_generic_session(dev->fd, opal_dev, OPAL_LOCKING_SP_UID,
				opal_auth, key);

	if (ret) {
		goto end_sessn;
	}

	ret = opal_write_datastr(dev->fd, opal_dev, from, offset, size);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

static struct opal_req_item opal_ds_add_anybody_set_cmd[] = {
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 1 } }, /* Values */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = 0x03 } }, /* BooleanExpr */
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
	{ .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
	{ .type = OPAL_BYTES, .len = 8, .val = { .bytes = opal_uid[OPAL_ANYBODY_UID] } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
	{ .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

/**
 * Change ACL in such way so anybody user can read the data but only
 * Admin1 can write to it.
 * Admin1 key needs to be provided
 */
int opal_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key)
{
	int ret = 0;
	struct opal_device *opal_dev;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must provide password\n");
		return -EINVAL;
	}
	opal_dev = dev->priv;

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (ret) {
		goto end_sessn;
	}

	prepare_req_buf(opal_dev, opal_ds_add_anybody_set_cmd, ARRAY_SIZE(opal_ds_add_anybody_set_cmd),
			opal_uid[OPAL_ACE_DS_GET_ALL_UID], opal_method[OPAL_SET_METHOD_UID]);

	ret = opal_snd_rcv_cmd_parse_chk(dev->fd, opal_dev, false);

	opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_list_lr_pt(struct sed_device *dev, const struct sed_key *key,
		    struct sed_opal_lockingranges *lrs)
{
	struct opal_device *opal_dev;
	int ret = 0;

	if (key == NULL) {
		SEDCLI_DEBUG_MSG("Must provide the password.\n");
		return -EINVAL;
	}

	if (!lrs) {
		SEDCLI_DEBUG_MSG("Must provide a valid destination pointer\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (ret)
		goto end_sessn;

	ret = list_lr(dev->fd, opal_dev, lrs);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

int opal_write_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key,
			const uint8_t *from, uint32_t size, uint32_t offset)
{
	int ret;
	struct opal_device *opal_dev;

	if (from == NULL) {
		SEDCLI_DEBUG_MSG("Must provide a valid source pointer\n");
		return -EINVAL;
	}

	opal_dev = dev->priv;

	ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
	if (ret)
		goto end_sessn;

	ret = opal_write_mbr(dev->fd, opal_dev, from, offset, size);

end_sessn:
	opal_end_session(dev->fd, opal_dev);
	return ret;
}

