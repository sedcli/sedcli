/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <linux/nvme_ioctl.h>

#include "nvme_pt_ioctl.h"

#define NVME_SECURITY_SEND (0x81)
#define NVME_SECURITY_RECV (0x82)

#define OPAL_RECV_SLEEP (15000)

#define SEND (1)
#define RECV (0)

static int send_recv_nvme_pt_ioctl(int fd, int send, uint8_t proto_id,
		uint16_t com_id, void *sec_cmd, uint32_t sec_cmd_len)
{
	int status;
	struct nvme_admin_cmd nvme_cmd;

	memset(&nvme_cmd, 0, sizeof(nvme_cmd));

	nvme_cmd.opcode = send ? NVME_SECURITY_SEND : NVME_SECURITY_RECV;

	nvme_cmd.cdw10 = proto_id << 24 | com_id << 8;
	nvme_cmd.cdw11 = sec_cmd_len;

	nvme_cmd.data_len = sec_cmd_len;
	nvme_cmd.addr = (uint64_t) sec_cmd;

	status = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &nvme_cmd);

	if (status < 0)
		return errno;

	return status;
}

int opal_send(int fd, uint8_t proto_id, uint16_t com_id, uint8_t *buf, int buf_len)
{
	int ret;

	ret = send_recv_nvme_pt_ioctl(fd, SEND, proto_id, com_id, buf,
			buf_len);

	return ret;
}

int opal_recv(int fd, uint16_t com_id, uint8_t *buf, int buf_len)
{
	int ret, done;
	struct opal_header *header;
	uint32_t outstanding_data, min_transfer;

	done = 0;
	while (!done) {
		done = 1;
		memset(buf, 0, buf_len);

		ret = send_recv_nvme_pt_ioctl(fd, RECV, TCG_SECP_01, com_id,
				buf, buf_len);
		if (ret == 0) {
			header = (struct opal_header *) buf;

			outstanding_data =
				be32toh(header->compacket.outstanding_data);
			min_transfer = be32toh(header->compacket.min_transfer);

			if (outstanding_data != 0 && min_transfer == 0) {
				usleep(OPAL_RECV_SLEEP);
				done = 0;
			}
		}
	}

	return ret;
}

int opal_send_recv(int fd, uint16_t com_id, uint8_t *req_buf,
		int req_buf_len, uint8_t *resp_buf, int resp_buf_len)
{
	int ret;

	ret = opal_send(fd, TCG_SECP_01, com_id, req_buf, req_buf_len);
	if (ret)
		return ret;

	ret = opal_recv(fd, com_id, resp_buf, resp_buf_len);

	return ret;
}


