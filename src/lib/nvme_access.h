/*
 * Copyright (C) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _NVME_ACCESS_H_
#define _NVME_ACCESS_H_

#define OPAL_DISCOVERY_COMID (0x0001)

int opal_send_recv(int fd, uint16_t com_id, uint8_t *req_buf,
		int req_buf_len, uint8_t *resp_buf, int resp_buf_len);

int opal_send(int fd, uint8_t proto_id, uint16_t com_id, uint8_t *buf, int buf_len);
int opal_recv(int fd, uint16_t com_id, uint8_t *buf, int buf_len);

#endif /* _NVME_ACCESS_H_ */
