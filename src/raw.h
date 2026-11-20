/*
 * Copyright (c) 2006-2026 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __RAW_H__
#define __RAW_H__

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "common.h"
#include "sock.h"

/* Last byte of raw header is the command */
#define RAW_HDR_LEN 4
#define RAW_HDR_CMD_LOGIN 0x10
#define RAW_HDR_CMD_DATA  0x20
#define RAW_HDR_CMD_PING  0x30

struct raw_msg {
	uint8_t cmd;
	uint8_t userid;
	const char *data;
	size_t len;
};

int raw_decode(struct raw_msg *msg, const char *packet, size_t len);
int raw_encode(char *buf, size_t buflen, const struct raw_msg *msg);
int send_raw(sock_t fd, const struct raw_msg *msg, struct udp_addr *addr);

#endif
