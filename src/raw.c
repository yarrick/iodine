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

#include "config.h"

#include <string.h>

#include "common.h"
#include "raw.h"
#include "udp.h"
#include "ui.h"

#define RAW_HDR_IDENT_LEN 3
#define RAW_HDR_CMD 3
#define RAW_HDR_CMD_MASK 0xF0
#define RAW_HDR_USR_MASK 0x0F

/* The raw header used when not using DNS protocol */
static const unsigned char raw_header[RAW_HDR_LEN] = { 0x10, 0xd1, 0x9e, 0x00 };

int
raw_decode(struct raw_msg *msg, const char *packet, size_t len)
{
	unsigned char cmdbyte;

	if (len < RAW_HDR_LEN)
		return 0;
	if (memcmp(packet, raw_header, RAW_HDR_IDENT_LEN) != 0)
		return 0;

	cmdbyte = (unsigned char) packet[RAW_HDR_CMD];
	msg->cmd = cmdbyte & RAW_HDR_CMD_MASK;
	msg->userid = cmdbyte & RAW_HDR_USR_MASK;
	msg->data = packet + RAW_HDR_LEN;
	msg->len = len - RAW_HDR_LEN;
	return 1;
}

int
raw_encode(char *buf, size_t buflen, const struct raw_msg *msg)
{
	size_t datalen;
	size_t len;

	if (buflen < RAW_HDR_LEN)
		return -1;

	datalen = (msg->data != NULL) ? msg->len : 0;
	len = MIN(buflen - RAW_HDR_LEN, datalen);
	memcpy(buf, raw_header, RAW_HDR_LEN);
	if (len > 0)
		memcpy(buf + RAW_HDR_LEN, msg->data, len);

	buf[RAW_HDR_CMD] = (msg->cmd & RAW_HDR_CMD_MASK) | (msg->userid & RAW_HDR_USR_MASK);
	return (int) (len + RAW_HDR_LEN);
}

int
send_raw(sock_t fd, const struct raw_msg *msg, struct udp_addr *addr)
{
	char packet[4096];
	int len;

	len = raw_encode(packet, sizeof(packet), msg);
	if (len < 0)
		return -1;

	ui_debug(2, "TX-raw: %s, cmd %d, %d bytes\n",
		 format_addr(&addr->remote), msg->cmd, len);

	return send_udp(fd, packet, len, addr);
}
