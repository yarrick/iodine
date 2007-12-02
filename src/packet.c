/*
 * Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <string.h>

#include "common.h"
#include "packet.h"

/**
 *	Is some part of this packet sent?
 */
int
packet_empty(struct packet *packet)
{
	return (packet->len == 0);
}

/**
 *	Acknowledge that the latest send was succesful
 */
void
packet_advance(struct packet *packet)
{
	packet->offset += packet->sentlen;
	packet->sentlen = 0;
	if (packet->offset == packet->len) {
		/* Packet completed */
		packet->offset = 0;
		packet->len = 0;
	}
}


/**
 *	The length left to send
 */
int
packet_len_to_send(struct packet *packet)
{
	return packet->len - packet->offset;
}

/**
 *	Fill the packet with data
 */
int
packet_fill(struct packet *packet, char *data, unsigned long datalen)
{
	memcpy(packet->data, data, MIN(datalen, PKTSIZE));
	packet->sentlen = 0;
	packet->offset = 0;
	packet->len = datalen;
	
	return packet->len;
}

/**
 *	Clear packet struct, mark empty
 */
void
packet_init(struct packet *packet)
{
	packet->sentlen = 0;
	packet->offset = 0;
	packet->len = 0;
}

/**
 *	Mark len number of bytes as being sent
 */
void
packet_send_len(struct packet *packet, int len)
{
	packet->sentlen = len;
}

