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

#ifndef __PACKET_H__
#define __PACKET_H__

#define PKTSIZE (64*1024)

struct packet 
{
	int len;		/* Total packet length */
	int sentlen;		/* Length of chunk currently transmitted */
	int offset;		/* Current offset */
	char data[PKTSIZE];	/* The data */
};

void packet_init(struct packet *);
int packet_sending(struct packet *);
void packet_advance(struct packet *);
int packet_len_to_send(struct packet *);
int packet_fill(struct packet *, char *, unsigned long);
void packet_send_len(struct packet *, int);

#endif
