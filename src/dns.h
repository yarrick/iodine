/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#ifndef __DNS_H__
#define __DNS_H__

#include "common.h"

typedef enum {
	QR_QUERY = 0,
	QR_ANSWER = 1
} qr_t;

int dns_settarget(const char*);
void dns_set_topdomain(const char*);

int dns_sending();
void dns_handle_tun(int, char *, int);
void dns_ping(int);
void dns_send_version(int, int);
void dns_login(int, char *, int);
int dns_read(int, char *, int);
int dns_encode_hostname(const char *, char *, int);
int dns_encode(char *, size_t, struct query *, qr_t, char *, size_t);
int dns_decode(char *, size_t, struct query *, qr_t, char *, size_t);

int dnsd_read(int, struct query*, char *, int);
void dnsd_send(int, struct query*, char *, int);

int dnsd_haspacket();
int dnsd_hasack();
void dnsd_forceack(int);
void dnsd_queuepacket(const char *, const int);

int dns_parse_reply(char *, int, char *, int);

#endif /* _DNS_H_ */
