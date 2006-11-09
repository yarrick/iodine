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

#ifndef _DNS_H_
#define _DNS_H_

int open_dns(const char *, int, in_addr_t);
int dns_settarget(const char*);
void close_dns(int);

int dns_sending();
void dns_handle_tun(int, char *, int);
void dns_ping(int);
void dns_handshake(int);
int dns_read(int, char *, int);
int dns_encode_hostname(const char *, char *, int);

extern struct sockaddr_in peer;

int dnsd_read(int, struct query*, char *, int);
void dnsd_send(int, struct query*, char *, int);

int dnsd_haspacket();
int dnsd_hasack();
void dnsd_forceack(int);
void dnsd_queuepacket(const char *, const int);

int dns_parse_reply(char *, int, char *, int);


#endif /* _DNS_H_ */
