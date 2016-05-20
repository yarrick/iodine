/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "window.h"

extern int debug;
extern int stats;

#define PENDING_QUERIES_LENGTH (MAX(windowsize_up, windowsize_down) * 3)

struct query_tuple {
	int id; /* DNS query / response ID */
	struct timeval time; /* time sent or 0 if cleared */
};

void client_init();
void client_stop();

enum connection client_get_conn();
const char *client_get_raw_addr();

void client_rotate_nameserver();
void client_set_nameservers(struct socket *, int);
void client_set_topdomain(const char *cp);
void client_set_password(const char *cp);
int client_set_qtype(char *qtype);
char *client_get_qtype();
void client_set_downenc(char *encoding);
void client_set_compression(int up, int down);
void client_set_dnstimeout(int, int, int, int);
void client_set_lazymode(int lazy_mode);
void client_set_windowsize(size_t, size_t);
void client_set_hostname_maxlen(size_t i);
void client_set_interval(int, int);

int client_handshake(int dns_fd, int raw_mode, int autodetect_frag_size, int fragsize);
int client_tunnel(int tun_fd, int dns_fd);

int parse_data(uint8_t *data, size_t len, struct fragment *f, int *immediate);
int handshake_waitdns(int dns_fd, char *buf, size_t buflen, char cmd, int timeout);
void handshake_switch_options(int dns_fd, int lazy, int compression, char denc);
int send_ping(int fd, int ping_response, int ack, int timeout);

#endif
