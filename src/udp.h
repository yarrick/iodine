/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __UDP_H__
#define __UDP_H__

#include "config.h"
#include "common.h"

#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

int open_udp(struct sockaddr_storage *, socklen_t);
int open_udp_opt(struct sockaddr_storage *sockaddr, socklen_t sockaddr_len, int v6only);
int open_udp_from_host(char *host, int port, int addr_family, int flags);
void close_udp(int);

int read_udp(int fd, char *packet, size_t packetlen, struct query *q);
int send_udp(int fd, const char *packet, size_t packetlen, struct query *q);
#endif
