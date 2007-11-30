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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define QUERY_NAME_SIZE 256

struct packet 
{
	int len;		/* Total packet length */
	int sentlen;		/* Length of chunk currently transmitted */
	int offset;		/* Current offset */
	char data[64*1024];	/* The data */
};

struct query {
	char name[QUERY_NAME_SIZE];
	short type;
	short id;
	struct sockaddr from;
	int fromlen;
};

int open_dns(int, in_addr_t);
void close_dns(int);

void do_chroot(char *);
void do_detach();

void read_password(char*, size_t);

#endif
