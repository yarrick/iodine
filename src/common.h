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

#ifndef __COMMON_H__
#define __COMMON_H__

/* Last byte of raw header is the command */
#define RAW_HDR_LEN 4
#define RAW_HDR_IDENT_LEN 3
#define RAW_HDR_CMD 3
#define RAW_HDR_CMD_LOGIN 0x10
#define RAW_HDR_CMD_DATA  0x20
#define RAW_HDR_CMD_PING  0x30

#define RAW_HDR_CMD_MASK  0xF0
#define RAW_HDR_USR_MASK  0x0F
#define RAW_HDR_GET_CMD(x) ((x)[RAW_HDR_CMD] & RAW_HDR_CMD_MASK)
#define RAW_HDR_GET_USR(x) ((x)[RAW_HDR_CMD] & RAW_HDR_USR_MASK)
extern const unsigned char raw_header[RAW_HDR_LEN];

#include "config.h"

#include <stdarg.h>
#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#define DNS_PORT 53

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define QUERY_NAME_SIZE 256

#define T_PRIVATE 65399
/* Undefined RR type; "private use" range, see
 * http://www.bind9.net/dns-parameters */
#define T_UNSET 65432
/* Unused RR type, never actually sent */

struct packet
{
	unsigned int len;	/* Total packet length */
	unsigned int sentlen;	/* Length of chunk currently transmitted */
	unsigned int offset;	/* Current offset */
	char data[64*1024];	/* The data */
	char seqno;		/* The packet sequence number */
	char fragment;		/* Fragment index */
};

struct query {
	char name[QUERY_NAME_SIZE];
	unsigned short type;
	unsigned short rcode;
	unsigned short id;
	struct sockaddr_storage local;
	socklen_t locallen;
	struct sockaddr_storage remote;
	socklen_t remotelen;
	unsigned short id2;
	struct sockaddr_storage remote2;
	socklen_t remotelen2;
};

enum connection {
	CONN_RAW_UDP = 0,
	CONN_DNS_NULL,
	CONN_MAX
};

char *format_inaddr(struct in_addr *addr);
char *format_addr(struct sockaddr_storage *sockaddr, socklen_t sockaddr_len);
int get_addr(char *host, int port, int addr_family, int flags,
             struct sockaddr_storage *out, socklen_t *outlen);

int build_netmask(int netbits, struct in_addr *addr);

int check_topdomain(char *, int, char **);

int query_datalen(const char *qname, const char *topdomain);

int recent_seqno(int , int);

void fd_set_close_on_exec(int fd);

unsigned char ascii_tolower(unsigned char c);

#endif
