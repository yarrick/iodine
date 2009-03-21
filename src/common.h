/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#ifdef WINDOWS32
#include "windows.h"
#else
#include <sys/socket.h>
#include <err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif


#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define QUERY_NAME_SIZE 256

#if defined IP_RECVDSTADDR 
# define DSTADDR_SOCKOPT IP_RECVDSTADDR 
# define dstaddr(x) ((struct in_addr *) CMSG_DATA(x)) 
#elif defined IP_PKTINFO 
# define DSTADDR_SOCKOPT IP_PKTINFO 
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr)) 
#endif

#if defined IP_MTU_DISCOVER
  /* Linux */
# define IP_OPT_DONT_FRAG IP_MTU_DISCOVER
# define DONT_FRAG_VALUE IP_PMTUDISC_DO
#elif defined IP_DONTFRAG
  /* FreeBSD */
# define IP_OPT_DONT_FRAG IP_DONTFRAG
# define DONT_FRAG_VALUE 1
#elif defined IP_DONTFRAGMENT
  /* Winsock2 */
# define IP_OPT_DONT_FRAG IP_DONTFRAGMENT
# define DONT_FRAG_VALUE 1
#endif

struct packet 
{
	int len;		/* Total packet length */
	int sentlen;		/* Length of chunk currently transmitted */
	int offset;		/* Current offset */
	char data[64*1024];	/* The data */
	char seqno;		/* The packet sequence number */
	char fragment;		/* Fragment index */
};

struct query {
	char name[QUERY_NAME_SIZE];
	unsigned short type;
	unsigned short id;
	struct in_addr destination;
	struct sockaddr from;
	int fromlen;
};

void check_superuser(void (*usage_fn)(void));
int open_dns(int, in_addr_t);
void close_dns(int);

void do_chroot(char *);
void do_detach();

void read_password(char*, size_t);

int check_topdomain(char *);

#ifdef WINDOWS32
int inet_aton(const char *cp, struct in_addr *inp);

void err(int eval, const char *fmt, ...);
void warn(const char *fmt, ...);
void errx(int eval, const char *fmt, ...);
void warnx(const char *fmt, ...);
#endif

#endif
