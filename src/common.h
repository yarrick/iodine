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

#ifdef WINDOWS32
#include "windows.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#define DNS_PORT 53

#if _WIN32 || _WIN64
#if _WIN64
#define BITS_64
#else
#define BITS_32
#endif
#endif

#if __GNUC__
#if __x86_64__ || __ppc64__
#define BITS_64 1
#else
#define BITS_32 1
#endif
#endif

/* Determine appropriate format specifier for long int on 32/64 bit systems */
#if BITS_64
#define FMT_LONG "l"
#else
#define FMT_LONG ""
#endif

/* For convenience and shortness */
#define L FMT_LONG

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#define QUERY_NAME_SIZE 256

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

#ifndef GITREVISION
#define GITREVISION "GIT"
#endif

#define T_PRIVATE 65399
/* Undefined RR type; "private use" range, see http://www.bind9.net/dns-parameters */
#define T_UNSET 65432
/* Unused RR type, never actually sent */

#define DOWNSTREAM_HDR 3
#define DOWNSTREAM_PING_HDR 7
#define UPSTREAM_HDR 6
#define UPSTREAM_PING 11

/* handy debug printing macro */
#ifdef DEBUG_BUILD
#define TIMEPRINT(...) \
		struct timeval currenttime;\
		gettimeofday(&currenttime, NULL);\
		fprintf(stderr, "%03ld.%03ld ", (long) currenttime.tv_sec, (long) currenttime.tv_usec / 1000);\
		fprintf(stderr, __VA_ARGS__);

#define DEBUG(level, ...) \
		if (INSTANCE.debug >= level) {\
			TIMEPRINT("[D%d %s:%d] ", level, __FILE__, __LINE__); \
			fprintf(stderr, __VA_ARGS__);\
			fprintf(stderr, "\n");\
		}
#else
#define TIMEPRINT(...) \
		fprintf(stderr, __VA_ARGS__);

#define DEBUG(level, ...) \
		if (INSTANCE.debug >= level) {\
			fprintf(stderr, "[D%d] ", level); \
			fprintf(stderr, __VA_ARGS__);\
			fprintf(stderr, "\n");\
		}
#endif


struct query {
	char name[QUERY_NAME_SIZE];
	unsigned short type;
	unsigned short rcode;
	int id;	/* id < 0: unusued */
	struct sockaddr_storage destination;
	socklen_t dest_len;
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct timeval time_recv;
};

enum connection {
	CONN_RAW_UDP = 0,
	CONN_DNS_NULL,
	CONN_MAX
};

void check_superuser(void (*usage_fn)(void));
char *format_addr(struct sockaddr_storage *sockaddr, int sockaddr_len);
int get_addr(char *, int, int, int, struct sockaddr_storage *);
int open_dns(struct sockaddr_storage *, size_t);
int open_dns_opt(struct sockaddr_storage *sockaddr, size_t sockaddr_len, int v6only);
int open_dns_from_host(char *host, int port, int addr_family, int flags);
void close_socket(int);

int open_tcp_nonblocking(struct sockaddr_storage *addr, char **error);
int check_tcp_error(int fd, char **error);

void do_chroot(char *);
void do_setcon(char *);
void do_detach();
void do_pidfile(char *);

void read_password(char*, size_t);

int check_topdomain(char *, char **);

extern double difftime(time_t, time_t);

#if defined(WINDOWS32) || defined(ANDROID)
#ifndef ANDROID
int inet_aton(const char *cp, struct in_addr *inp);
#endif

void err(int eval, const char *fmt, ...);
void warn(const char *fmt, ...);
void errx(int eval, const char *fmt, ...);
void warnx(const char *fmt, ...);
#endif

#ifndef WINDOWS32
void fd_set_close_on_exec(int fd);
#endif

#endif
