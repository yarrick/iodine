/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015 Frekk van Blagh <frekk@frekkworks.com>
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

#ifndef __SERVER_H__
#define __SERVER_H__

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#define _XPG4_2
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <grp.h>
#include <sys/uio.h>
#include <pwd.h>
#include <netdb.h>
#include <syslog.h>
#endif

#define DNSCACHE_LEN 10
/* Undefine to disable. Should be less than 18; also see comments in iodined.c */

#define QMEMPING_LEN 30
/* Max advisable: 64k/2 = 32000. Total mem usage: QMEMPING_LEN * USERS * 6 bytes */

#define QMEMDATA_LEN 15
/* Max advisable: 36/2 = 18. Total mem usage: QMEMDATA_LEN * USERS * 6 bytes */

/* Number of fragments in outgoing buffer.
 * Mem usage: USERS * (MAX_FRAGLEN * OUTFRAGBUF_LEN + sizeof(struct window_buffer) */
#define OUTFRAGBUF_LEN 64

/* Number of fragments in incoming buffer
 * Minimum recommended = ((max packet size or MTU) / (max up fragsize)) * 2
 * ie. (1200 / 100) * 2 = 24 */
#define INFRAGBUF_LEN 32

#define PASSWORD_ENV_VAR "IODINED_PASS"

#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define dstaddr(x) ((struct in_addr *) CMSG_DATA(x))
#elif defined IP_PKTINFO
# define DSTADDR_SOCKOPT IP_PKTINFO
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#endif

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#if !defined(BSD) && !defined(__GLIBC__)
static char *__progname;
#endif

/* Struct with IPv4 and IPv6 file descriptors.
 * Need to be passed on down to tunneling code since we can get a
 * packet on one fd meant for a user on the other.
 */
struct dnsfd {
	int v4fd;
	int v6fd;
};

typedef enum {
	VERSION_ACK,
	VERSION_NACK,
	VERSION_FULL
} version_ack_t;

extern char *topdomain;
extern char password[33];
extern struct encoder *b32;
extern struct encoder *b64;
extern struct encoder *b64u;
extern struct encoder *b128;

extern int check_ip;
extern int my_mtu;
extern in_addr_t my_ip;
extern int netmask;

extern in_addr_t ns_ip;

extern int bind_port;
extern int debug;

void server_init();
void server_stop();
int server_tunnel(int tun_fd, struct dnsfd *dns_fds, int bind_fd, int max_idle_time);

int read_dns(int fd, struct dnsfd *dns_fds, int tun_fd, struct query *q);
void write_dns(int fd, struct query *q, char *data, size_t datalen, char downenc);
void handle_full_packet(int tun_fd, struct dnsfd *dns_fds, int userid, uint8_t *data, size_t len);
void handle_null_request(int tun_fd, int dns_fd, struct dnsfd *dns_fds, struct query *q, int domain_len);
void handle_ns_request(int dns_fd, struct query *q);
void handle_a_request(int dns_fd, struct query *q, int fakeip);

#endif /* __SERVER_H__ */
