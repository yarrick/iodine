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

#include "config.h"

#include <string.h>
#include <unistd.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#else
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "common.h"
#include "compat.h"
#include "ui.h"
#include "udp.h"

int
open_udp(struct sockaddr_storage *sockaddr, socklen_t sockaddr_len)
{
	return open_udp_opt(sockaddr, sockaddr_len, -1);
}

int
open_udp_opt(struct sockaddr_storage *sockaddr, socklen_t sockaddr_len, int v6only)
{
	int flag;
	int fd;

	if ((fd = socket(sockaddr->ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		err(1, "socket");
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &flag, sizeof(flag));

	fd_set_close_on_exec(fd);

	if (sockaddr->ss_family == AF_INET6 && v6only >= 0) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void*) &v6only, sizeof(v6only));
	}

	if (sockaddr->ss_family == AF_INET6) {
#ifdef IPV6_RECVPKTINFO
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void*) &flag, sizeof(flag));
#endif
#ifdef IPV6_PKTINFO
		setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, (const void*) &flag, sizeof(flag));
#endif
	}
	if (sockaddr->ss_family == AF_INET) {
#ifdef DSTADDR_SOCKOPT
		/* To get destination address from each UDP datagram, see read_dns() */
		setsockopt(fd, IPPROTO_IP, DSTADDR_SOCKOPT, (const void*) &flag, sizeof(flag));
#endif

#ifdef IP_OPT_DONT_FRAG
		/* Set dont-fragment ip header flag */
		flag = DONT_FRAG_VALUE;
		setsockopt(fd, IPPROTO_IP, IP_OPT_DONT_FRAG, (const void*) &flag, sizeof(flag));
#endif
	}

	if (bind(fd, (struct sockaddr*) sockaddr, sockaddr_len) < 0)
		err(1, "bind() to %s", format_addr(sockaddr, sockaddr_len));

	ui_log("Opened IPv%d UDP socket\n", sockaddr->ss_family == AF_INET6 ? 6 : 4);

	return fd;
}

int
open_udp_from_host(char *host, int port, int addr_family, int flags)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int res;

	res = get_addr(host, port, addr_family, flags, &addr, &addrlen);
	if (res)
		return res;

	return open_udp(&addr, addrlen);
}

void
close_udp(int fd)
{
	close(fd);
}

int
read_udp(int fd, char *packet, size_t packetlen, struct query *q)
{
	socklen_t addrlen;
	int r;
#ifndef WINDOWS
	char control[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;

	addrlen = sizeof(struct sockaddr_storage);
	iov.iov_base = packet;
	iov.iov_len = packetlen;

	msg.msg_name = (caddr_t) &q->remote;
	msg.msg_namelen = (unsigned) addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;

	r = recvmsg(fd, &msg, 0);
	addrlen = msg.msg_namelen;
#else
	addrlen = sizeof(struct sockaddr_storage);
	r = recvfrom(fd, packet, packetlen, 0, (struct sockaddr *)&q->remote, &addrlen);
#endif /* !WINDOWS */
	if (r < 0) {
		warn("read_udp");
		return r;
	}
	q->remotelen = addrlen;

	memset(&q->local, 0, sizeof(struct sockaddr_storage));
	q->locallen = sizeof(struct sockaddr_storage);
#ifndef WINDOWS
	/* Read destination IP address */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		cmsg = CMSG_NXTHDR(&msg, cmsg)) {

		if (cmsg->cmsg_level == IPPROTO_IP &&
			cmsg->cmsg_type == DSTADDR_SOCKOPT) {

			struct sockaddr_in *addr = (struct sockaddr_in *) &q->local;
			addr->sin_family = AF_INET;
			addr->sin_addr = *dstaddr(cmsg);
			q->locallen = sizeof(*addr);
			break;
		}
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
			cmsg->cmsg_type == IPV6_PKTINFO) {

			struct in6_pktinfo *pktinfo;
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->local;
			pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
			addr->sin6_family = AF_INET6;
			memcpy(&addr->sin6_addr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
			q->locallen = sizeof(*addr);
			break;
		}
	}
#endif

	return r;
}

