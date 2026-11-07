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

#ifdef IP_OPT_DONT_FRAG
	/* Set dont-fragment ip header flag */
	flag = DONT_FRAG_VALUE;
	setsockopt(fd, IPPROTO_IP, IP_OPT_DONT_FRAG, (const void*) &flag, sizeof(flag));
#endif

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

