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

#include <stdint.h>
#include <string.h>

#include "config.h"

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "common.h"
#include "compat.h"
#include "dns.h"
#include "ext_ip.h"
#include "random.h"
#include "sock.h"
#include "udp.h"
#include "ui.h"

/* Ask opendns.com DNS service for external ip */
int
get_external_ip(struct in_addr *ip)
{
	static const char target[] = "myip.opendns.com";
	struct dns_msg query;
	struct net_addr addr;
	int attempt;
	int res;
	sock_t fd;
	int out_len = 0;
	memset(&query, 0, sizeof(query));

	query.type = T_A;
	query.edns0 = true;
	if (get_addr("resolver1.opendns.com", DNS_PORT, AF_INET, 0, &addr))
		return 1;

	fd = open_udp_from_host(NULL, 0, AF_INET, AI_PASSIVE);
	if (fd == INVALID_SOCK) return 2;

	for (attempt = 0; attempt < 3; attempt++) {
		char buf[64*1024];
		int buflen;

		if (attempt)
			ui_log("Retrying external IP lookup\n");
		secure_random(&query.id, sizeof(query.id));
		buflen = sizeof(buf);
		buflen = dns_encode(buf, buflen, &query, QR_QUERY, target, strlen(target));
		if (buflen < 0) continue;

		sendto(fd, buf, buflen, 0, (struct sockaddr*) &addr.addr, addr.addrlen);

		res = sock_select((1 + attempt) * 1000, NULL, fd);
		if (res > 0) {
			buflen = sizeof(buf);
			buflen = recv(fd, buf, buflen, 0);
			if (buflen > 0) {
				out_len = dns_decode_answer((char *)ip, sizeof(struct in_addr),
							    &query, buf, buflen);
				if (out_len > 0) break;
			}
		}
	}

	close_udp(fd);
	return (out_len != sizeof(struct in_addr));
}
