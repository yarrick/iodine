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

#include <string.h>
#include <sys/time.h>

#include "config.h"

#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser_compat.h>
#endif
#include <netdb.h>
#include <sys/select.h>
#endif

#include "common.h"
#include "compat.h"
#include "dns.h"
#include "ext_ip.h"
#include "random.h"
#include "udp.h"
#include "ui.h"

/* Ask opendns.com DNS service for external ip */
int
get_external_ip(struct in_addr *ip)
{
	static const char target[] = "myip.opendns.com";
	struct query query;
	int attempt;
	int res;
	int fd;
	int out_len = 0;
	memset(&query, 0, sizeof(query));

	query.type = T_A;
	if (get_addr("resolver1.opendns.com", DNS_PORT, AF_INET, 0, &query.remote, &query.remotelen))
		return 1;

	fd = open_udp_from_host(NULL, 0, AF_INET, AI_PASSIVE);
	if (fd < 0) return 2;

	for (attempt = 0; attempt < 3; attempt++) {
		char buf[64*1024];
		int buflen;
		fd_set fds;
		struct timeval tv;

		if (attempt)
			ui_log("Retrying external IP lookup\n");
		secure_random(&query.id, sizeof(query.id));
		buflen = sizeof(buf);
		buflen = dns_encode(buf, buflen, &query, QR_QUERY, target, strlen(target));
		if (buflen < 0) continue;

		sendto(fd, buf, buflen, 0, (struct sockaddr*)&query.remote, query.remotelen);

		tv.tv_sec = 1 + attempt;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		res = select(fd + 1, &fds, NULL, NULL, &tv);
		if (res > 0) {
			buflen = sizeof(buf);
			buflen = recv(fd, buf, buflen, 0);
			if (buflen > 0) {
				out_len = dns_decode((char *)ip, sizeof(struct in_addr),
						     &query, QR_ANSWER, buf, buflen);
				if (out_len > 0) break;
			}
		}
	}

	close_udp(fd);
	return (out_len != sizeof(struct in_addr));
}
