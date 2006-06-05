/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <err.h>

#include "tun.h"
#include "dns.h"

#define MAX(a,b) ((a)>(b)?(a):(b))

static int
tunnel(int tun_fd, int dns_fd)
{
	int i;
	fd_set fds;
	struct timeval tv;
	
	for (;;) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if(i < 0) {
			warn("select");
			return 1;
		}
		
		if(i == 0) {
			dns_ping();	
		} else {
			if(FD_ISSET(tun_fd, &fds)) {
					
			}
			if(FD_ISSET(dns_fd, &fds)) {
				
			} 
		}
	}

	return 0;
}

int
main()
{
	int tun_fd;
	int dns_fd;

	tun_fd = open_tun();
	dns_fd = open_dns();
	dns_set_peer("192.168.11.101");
	dns_query(dns_fd, "kryo.se", 1);

	tunnel(tun_fd, dns_fd);

	close_dns(dns_fd);
	close_tun(tun_fd);	

	return 0;
}
