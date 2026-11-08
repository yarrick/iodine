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

#ifndef __SERVER_H__
#define __SERVER_H__

/* Struct with IPv4 and IPv6 file descriptors.
 * Need to be passed on down to tunneling code since we can get a
 * packet on one fd meant for a user on the other.
 */
struct dnsfd {
	int v4fd;
	int v6fd;
};

struct server_params {
	const char *topdomain;
	const char *password;
	int users;
	int check_ip;
	int tunnel_mtu;
	in_addr_t server_ip;
	int netmask;
	in_addr_t nameserver_ip;
	struct sockaddr *bind_addr;
	socklen_t bind_addrlen;
};

int get_external_ip(struct in_addr *ip);

void server_init(struct server_params *params);
int server_tunnel(int tun_fd, struct dnsfd *dns_fds, int bind_fd, int max_idle_time);
void server_stop(void);
int tunnel_dns(int tun_fd, int dns_fd, struct dnsfd *dns_fds, int bind_fd);

#endif
