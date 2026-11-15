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

#include "common.h"
#include "sock.h"

/* Struct with IPv4 and IPv6 file descriptors.
 * Need to be passed on down to tunneling code since we can get a
 * packet on one fd meant for a user on the other.
 */
struct dnsfd {
	sock_t v4fd;
	sock_t v6fd;
};

struct server_params {
	const char *topdomain;
	const char *password;
	int users;
	int check_ip;
	int tunnel_mtu;
	struct in_addr server_ip;
	int netmask;
	struct in_addr nameserver_ip;
	struct net_addr bind_addr;
};

void server_init(struct server_params *params);
int server_tunnel(sock_t tun_fd, struct dnsfd *dns_fds, sock_t bind_fd, int max_idle_time);
void server_stop(void);
int tunnel_bind(sock_t bind_fd, struct dnsfd *dns_fds);
int tunnel_dns(sock_t tun_fd, sock_t dns_fd, struct dnsfd *dns_fds, sock_t bind_fd);
int tunnel_tun(sock_t tun_fd, struct dnsfd *dns_fds);

#endif
