/*
 * Copyright (c) 2026 Erik Ekman <yarrick@kryo.se>
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "src/common.h"
#include "src/dns.h"
#include "src/encoding.h"
#include "src/fw_query.h"
#include "src/server.h"
#include "src/sock.h"
#include "src/tun.h"
#include "src/udp.h"
#include "src/user.h"

#include "fuzz_main.h"

#define USERS 16
#define FUZZ_BIND_FD ((sock_t) 1)

/*
 * Uncompressed 32-byte TUN (4B) + IPv4 ICMP echo request (28B)
 * from 10.0.0.5 to 10.0.0.1.
 */
static const uint8_t fuzz_tun_pkt[32] = {
	0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c,
	0x12, 0x34, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
	0x0a, 0x00, 0x00, 0x05, 0x0a, 0x00, 0x00, 0x01,
	0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01
};

static int fuzz_ipv6 = 0;
static uint8_t fuzz_src_byte = 2;
static int fuzz_upstream = 0;
static char tun_rx_buf[64 * 1024];
static size_t tun_rx_len = 0;

int
read_udp(sock_t fd, char *packet, size_t packetlen, struct udp_addr *addr)
{
	(void)fd;

	if (current_pkt == NULL || current_pkt_len == 0 || current_pkt_len > packetlen)
		return -1;

	memset(addr, 0, sizeof(*addr));

	if (fuzz_ipv6) {
		struct sockaddr_in6 *rem6 = (struct sockaddr_in6 *) &addr->remote.addr;
		struct sockaddr_in6 *loc6 = (struct sockaddr_in6 *) &addr->local.addr;

		rem6->sin6_family = AF_INET6;
		rem6->sin6_addr.s6_addr[15] = fuzz_src_byte;
		rem6->sin6_port = htons(53000);
		addr->remote.addrlen = sizeof(*rem6);

		loc6->sin6_family = AF_INET6;
		loc6->sin6_addr.s6_addr[15] = 1;
		loc6->sin6_port = htons(53);
		addr->local.addrlen = sizeof(*loc6);
	} else {
		struct sockaddr_in *rem = (struct sockaddr_in *) &addr->remote.addr;
		struct sockaddr_in *loc = (struct sockaddr_in *) &addr->local.addr;

		rem->sin_family = AF_INET;
		rem->sin_addr.s_addr = htonl(0x7f000000U | fuzz_src_byte);
		rem->sin_port = htons(53000);
		addr->remote.addrlen = sizeof(*rem);

		loc->sin_family = AF_INET;
		loc->sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
		loc->sin_port = htons(53);
		addr->local.addrlen = sizeof(*loc);
	}

	memcpy(packet, current_pkt, current_pkt_len);
	return (int) current_pkt_len;
}

void
fuzz_on_tun_write(const char *data, size_t len)
{
	char tmp[4];

	/* Need 4B TUN header + 20B minimum IPv4 header */
	if (len < 24 || len > sizeof(tun_rx_buf))
		return;

	memcpy(tun_rx_buf, data, len);
	/* Swap IPv4 src (16..19) and dst (20..23) so it routes back to sender */
	memcpy(tmp, tun_rx_buf + 16, 4);
	memcpy(tun_rx_buf + 16, tun_rx_buf + 20, 4);
	memcpy(tun_rx_buf + 20, tmp, 4);
	tun_rx_len = len;
}

ssize_t
read_tun(sock_t tun_fd, char *buf, size_t len)
{
	size_t n = tun_rx_len;
	(void)tun_fd;

	if (n == 0 || n > len)
		return -1;
	memcpy(buf, tun_rx_buf, n);
	tun_rx_len = 0;
	return (ssize_t) n;
}

static void
init_user_stage(int userid, int authenticated, int options_locked, int raw_auth)
{
	users[userid].active = 1;
	users[userid].authenticated = authenticated;
	users[userid].authenticated_raw = raw_auth;
	users[userid].options_locked = options_locked;
	users[userid].seed = FUZZ_SEED;
	users[userid].last_pkt = time(NULL);
	users[userid].up_encoder = &base32_ops;
	users[userid].down_encoder = &base32_ops;
	users[userid].fragsize = options_locked ? 768 : 100;
	users[userid].conn = raw_auth ? CONN_RAW_UDP : CONN_DNS_NULL;
	users[userid].lazy = 0;

	memset(&users[userid].host, 0, sizeof(users[userid].host));
	memset(&users[userid].raw_addr, 0, sizeof(users[userid].raw_addr));
	if (fuzz_ipv6) {
		struct sockaddr_in6 *host6 = (struct sockaddr_in6 *) &users[userid].host.addr;
		host6->sin6_family = AF_INET6;
		host6->sin6_addr.s6_addr[15] = 2;
		host6->sin6_port = htons(53000);
		users[userid].host.addrlen = sizeof(*host6);
	} else {
		struct sockaddr_in *host = (struct sockaddr_in *) &users[userid].host.addr;
		host->sin_family = AF_INET;
		host->sin_addr.s_addr = htonl(0x7f000002); /* 127.0.0.2 */
		host->sin_port = htons(53000);
		users[userid].host.addrlen = sizeof(*host);
	}
	if (raw_auth) {
		users[userid].raw_addr.remote = users[userid].host;
	}

	for (int q = 0; q < QMEMPING_LEN; q++)
		users[userid].qmem_ping.entries[q].type = T_UNSET;
	users[userid].qmem_ping.lastfilled = QMEMPING_LEN - 1;
	users[userid].qmem_ping.capacity = QMEMPING_LEN;

	for (int q = 0; q < QMEMDATA_LEN; q++)
		users[userid].qmem_data.entries[q].type = T_UNSET;
	users[userid].qmem_data.lastfilled = QMEMDATA_LEN - 1;
	users[userid].qmem_data.capacity = QMEMDATA_LEN;
}

static void
reset_user(int userid)
{
	users[userid].active = 0;
	users[userid].authenticated = 0;
	users[userid].authenticated_raw = 0;
	users[userid].options_locked = 0;
	users[userid].disabled = 0;
	users[userid].last_pkt = 0;
	users[userid].seed = 0;
	memset(&users[userid].host, 0, sizeof(users[userid].host));
	memset(&users[userid].raw_addr, 0, sizeof(users[userid].raw_addr));
	users[userid].q.id = 0;
	users[userid].q.id2 = 0;
	users[userid].q_sendrealsoon.id = 0;
	users[userid].q_sendrealsoon.id2 = 0;
	users[userid].q_sendrealsoon_new = 0;
	users[userid].inpacket.len = 0;
	users[userid].inpacket.sentlen = 0;
	users[userid].inpacket.offset = 0;
	users[userid].inpacket.seqno = 0;
	users[userid].inpacket.fragment = 0;
	users[userid].outpacket.len = 0;
	users[userid].outpacket.sentlen = 0;
	users[userid].outpacket.offset = 0;
	users[userid].outpacket.seqno = 0;
	users[userid].outpacket.fragment = 0;
	users[userid].outfragresent = 0;
	users[userid].up_encoder = NULL;
	users[userid].down_encoder = NULL;
	users[userid].out_acked_seqno = 0;
	users[userid].out_acked_fragment = 0;
	users[userid].fragsize = 0;
	users[userid].conn = CONN_DNS_NULL;
	users[userid].lazy = 0;
#ifdef OUTPACKETQ_LEN
	users[userid].outpacketq_nexttouse = 0;
	users[userid].outpacketq_filled = 0;
#endif
#ifdef DNSCACHE_LEN
	for (int i = 0; i < DNSCACHE_LEN; i++) {
		users[userid].dnscache_q[i].id = 0;
		users[userid].dnscache_answerlen[i] = 0;
	}
	users[userid].dnscache_lastfilled = 0;
#endif
}

void
fuzz_reset_directives(void)
{
	fuzz_ipv6 = 0;
	fuzz_src_byte = 2;
	fuzz_upstream = 0;
}

void
fuzz_reset_pkt_directives(void)
{
	fuzz_src_byte = 2;
	fuzz_upstream = 0;
}

int
fuzz_parse_meta(char cmd, char arg)
{
	if (cmd == 'v' || cmd == 'V') {
		if (arg == '4') {
			fuzz_ipv6 = 0;
			return 0;
		}
		if (arg == '6') {
			fuzz_ipv6 = 1;
			return 0;
		}
		return -1;
	}

	if (cmd == 'n' || cmd == 'N') {
		if (arg == '0') {
			fuzz_upstream = 0;
			return 0;
		}
		if (arg == '1') {
			fuzz_upstream = 1;
			return 0;
		}
		return -1;
	}

	if (cmd == 's' || cmd == 'S') {
		if (arg >= '0' && arg <= '9') {
			fuzz_src_byte = (uint8_t) (arg - '0');
			return 0;
		}
		if (arg >= 'a' && arg <= 'f') {
			fuzz_src_byte = (uint8_t) (arg - 'a' + 10);
			return 0;
		}
		if (arg >= 'A' && arg <= 'F') {
			fuzz_src_byte = (uint8_t) (arg - 'A' + 10);
			return 0;
		}
		return -1;
	}

	return -1;
}

void
fuzz_setup(void)
{
	static int initialized = 0;
	static int created = 0;
	struct server_params params;
	struct in_addr server_ip;
	int netmask = 28;
	size_t half_len = sizeof(fuzz_tun_pkt) / 2;

	server_ip.s_addr = htonl(0x0a000001); /* 10.0.0.1 */

	if (!initialized) {
		created = init_users(USERS, server_ip, netmask);

		memset(&params, 0, sizeof(params));
		params.topdomain = FUZZ_TOPDOMAIN;
		params.password = fuzz_password;
		params.users = created;
		params.check_ip = 1;
		params.tunnel_mtu = 1130;
		params.server_ip = server_ip;
		params.netmask = netmask;
		params.nameserver_ip.s_addr = htonl(0x01020304);
		struct sockaddr_in *bsin = (struct sockaddr_in *) &params.bind_addr.addr;
		bsin->sin_family = AF_INET;
		bsin->sin_addr.s_addr = htonl(0x7f000001);
		bsin->sin_port = htons(5353);
		params.bind_addr.addrlen = sizeof(*bsin);

		server_init(&params);
		initialized = 1;
	}

	fw_query_init();

	for (int i = 0; i < created; i++)
		reset_user(i);

	/*
	 * User stages:
	 * - users[0]: logged in, options locked, mid-packet (first half of compressed
	 *             IPv4 packet in inpacket seq=1 frag=0, and outpacket seq=1 frag=0
	 *             in flight waiting for ack)
	 * - users[1]: version accepted, waiting for 'l' (login) handshake
	 * - users[2]: logged in, options unlocked -> 'i', 's', 'o', 'r', 'n', raw login
	 * - users[3]: logged in, options locked -> 'p' (ping) and tunnel data
	 * - users[4]: raw UDP mode authenticated -> raw data and raw ping
	 * - users[5..]: unused (active=0) -> receives 'v' (version) handshake
	 */
	init_user_stage(0, 1, 1, 0);
	init_user_stage(1, 0, 0, 0);
	init_user_stage(2, 1, 0, 0);
	init_user_stage(3, 1, 1, 0);
	init_user_stage(4, 1, 1, 1);

	memcpy(users[0].inpacket.data, fuzz_tun_pkt, half_len);
	users[0].inpacket.seqno = 1;
	users[0].inpacket.fragment = 0;
	users[0].inpacket.len = (int) half_len;
	users[0].inpacket.offset = (int) half_len;

	memcpy(users[0].outpacket.data, fuzz_tun_pkt, sizeof(fuzz_tun_pkt));
	users[0].outpacket.len = (int) sizeof(fuzz_tun_pkt);
	users[0].outpacket.offset = 0;
	users[0].outpacket.sentlen = (int) half_len;
	users[0].outpacket.seqno = 1;
	users[0].outpacket.fragment = 0;
	users[0].outfragresent = 1;
}

void
fuzz_run_packet(const uint8_t *pkt, size_t len)
{
	struct dnsfd dns_fds = { INVALID_SOCK, INVALID_SOCK };
	(void)pkt;
	(void)len;

	tun_rx_len = 0;
	if (fuzz_upstream) {
		tunnel_bind(FUZZ_BIND_FD, &dns_fds);
	} else {
		tunnel_dns(INVALID_SOCK, INVALID_SOCK, &dns_fds, FUZZ_BIND_FD);
		if (tun_rx_len > 0)
			tunnel_tun(INVALID_SOCK, &dns_fds);
	}
}

void
fuzz_cleanup(void)
{
	free(users);
	users = NULL;
}
