/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef WINDOWS32
#include <winsock2.h>
#else
#include <netdb.h>
#endif

#include "common.h"
#include "encoding.h"
#include "user.h"
#include "window.h"
#include "server.h"

struct tun_user *users;
unsigned usercount;
int created_users;


int
init_users(in_addr_t my_ip, int netbits)
{
	int i;
	int skip = 0;
	char newip[16];

	int maxusers;

	in_addr_t netmask = 0;
	struct in_addr net;
	struct in_addr ipstart;

	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);
	ipstart.s_addr = my_ip & net.s_addr;

	maxusers = (1 << (32-netbits)) - 3; /* 3: Net addr, broadcast addr, iodined addr */
	usercount = MIN(maxusers, USERS);

	if (users) free(users);
	users = calloc(usercount, sizeof(struct tun_user));
	for (i = 0; i < usercount; i++) {
		in_addr_t ip;
		users[i].id = i;
		snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
		ip = ipstart.s_addr + inet_addr(newip);
		if (ip == my_ip && skip == 0) {
			/* This IP was taken by iodined */
			skip++;
			snprintf(newip, sizeof(newip), "0.0.0.%d", i + skip + 1);
			ip = ipstart.s_addr + inet_addr(newip);
		}
		if (debug >= 2) {
			struct in_addr IP;
			IP.s_addr = ip;
			DEBUG(2, "User %d: IP %s", i, inet_ntoa(IP));
		}
		users[i].tun_ip = ip;
		net.s_addr = ip;

		users[i].incoming = window_buffer_init(INFRAGBUF_LEN, 10, MAX_FRAGSIZE, WINDOW_RECVING);
		users[i].outgoing = window_buffer_init(OUTFRAGBUF_LEN, 10, 100, WINDOW_SENDING);
 		/* Rest is reset on login ('V' packet) or already 0 */
	}

	return usercount;
}

const char*
users_get_first_ip()
{
	struct in_addr ip;
	ip.s_addr = users[0].tun_ip;
	return strdup(inet_ntoa(ip));
}

int
find_user_by_ip(uint32_t ip)
{
	for (int i = 0; i < usercount; i++) {
		if (user_active(i) && users[i].authenticated && ip == users[i].tun_ip) {
			return i;
		}
	}
	return -1;
}

int
user_sending(int user)
{
	return users[user].outgoing->numitems > 0;
}

int
user_active(int i)
{
	return users[i].active && difftime(time(NULL), users[i].last_pkt) < 60;
}

int
all_users_waiting_to_send()
/* If this returns true, then reading from tun device is blocked.
   So only return true when all clients have insufficient space in
   outgoing buffer, so that sending back-to-back is possible
   without going through another select loop. */
{
	int numactive = 0;
	for (int i = 0; i < usercount; i++) {
		if (user_active(i)) {
			if (users[i].outgoing->length - users[i].outgoing->numitems > 8)
				return 0;
			numactive ++;
		}
	}

	/* no users waiting if there are no users */
	if (numactive == 0)
		return 0;

	return 1;
}

int
find_available_user()
{
	for (int u = 0; u < usercount; u++) {
		/* Not used at all or not used in one minute */
		if (!user_active(u)) {
			struct tun_user *user = &users[u];
			/* reset all stats */
			user->active = 1;
			user->authenticated = 0;
			user->authenticated_raw = 0;
			user->last_pkt = time(NULL);
			user->fragsize = MAX_FRAGSIZE;
			user->conn = CONN_DNS_NULL;
			return u;
		}
	}
	return -1;
}

void
user_switch_codec(int userid, struct encoder *enc)
{
	if (userid < 0 || userid >= usercount)
		return;

	users[userid].encoder = enc;
}

void
user_set_conn_type(int userid, enum connection c)
{
	if (userid < 0 || userid >= usercount)
		return;

	if (c < CONN_RAW_UDP || c >= CONN_MAX)
		return;

	users[userid].conn = c;
}

/* This will not check that user has passed login challenge */
int
check_user_and_ip(int userid, struct query *q)
{
	/* Note: duplicate in handle_raw_login() except IP-address check */

	if (userid < 0 || userid >= created_users ) {
		return 1;
	}
	if (!user_active(userid)) return 1;

	/* return early if IP checking is disabled */
	if (!check_ip) {
		return 0;
	}

	if (q->from.ss_family != users[userid].host.ss_family) {
		return 1;
	}
	/* Check IPv4 */
	if (q->from.ss_family == AF_INET) {
		struct sockaddr_in *expected, *received;

		expected = (struct sockaddr_in *) &(users[userid].host);
		received = (struct sockaddr_in *) &(q->from);
		return memcmp(&(expected->sin_addr), &(received->sin_addr), sizeof(struct in_addr));
	}
	/* Check IPv6 */
	if (q->from.ss_family == AF_INET6) {
		struct sockaddr_in6 *expected, *received;

		expected = (struct sockaddr_in6 *) &(users[userid].host);
		received = (struct sockaddr_in6 *) &(q->from);
		return memcmp(&(expected->sin6_addr), &(received->sin6_addr), sizeof(struct in6_addr));
	}
	/* Unknown address family */
	return 1;
}

int
check_authenticated_user_and_ip(int userid, struct query *q)
/* This checks that user has passed normal (non-raw) login challenge
 * Returns 0 on success, 1 if user is not authenticated/IP is wrong */
{
	int res = check_user_and_ip(userid, q);
	if (res)
		return res;

	if (!users[userid].authenticated)
		return 1;

	return 0;
}
