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

struct tun_user *users;
unsigned usercount;

int init_users(in_addr_t my_ip, int netbits)
{
	int i;
	int skip = 0;
	char newip[16];
	char ip6Tmp[16];
	char ip6Tmp2[18];
        char ipv4Tmp[16];

	int maxusers;

	in_addr_t netmask = 0;
	struct in_addr net;
	struct in_addr ipstart;
	 
	/* For IPv6, we take the IPv4 address and simply prepend ::
	 * and use a 64-bit mask. Reduces the need to parse
	 * netmasks. 
	 */

	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);
	ipstart.s_addr = my_ip & net.s_addr;

	maxusers = (1 << (32-netbits)) - 3; /* 3: Net addr, broadcast addr, iodined addr */
	usercount = MIN(maxusers, USERS);

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

			inet_ntop(AF_INET, &ip, ip6Tmp, INET_ADDRSTRLEN);

			snprintf(ip6Tmp2, sizeof(ip6Tmp2), "::%s", ip6Tmp);
                        
			inet_pton(AF_INET6, ip6Tmp2, &users[i].tun_ip6);
			memset(ip6Tmp2,0,strlen(ip6Tmp2)); 
			inet_ntop(AF_INET6, &users[i].tun_ip6, ip6Tmp2, INET6_ADDRSTRLEN); 
			inet_ntop(AF_INET, &ip, ipv4Tmp, INET_ADDRSTRLEN); 
	                printf("storing IPv4 address: %s\n", ipv4Tmp);
	                printf("storing IPv6 address: %s\n", ip6Tmp2);
			memset(ip6Tmp2,0,strlen(ip6Tmp2)); 
			
		}
		users[i].tun_ip = ip;
		net.s_addr = ip;
		users[i].disabled = 0;
		users[i].authenticated = 0;
		users[i].authenticated_raw = 0;
		users[i].options_locked = 0;
		users[i].active = 0;
 		/* Rest is reset on login ('V' packet) */
	}

	return usercount;
}

const char *users_get_first_ip(void)
{
	struct in_addr ip;
	ip.s_addr = users[0].tun_ip;
	return strdup(inet_ntoa(ip));
}

int find_user_by_ip6(struct in6_addr *v6Addr) 
{
	int i;
        char v6AddrOut[32];

	inet_ntop(AF_INET6, v6Addr, v6AddrOut, INET6_ADDRSTRLEN);

	for (i = 0; i < usercount; i++) {
		if (users[i].active &&
			users[i].authenticated &&
			!users[i].disabled &&
			users[i].last_pkt + 60 > time(NULL) &&
			(areV6AddressesEqual(v6Addr, &users[i].tun_ip6) == 0) ) {
			   return i;
		}
	}
	return -1;
}

int areV6AddressesEqual(struct in6_addr *v6Struct1, struct in6_addr *v6Struct2)
{
        int i;
    
	for (i = 0; i < 16; i++) {
		if (v6Struct1->s6_addr[i] != v6Struct2->s6_addr[i]) {
		    return -1;
		}
        }
	return 0;
}


int find_user_by_ip(uint32_t ip)
{
	int ret;
	int i;

	ret = -1;
	for (i = 0; i < usercount; i++) {
		if (users[i].active &&
			users[i].authenticated &&
			!users[i].disabled &&
			users[i].last_pkt + 60 > time(NULL) &&
			ip == users[i].tun_ip) {
			ret = i;
			break;
		}
	}
	return ret;
}

/* If this returns true, then reading from tun device is blocked.
   So only return true when all clients have at least one packet in
   the outpacket-queue, so that sending back-to-back is possible
   without going through another select loop.
*/
int all_users_waiting_to_send(void)
{
	time_t now;
	int ret;
	int i;

	ret = 1;
	now = time(NULL);
	for (i = 0; i < usercount; i++) {
		if (users[i].active && !users[i].disabled &&
			users[i].last_pkt + 60 > now &&
			((users[i].conn == CONN_RAW_UDP) ||
			((users[i].conn == CONN_DNS_NULL)
#ifdef OUTPACKETQ_LEN
				&& users[i].outpacketq_filled < 1
#else
				&& users[i].outpacket.len == 0
#endif
			))) {

			ret = 0;
			break;
		}
	}
	return ret;
}

int find_available_user(void)
{
	int ret = -1;
	int i;
	for (i = 0; i < usercount; i++) {
		/* Not used at all or not used in one minute */
		if ((!users[i].active || users[i].last_pkt + 60 < time(NULL)) && !users[i].disabled) {
			users[i].active = 1;
			users[i].authenticated = 0;
			users[i].authenticated_raw = 0;
			users[i].options_locked = 0;
			users[i].last_pkt = time(NULL);
			users[i].fragsize = 4096;
			users[i].conn = CONN_DNS_NULL;
			ret = i;
			break;
		}
	}
	return ret;
}

void user_switch_codec(int userid, const struct encoder *enc)
{
	if (userid < 0 || userid >= usercount)
		return;

	users[userid].encoder = enc;
}

void user_set_conn_type(int userid, enum connection c)
{
	if (userid < 0 || userid >= usercount)
		return;

	if (c < CONN_RAW_UDP || c >= CONN_MAX)
		return;

	users[userid].conn = c;
}

