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
#include <math.h>

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

int init_users(in_addr_t my_ip, int netbits, struct in6_addr my_ip6, int netbits6)
{
	int i;
	int i6;
	int skip = 0;
	int skip6 = 0;
	char newip[16];

	int maxusers;

	in_addr_t netmask = 0;
	struct in_addr net;
	struct in_addr ipstart;
        struct in6_addr ip6start;     
        unsigned ip6_netmask[16]; 

	bool ip6_enabled;

        ip6_enabled = isV6AddrSet(&my_ip6);
 
	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);
	ipstart.s_addr = my_ip & net.s_addr;

        /* Covert IPv6 netbits to IPv6 netmask and work
         * out the network address from my IP address. Start
         * assigning IPv6 address from the network address + 1
         */
        if (ip6_enabled == true) {
           for (i6 = 0; i6 < netbits6 / 8; i6++) {
              ip6_netmask[i6] |= 0xFF;
           }

           ip6_netmask[netbits6 / 8] = pow(2, (netbits6 % 8 )) - 1;
           ip6_netmask[netbits6 / 8] <<= (8-(netbits6 % 8)); 
           
           for (i6 = 0; i6 < 16; i6++) { 
	       ip6start.s6_addr[i6] = my_ip6.s6_addr[i6] & ip6_netmask[i6];
           } 
        }
	maxusers = (1 << (32-netbits)) - 3; /* 3: Net addr, broadcast addr, iodined addr */
	usercount = MIN(maxusers, USERS);

	users = calloc(usercount, sizeof(struct tun_user));
        /* 
         * IPv6 note: Current behavior is to populate the users structure
         * with the IPv4 addresses that are expected to be used. 
         * In the future with IPv6-only tunnel transport, we should not be
         * populating a /64 (or whatever mask) in the users structure
         * and should shift to an on-demand scheme. For now
         * we expect dual-stack and pre-allocate IPv6 addresses into the
         * users struct as we do with IPv4.
         */
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
		users[i].tun_ip = ip;

                if (ip6_enabled == true) {
	           struct in6_addr temp_ip6;
                   /*
                    * start assigning host addresses from the network address + 1
                    * unless that is my_ip, in which case, use the following address.
                    */
                   memcpy(temp_ip6.s6_addr, ip6start.s6_addr, sizeof(ip6start.s6_addr));
                   temp_ip6.s6_addr[15] = ip6start.s6_addr[15] + skip + 1 + i;
                  
                   if (v6AddressesEqual(&temp_ip6, &my_ip6) == true &&
                      skip6 == 0) {
                         /* This IPv6 was taken by iodined */
                         skip6++;

                         /* 
                          * We expect to start assigning addresses at the network address + 1 and
                          * to not worry about assigning more than 254 host addresses. If we did, we have to 
                          * iterate through lower order bytes of ip6. This plus a few other corner cases
                          * is why we enourage/force/assume the user to specify a /64 V6 address
                          */
                   
			 temp_ip6.s6_addr[15] = ip6start.s6_addr[15] + skip + 1 + i;

	           }	
                   memcpy(users[i].tun_ip6.s6_addr, temp_ip6.s6_addr, sizeof(temp_ip6.s6_addr));
                }
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

const char *users_get_first_ip6(void)
{
	struct in6_addr ip6;
        char display_ip6[INET6_ADDRSTRLEN];

        memcpy(&ip6, &users[0].tun_ip6, sizeof(struct in6_addr));

        inet_ntop(AF_INET6, &ip6, display_ip6, INET6_ADDRSTRLEN);
        return strdup(display_ip6);
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
			v6AddressesEqual(v6Addr, &users[i].tun_ip6) == true) {
			   return i;
                }
	}
	return -1;
}

bool v6AddressesEqual(struct in6_addr *v6Struct1, struct in6_addr *v6Struct2)
{
        int i;
    
	for (i = 0; i < 16; i++) {
		if (v6Struct1->s6_addr[i] != v6Struct2->s6_addr[i]) {
		    return false;
		}
        }
	return true;
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

