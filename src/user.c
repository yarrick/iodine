/*
 * Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <err.h>
#include <arpa/inet.h>

#include "common.h"
#include "encoding.h"
#include "user.h"

struct user users[USERS];

void
init_users(in_addr_t my_ip)
{
	int i;
	char newip[16];
	
	memset(users, 0, USERS * sizeof(struct user));
	for (i = 0; i < USERS; i++) {
		users[i].id = i;
		snprintf(newip, sizeof(newip), "0.0.0.%d", i + 1);
		users[i].tun_ip = my_ip + inet_addr(newip);;
		users[i].inpacket.len = 0;
		users[i].inpacket.offset = 0;
		users[i].outpacket.len = 0;
		users[i].q.id = 0;
	}
}

int
users_waiting_on_reply()
{
	int ret;
	int i;

	ret = 0;
	for (i = 0; i < USERS; i++) {
		if (users[i].active && users[i].last_pkt + 60 > time(NULL) &&
			users[i].q.id != 0) {
			ret++;
		}
	}
	
	return ret;
}

int
find_user_by_ip(uint32_t ip)
{
	int ret;
	int i;

	ret = -1;
	for (i = 0; i < USERS; i++) {
		if (users[i].active && users[i].last_pkt + 60 > time(NULL) &&
			ip == users[i].tun_ip) {
			ret = i;
			break;
		}
	}
	return ret;
}

int
all_users_waiting_to_send()
{
	time_t now;
	int ret;
	int i;

	ret = 1;
	now = time(NULL);
	for (i = 0; i < USERS; i++) {
		if (users[i].active && users[i].last_pkt + 60 > now &&
			users[i].outpacket.len == 0) {
			ret = 0;
			break;
		}
	}
	return ret;
}

int
find_available_user()
{
	int ret = -1;
	int i;
	for (i = 0; i < USERS; i++) {
		/* Not used at all or not used in one minute */
		if (!users[i].active || users[i].last_pkt + 60 < time(NULL)) {
			users[i].active = 1;
			users[i].last_pkt = time(NULL);
			ret = i;
			break;
		}
	}
	return ret;
}

