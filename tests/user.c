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

#include "config.h"

#include <check.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "common.h"
#include "encoding.h"
#include "user.h"
#include "test_main.h"

START_TEST(test_init_users)
{
	struct in_addr ip;
	struct in_addr uip;
	char givenip[32];
	int i;
	int count;

	inet_pton(AF_INET, "127.0.0.1", &ip);
	count = init_users(ip.s_addr, 27);
	for (i = 0; i < count; i++) {
		ck_assert_int_eq(users[i].id, i);
		ck_assert_int_eq(users[i].q.id, 0);
		ck_assert_int_eq(users[i].inpacket.len, 0);
		ck_assert_int_eq(users[i].outpacket.len, 0);
		snprintf(givenip, sizeof(givenip), "127.0.0.%d", i + 2);
		inet_pton(AF_INET, givenip, &uip);
		ck_assert_uint_eq(users[i].tun_ip, uip.s_addr);
	}
}
END_TEST

START_TEST(test_find_user_by_ip)
{
	struct in_addr ip;
	struct in_addr testip;

	inet_pton(AF_INET, "127.0.0.1", &ip);
	init_users(ip.s_addr, 27);
	users[0].conn = CONN_DNS_NULL;

	inet_pton(AF_INET, "10.0.0.1", &testip);
	ck_assert_int_eq(find_user_by_ip(testip.s_addr), -1);

	inet_pton(AF_INET, "127.0.0.2", &testip);
	ck_assert_int_eq(find_user_by_ip(testip.s_addr), -1);

	users[0].active = 1;
	ck_assert_int_eq(find_user_by_ip(testip.s_addr), -1);

	users[0].last_pkt = time(NULL);
	ck_assert_int_eq(find_user_by_ip(testip.s_addr), -1);

	users[0].authenticated = 1;
	ck_assert_int_eq(find_user_by_ip(testip.s_addr), 0);
}
END_TEST

START_TEST(test_all_users_waiting_to_send)
{
	struct in_addr ip;

	inet_pton(AF_INET, "127.0.0.1", &ip);
	init_users(ip.s_addr, 27);

	ck_assert_int_eq(all_users_waiting_to_send(), 1);

	users[0].conn = CONN_DNS_NULL;
	users[0].active = 1;

	ck_assert_int_eq(all_users_waiting_to_send(), 1);

	users[0].last_pkt = time(NULL);
	users[0].outpacket.len = 0;

	ck_assert_int_eq(all_users_waiting_to_send(), 0);

#ifdef OUTPACKETQ_LEN
	users[0].outpacketq_filled = 1;
#else
	users[0].outpacket.len = 44;
#endif

	ck_assert_int_eq(all_users_waiting_to_send(), 1);
}
END_TEST

START_TEST(test_find_available_user)
{
	struct in_addr ip;
	unsigned int i;
	unsigned int user;

	inet_pton(AF_INET, "127.0.0.1", &ip);
	init_users(ip.s_addr, 27);

	for (i = 0; i < USERS; i++) {
		users[i].authenticated = 1;
		users[i].authenticated_raw = 1;
		ck_assert_int_ne(find_available_user(&user), 0);
		ck_assert_uint_eq(user, i);
		ck_assert_int_eq(users[i].authenticated, 0);
		ck_assert_int_eq(users[i].authenticated_raw, 0);
	}

	for (i = 0; i < USERS; i++) {
		ck_assert_int_eq(find_available_user(&user), 0);
	}

	users[3].active = 0;

	ck_assert_int_ne(find_available_user(&user), 0);
	ck_assert_uint_eq(user, 3);
	ck_assert_int_eq(find_available_user(&user), 0);

	users[3].last_pkt = 55;

	ck_assert_int_ne(find_available_user(&user), 0);
	ck_assert_uint_eq(user, 3);
	ck_assert_int_eq(find_available_user(&user), 0);
}
END_TEST

START_TEST(test_find_available_user_small_net)
{
	struct in_addr ip;
	unsigned int i;
	unsigned int user;

	inet_pton(AF_INET, "127.0.0.1", &ip);
	init_users(ip.s_addr, 29); /* this should result in 5 enabled users */

	for (i = 0; i < 5; i++) {
		ck_assert_int_ne(find_available_user(&user), 0);
		ck_assert_uint_eq(user, i);
	}

	for (i = 0; i < USERS; i++) {
		ck_assert_int_eq(find_available_user(&user), 0);
	}

	users[3].active = 0;

	ck_assert_int_ne(find_available_user(&user), 0);
	ck_assert_uint_eq(user, 3);
	ck_assert_int_eq(find_available_user(&user), 0);

	users[3].last_pkt = 55;

	ck_assert_int_ne(find_available_user(&user), 0);
	ck_assert_uint_eq(user, 3);
	ck_assert_int_eq(find_available_user(&user), 0);
}
END_TEST

TCase *
test_create(void)
{
	TCase *tc;

	tc = tcase_create("User");
	tcase_add_test(tc, test_init_users);
	tcase_add_test(tc, test_find_user_by_ip);
	tcase_add_test(tc, test_all_users_waiting_to_send);
	tcase_add_test(tc, test_find_available_user);
	tcase_add_test(tc, test_find_available_user_small_net);

	return tc;
}
