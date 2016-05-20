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

#include <check.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "encoding.h"
#include "user.h"
#include "test.h"

int debug = 0;

START_TEST(test_init_users)
{
	in_addr_t ip;
	char givenip[16];
	int i;
	int count;

	ip = inet_addr("127.0.0.1");
	count = init_users(ip, 27);
	for (i = 0; i < count; i++) {
		fail_unless(users[i].id == i);
		snprintf(givenip, sizeof(givenip), "127.0.0.%d", i + 2);
		fail_unless(users[i].tun_ip == inet_addr(givenip));
		fail_if(user_active(i), "user_active true for new users");
	}
}
END_TEST

START_TEST(test_find_user_by_ip)
{
	in_addr_t ip;
	unsigned int testip;

	ip = inet_addr("127.0.0.1");
	init_users(ip, 27);
	users[0].conn = CONN_DNS_NULL;

	testip = (unsigned int) inet_addr("10.0.0.1");
	fail_unless(find_user_by_ip(testip) == -1);

	testip = (unsigned int) inet_addr("127.0.0.2");
	fail_unless(find_user_by_ip(testip) == -1);

	users[0].active = 1;

	testip = (unsigned int) inet_addr("127.0.0.2");
	fail_unless(find_user_by_ip(testip) == -1);

	users[0].last_pkt = time(NULL);

	testip = (unsigned int) inet_addr("127.0.0.2");
	fail_unless(find_user_by_ip(testip) == -1);

	users[0].authenticated = 1;

	testip = (unsigned int) inet_addr("127.0.0.2");
	fail_unless(find_user_by_ip(testip) == 0);
}
END_TEST

START_TEST(test_all_users_waiting_to_send)
{
	in_addr_t ip;

	ip = inet_addr("127.0.0.1");
	init_users(ip, 27);

	fail_unless(all_users_waiting_to_send() == 0, "empty user list all waiting to send");

	users[0].conn = CONN_DNS_NULL;
	users[0].active = 1;

	fail_unless(all_users_waiting_to_send() == 0, "single user with empty buffer waiting to send");

	users[0].last_pkt = time(NULL);

	fail_unless(all_users_waiting_to_send() == 0, "single active user with empty buffer waiting to send");

}
END_TEST

START_TEST(test_find_available_user)
{
	in_addr_t ip;
	int i;

	ip = inet_addr("127.0.0.1");
	init_users(ip, 27);

	for (i = 0; i < USERS; i++) {
		users[i].authenticated = 1;
		users[i].authenticated_raw = 1;
		fail_unless(find_available_user() == i);
		fail_if(users[i].authenticated);
		fail_if(users[i].authenticated_raw);
	}

	for (i = 0; i < USERS; i++) {
		fail_unless(find_available_user() == -1);
	}

	users[3].active = 0;

	fail_unless(find_available_user() == 3);
	fail_unless(find_available_user() == -1);

	users[3].last_pkt = 55;

	fail_unless(find_available_user() == 3);
	fail_unless(find_available_user() == -1);
}
END_TEST

START_TEST(test_find_available_user_small_net)
{
	in_addr_t ip;
	int i;

	ip = inet_addr("127.0.0.1");
	init_users(ip, 29); /* this should result in 5 enabled users */

	for (i = 0; i < 5; i++) {
		fail_unless(find_available_user() == i);
	}

	for (i = 0; i < USERS; i++) {
		fail_unless(find_available_user() == -1);
	}

	users[3].active = 0;

	fail_unless(find_available_user() == 3);
	fail_unless(find_available_user() == -1);

	users[3].last_pkt = 55;

	fail_unless(find_available_user() == 3);
	fail_unless(find_available_user() == -1);
}
END_TEST

TCase *
test_user_create_tests()
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
