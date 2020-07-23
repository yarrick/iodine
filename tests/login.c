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
#include <string.h>

#include "test.h"
#include "login.h"

START_TEST(test_login_hash)
{
	char ans[16];
	char good[] = "\x2A\x8A\x12\xB4\xE0\x42\xEE\xAB\xD0\x19\x17\x1E\x44\xA0\x88\xCD";
	char pass[32] = "iodine is the shit";
	int len;
	int seed;

	len = sizeof(ans);
	seed = 15;

	memset(ans, 0, sizeof(ans));
	login_calculate(ans, len, pass, seed);
	ck_assert(strncmp(ans, good, len) == 0);
}
END_TEST

START_TEST(test_login_hash_short)
{
	char ans[8];
	char check[sizeof(ans)];
	char pass[32] = "iodine is the shit";
	int len;
	int seed;

	len = sizeof(ans);
	seed = 15;

	memset(ans, 0, sizeof(ans));
	memset(check, 0, sizeof(check));

	/* If len < 16, it should do nothing */
	login_calculate(ans, len, pass, seed);
	ck_assert(memcmp(ans, check, sizeof(ans)) == 0);
}
END_TEST

TCase *
test_login_create_tests()
{
	TCase *tc;

	tc = tcase_create("Login");
	tcase_add_test(tc, test_login_hash);
	tcase_add_test(tc, test_login_hash_short);

	return tc;
}
