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
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "test.h"
#include "base32.h"
#include "base64.h"

#define TUPLES 4

static struct tuple
{
	char *a;
	char *b;
} dottests[] = {
	{ "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa"},
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaa"},
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaa"},
	{ "abcdefghijklmnopqrtsuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrtsuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVW.XYZ" },
	{ NULL, NULL }
};

START_TEST(test_inline_dotify)
{
	char temp[1024];
	char *b;

	memset(temp, 0, sizeof(temp));
	strcpy(temp, dottests[_i].a);
	b = temp;
	inline_dotify((uint8_t *)b, sizeof(temp));

	fail_unless(strcmp(dottests[_i].b, temp) == 0,
			"'%s' != '%s'", temp, dottests[_i].b);
}
END_TEST

START_TEST(test_inline_undotify)
{
	char temp[1024];
	char *b;

	memset(temp, 0, sizeof(temp));
	strcpy(temp, dottests[_i].b);
	b = temp;
	inline_undotify((uint8_t *)b, sizeof(temp));

	fail_unless(strcmp(dottests[_i].a, temp) == 0,
			"'%s' != '%s'", temp, dottests[_i].a);
}
END_TEST

START_TEST(test_build_hostname)
{
	char data[256];
	char buf[1024];
	char *topdomain = "iodine.test.example.com";
	int buflen;
	int i;

	for (i = 0; i < sizeof(data); i++) {
		data[i] = i & 0xFF;
	}

	buflen = sizeof(buf);

	for (int j = 0; j < 10; j++) /* dummy header length */
	for (i = 1; i < sizeof(data); i++) {
		buf[j] = j + 'A';
		int len = build_hostname((uint8_t *)buf, buflen, (uint8_t *)data, i, topdomain, get_base32_encoder(), buflen, j);

		fail_if(len > i);
		fail_if((strstr(buf, ".") - buf) > 63, "First label in encoded hostname >63 bytes!");
		fail_if(strstr(buf, ".."), "Found double dots when encoding data len %d! buf: %s", i, buf);
		fail_if(!strstr(buf, topdomain), "Didn't find topdomain in hostname!");
		fail_if(buf[j] == j, "Header has been changed during encode hostname!");
	}
}
END_TEST

TCase *
test_encoding_create_tests()
{
	TCase *tc;

	tc = tcase_create("Encoding");
	tcase_add_loop_test(tc, test_inline_dotify, 0, TUPLES);
	tcase_add_loop_test(tc, test_inline_undotify, 0, TUPLES);
	tcase_add_test(tc, test_build_hostname);

	return tc;
}
