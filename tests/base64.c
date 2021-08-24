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
#include <errno.h>

#include "encoding.h"
#include "test.h"

#define TUPLES 5

static struct tuple
{
	char *a;
	char *b;
} testpairs[TUPLES] = {
	{ "iodinetestingtesting", "Aw8KAw4LDgvZDgLUz2rLC2rPBMC" },
	{ "abc1231", "ywjJmtiZmq" },
	{
	  "\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68"
	  "\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50"
	  "\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40\x3F\x3F\x3C\xEF\xAE\x78"
	  "\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68\x9E\x69\x64\x8E\x28\x60"
	  "\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48"
	  "\x1C\x61\x44\x0C\x20\x40\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70"
	  "\xBE\xEB\x6C\xAE\xAA\x68\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58"
	  "\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40",

	  "+9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcbapZ"
	  "776543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba+987654"
	  "3210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
	},
	{
	  "\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xAA\x68"
	  "\x9E\x69\x64\x8E\x28\x60\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50"
	  "\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40\x3F\x3F\x3C\xEF\xAE\x78"
	  "\xDF\x6D\x74\xCF\x2C\x70\xBE\xEB\x6C\xAE\xA1\x61\x91\x61\x61\x81\x28\x60"
	  "\x7D\xE7\x5C\x6D\xA6\x58\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48"
	  "\x1C\x61\x44\x0C\x20\x40\xFF\xEF\x7C\xEF\xAE\x78\xDF\x6D\x74\xCF\x2C\x70"
	  "\xBE\xEB\x6C\xAE\xA1\x61\x91\x61\x61\x81\x28\x60\x7D\xE7\x5C\x6D\xA6\x58"
	  "\x5D\x65\x54\x4D\x24\x50\x3C\xE3\x4C\x2C\xA2\x48\x1C\x61\x44\x0C\x20\x40",

	  "+9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcbapZ"
	  "776543210-ZYXWVUTSRQfHKwfHGsHGFEDCBAzyxwvutsrqponmlkjihgfedcba+987654321"
	  "0-ZYXWVUTSRQfHKwfHGsHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
	},
	{ "", "" }
};

START_TEST(test_base64_encode)
{
	size_t len;
	char buf[4096];
	int val;

	len = sizeof(buf);
	val = base64_ops.encode(buf, &len, testpairs[_i].a, strlen(testpairs[_i].a));

	ck_assert(val == strlen(testpairs[_i].b));
	ck_assert_str_eq(buf, testpairs[_i].b);
}
END_TEST

START_TEST(test_base64_decode)
{
	size_t len;
	char buf[4096];
	int val;

	len = sizeof(buf);
	val = base64_ops.decode(buf, &len, testpairs[_i].b, strlen(testpairs[_i].b));

	ck_assert(val == strlen(testpairs[_i].a));
	ck_assert_str_eq(buf, testpairs[_i].a);
}
END_TEST

START_TEST(test_base64_blksize)
{
	size_t rawlen;
	size_t enclen;
	char *rawbuf;
	char *encbuf;
	int i;
	int val;

	rawlen = base64_ops.blocksize_raw;
	enclen = base64_ops.blocksize_encoded;

	rawbuf = malloc(rawlen + 16);
	encbuf = malloc(enclen + 16);

	for (i = 0; i < rawlen; i++) {
		rawbuf[i] = 'A';
	}
	rawbuf[i] = 0;

	val = base64_ops.encode(encbuf, &enclen, rawbuf, rawlen);

	ck_assert_msg(rawlen == 3, "raw length was %zu not 3", rawlen);
	ck_assert_msg(enclen == 3, "encoded %zu bytes, not 3", enclen);
	ck_assert_msg(val == 4, "encoded string %s was length %d", encbuf, val);

	memset(rawbuf, 0, rawlen + 16);

	enclen = val;
	val = base64_ops.decode(rawbuf, &rawlen, encbuf, enclen);

	ck_assert_msg(rawlen == 3, "raw length was %zu not 3", rawlen);
	ck_assert(val == 3);
	for (i = 0; i < rawlen; i++) {
		ck_assert(rawbuf[i] == 'A');
	}
}
END_TEST

TCase *
test_base64_create_tests()
{
	TCase *tc;

	tc = tcase_create("Base64");
	tcase_add_loop_test(tc, test_base64_encode, 0, TUPLES);
	tcase_add_loop_test(tc, test_base64_decode, 0, TUPLES);
	tcase_add_test(tc, test_base64_blksize);

	return tc;
}
