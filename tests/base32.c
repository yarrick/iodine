/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
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

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "encoding.h"
#include "base32.h"
#include "test.h"

#define TUPLES 5

static struct tuple
{
	char *a;
	char *b;
} testpairs[TUPLES] = {
	{ "iodinetestingtesting", "nfxwi0lomv0gk21unfxgo3dfon0gs1th" },
	{ "abc123", "mfrggmjsgm" },
	{ "test", "orsxg3a" },
	{ "tst", "orzxi" },
	{ "", "" },
};

START_TEST(test_base32_encode)
{
	size_t len;
	char buf[4096];
	struct encoder *b32;
	int val;

	b32 = get_base32_encoder();

	len = sizeof(buf);
	val = b32->encode(buf, &len, testpairs[_i].a, strlen(testpairs[_i].a));

	fail_unless(val == strlen(testpairs[_i].b));
	fail_unless(strcmp(buf, testpairs[_i].b) == 0,
			"'%s' != '%s'", buf, testpairs[_i].b);
}
END_TEST

START_TEST(test_base32_decode)
{
	size_t len;
	char buf[4096];
	struct encoder *b32;
	int val;

	b32 = get_base32_encoder();

	len = sizeof(buf);
	val = b32->decode(buf, &len, testpairs[_i].b, strlen(testpairs[_i].b));

	fail_unless(val == strlen(testpairs[_i].a));
	fail_unless(strcmp(buf, testpairs[_i].a) == 0,
			"'%s' != '%s'", buf, testpairs[_i].a);
}
END_TEST

START_TEST(test_base32_5to8_8to5)
{
	int i;
	int c;

	for (i = 0; i < 32; i++) {
		c = b32_5to8(i);
		fail_unless(b32_8to5(c) == i);
	}
}
END_TEST

START_TEST(test_base32_blksize)
{
	size_t rawlen;
	size_t enclen;
	char *rawbuf;
	char *encbuf;
	struct encoder *b32;
	int i;
	int val;

	b32 = get_base32_encoder();

	rawlen = b32->blocksize_raw();
	enclen = b32->blocksize_encoded();

	rawbuf = malloc(rawlen + 16);
	encbuf = malloc(enclen + 16);

	for (i = 0; i < rawlen; i++) {
		rawbuf[i] = 'A';
	}
	rawbuf[i] = 0;

	val = b32->encode(encbuf, &enclen, rawbuf, rawlen);

	fail_unless(rawlen == 5, "raw length was %d not 5", rawlen);
	fail_unless(enclen == 5, "encoded %d bytes, not 5", enclen);
	fail_unless(val == 8, "encoded string %s was length %d", encbuf, val);

	memset(rawbuf, 0, rawlen + 16);

	enclen = val;
	val = b32->decode(rawbuf, &rawlen, encbuf, enclen);

	fail_unless(rawlen == 5, "raw length was %d not 5", rawlen);
	fail_unless(val == 5, "val was not 5 but %d", val);
	for (i = 0; i < rawlen; i++) {
		fail_unless(rawbuf[i] == 'A');
	}
}
END_TEST

TCase *
test_base32_create_tests()
{
	TCase *tc;

	tc = tcase_create("Base32");
	tcase_add_loop_test(tc, test_base32_encode, 0, TUPLES);
	tcase_add_loop_test(tc, test_base32_decode, 0, TUPLES);
	tcase_add_test(tc, test_base32_5to8_8to5);
	tcase_add_test(tc, test_base32_blksize);

	return tc;
}
