/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include "encoding.h"
#include "test.h"

START_TEST(test_encoding_base32)
{
	char temp[256];
	char *start = "HELLOTEST";
	char *out = "1HELLOTEST";
	char end[256];
	char *tempend;
	int codedlength;

	memset(temp, 0, sizeof(temp));
	memset(end, 0, sizeof(end));

	codedlength = encode_data(start, strlen(start), sizeof(temp) - 1, temp + 1);
	temp[0] = '1';
	tempend = temp + strlen(temp);
	decode_data(end, sizeof(end), temp, tempend);

	fail_unless(strcmp(out, end) == 0, NULL);
}
END_TEST

TCase *
test_encoding_create_tests()
{
	TCase *tc;

	tc = tcase_create("Encoding");
	tcase_add_test(tc, test_encoding_base32);

	return tc;
}
