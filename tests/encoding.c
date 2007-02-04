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
	char *end;
	char *tempend;
	int codedlength;

	memset(temp, 0, sizeof(temp));
	end = malloc(16);
	memset(end, 0, 16);

	codedlength = encode_data(start, 9, 256, temp);
	tempend = temp + strlen(temp);
	decode_data(end, 16, temp, tempend);

	fail_unless(strcmp(out, end) == 0, NULL);

	free(end);
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
