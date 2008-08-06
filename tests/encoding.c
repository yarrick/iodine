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

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "test.h"

struct tuple
{
	char *a;
	char *b;
} dottests[] = {
	{ "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.a"},
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."},
	{ "abc123", "abc123" },
	{ NULL, NULL }
};

START_TEST(test_inline_dotify)
{
	unsigned i;
	char temp[1024];
	char *b;

	i = 0;
	while (dottests[i].a) {
		memset(temp, 0, sizeof(temp));
		strcpy(temp, dottests[i].a);
		b = temp;
		inline_dotify(b, sizeof(temp));

		fail_unless(strcmp(dottests[i].b, temp) == 0,
				"'%s' != '%s'", temp, dottests[i].b);
		i++;
	}
}
END_TEST

START_TEST(test_inline_undotify)
{
	unsigned i;
	char temp[1024];
	char *b;

	i = 0;
	while (dottests[i].a) {
		memset(temp, 0, sizeof(temp));
		strcpy(temp, dottests[i].b);
		b = temp;
		inline_undotify(b, sizeof(temp));

		fail_unless(strcmp(dottests[i].a, temp) == 0,
				"'%s' != '%s'", temp, dottests[i].a);
		i++;
	}
}
END_TEST

TCase *
test_encoding_create_tests()
{
	TCase *tc;

	tc = tcase_create("Encoding");
	tcase_add_test(tc, test_inline_dotify);
	tcase_add_test(tc, test_inline_undotify);

	return tc;
}
