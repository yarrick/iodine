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
#include "common.h"
#include "random.h"
#include "test_main.h"

#include <check.h>
#include <stdio.h>

START_TEST(test_secure_random)
{
	unsigned char a[64], b[64];
	int i, nonzero;

	/* A zero-initialized buffer must come back non-zero from the
	   CSPRNG. */
	memset(a, 0, sizeof(a));
	secure_random(a, sizeof(a));
	nonzero = 0;
	for (i = 0; i < (int)sizeof(a); i++)
		nonzero += (a[i] != 0);
	ck_assert_int_gt(nonzero, 0);

	/* Two independent draws of 64 random bytes must differ; a
	   no-op (or all-zero) implementation would make them equal. */
	memset(b, 0, sizeof(b));
	secure_random(b, sizeof(b));
	ck_assert_mem_ne(a, b, sizeof(b));
}
END_TEST

TCase *
test_create(void)
{
	TCase *tc;
	network_init();

	tc = tcase_create("Random");
	tcase_add_test(tc, test_secure_random);
	return tc;
}
