/*
 * Copyright (c) 2009-2014 Erik Ekman <yarrick@kryo.se>
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

#include "fw_query.h"
#include "test.h"

START_TEST(test_fw_query_simple)
{
	struct fw_query q;
	struct fw_query *qp;

	q.addrlen = 33;
	q.id = 0x848A;

	fw_query_init();

	/* Test empty cache */
	fw_query_get(0x848A, &qp);
	ck_assert(qp == NULL);

	fw_query_put(&q);

	/* Test cache with one entry */
	fw_query_get(0x848A, &qp);
	ck_assert(qp->addrlen == q.addrlen);
	ck_assert(qp->id == q.id);
}
END_TEST

START_TEST(test_fw_query_edge)
{
	struct fw_query q;
	struct fw_query *qp;
	int i;

	fw_query_init();

	q.addrlen = 33;
	q.id = 0x848A;
	fw_query_put(&q);

	for (i = 1; i < FW_QUERY_CACHE_SIZE; i++) {
		q.addrlen++;
		q.id++;
		fw_query_put(&q);
	}

	/* The query should still be cached */
	fw_query_get(0x848A, &qp);
	ck_assert(qp->addrlen == 33);
	ck_assert(qp->id == 0x848A);

	q.addrlen++;
	q.id++;
	fw_query_put(&q);

	/* but now it is overwritten */
	fw_query_get(0x848A, &qp);
	ck_assert(qp == NULL);
}
END_TEST

TCase *
test_fw_query_create_tests()
{
	TCase *tc;

	tc = tcase_create("Forwarded query");
	tcase_add_test(tc, test_fw_query_simple);
	tcase_add_test(tc, test_fw_query_edge);

	return tc;
}
