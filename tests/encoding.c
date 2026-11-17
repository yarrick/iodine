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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "compat.h"
#include "dns.h"
#include "encoding.h"
#include "test_main.h"

#define TUPLES 4

static struct tuple
{
	char *a;
	char *b;
} dottests[] = {
	{ "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaa"},
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."},
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{ "abc123", "abc123" },
	{ NULL, NULL }
};

START_TEST(test_inline_dotify)
{
	char temp[1024];
	char *b;

	memset(temp, 0, sizeof(temp));
	strlcpy(temp, dottests[_i].a, sizeof(temp));
	b = temp;
	inline_dotify(b, sizeof(temp));

	ck_assert_str_eq(dottests[_i].b, temp);
}
END_TEST

START_TEST(test_inline_undotify)
{
	char temp[1024];
	char *b;

	memset(temp, 0, sizeof(temp));
	strlcpy(temp, dottests[_i].b, sizeof(temp));
	b = temp;
	inline_undotify(b, sizeof(temp));

	ck_assert_str_eq(dottests[_i].a, temp);
}
END_TEST

START_TEST(test_build_hostname)
{
	char data[256];
	char buf[1024];
	char *topdomain = "a.c";
	unsigned int buflen;
	unsigned int i;

	for (i = 0; i < sizeof(data); i++) {
		data[i] = i & 0xFF;
	}

	buflen = sizeof(buf);

	for (i = 1; i < sizeof(data); i++) {
		int len = build_hostname(buf, buflen, data, i, topdomain, &base32_ops, sizeof(buf));

		ck_assert_int_le(len, i);
		ck_assert_msg(strstr(buf, "..") == NULL,
			"Found double dots when encoding data len %d! buf: %s", i, buf);
	}
}
END_TEST

START_TEST(test_unpack_data_bounds)
{
	char data[] = "nfxwi0lomv0gk21unfxgo3dfon0gs1th";
	char buf[8];
	int len;

	len = unpack_data(buf, sizeof(buf), data, strlen(data), &base32_ops);
	ck_assert_int_eq(len, sizeof(buf) - 1);
	ck_assert_int_eq(buf[sizeof(buf) - 1], '\0');
	ck_assert_int_eq(unpack_data(buf, 0, data, strlen(data), &base32_ops), 0);
}
END_TEST

START_TEST(test_get_encoder_by_name)
{
	ck_assert_ptr_eq(get_encoder_by_name("Base32"), &base32_ops);
	ck_assert_ptr_eq(get_encoder_by_name("base32"), &base32_ops);
	ck_assert_ptr_eq(get_encoder_by_name("BASE64"), &base64_ops);
	ck_assert_ptr_eq(get_encoder_by_name("base64u"), &base64u_ops);
	ck_assert_ptr_eq(get_encoder_by_name("Base128"), &base128_ops);
	ck_assert_ptr_eq(get_encoder_by_name("raw"), &raw_ops);
	ck_assert_ptr_null(get_encoder_by_name("bogus"));
	ck_assert_ptr_null(get_encoder_by_name(""));
	ck_assert_ptr_null(get_encoder_by_name(NULL));
}
END_TEST

#define NUM_WRAP_QTYPES 5
static const unsigned short
wrap_qtypes[NUM_WRAP_QTYPES] = { T_A, T_CNAME, T_MX, T_SRV, T_TXT };

START_TEST(test_payload_wrap_unwrap)
{
	static const struct encoder *const encs[] = {
		&base32_ops, &base64_ops, &base64u_ops, &base128_ops, &raw_ops, NULL
	};
	unsigned short qtype = wrap_qtypes[_i];
	unsigned short rtype = (qtype == T_A) ? T_CNAME : qtype;
	char bin_data[400];
	char buf[4096];
	size_t i, e, datalen;

	for (i = 0; i < sizeof(bin_data); i++) {
		bin_data[i] = (char)((i * 73 + 5) & 0xff);
	}

	for (e = 0; encs[e] != NULL; e++) {
		const struct encoder *enc = encs[e];

		if (!encoder_valid_for_qtype(enc, qtype))
			continue;

		for (datalen = 1; datalen <= sizeof(bin_data); datalen += 7) {
			size_t wrapped_data = datalen;
			int wraplen;
			int ret;

			memset(buf, '@', sizeof(buf));
			wraplen = payload_wrap(buf, sizeof(buf),
					bin_data, &wrapped_data, qtype, enc);
			ck_assert_int_gt(wraplen, 0);
			ck_assert_uint_gt(wrapped_data, 0);
			ck_assert_uint_le(wrapped_data, datalen);

			if (qtype == T_TXT) {
				ck_assert_int_eq(buf[0], enc->down_char);
			} else {
				ck_assert_int_eq(buf[0], enc->host_char);
				ck_assert_ptr_null(strstr(buf, ".."));
			}

			if (qtype == T_MX || qtype == T_SRV) {
				/* Full 400 bytes fit across multiple records */
				ck_assert_uint_eq(wrapped_data, datalen);
				ck_assert_int_eq(buf[wraplen], '\0');
			}

			ret = payload_unwrap(buf, (size_t)wraplen, rtype);
			ck_assert_int_eq(ret, wrapped_data);
			ck_assert_mem_eq(buf, bin_data, wrapped_data);
		}
	}
}
END_TEST

START_TEST(test_payload_wrap_raw_fallback)
{
	const char bin_data[] = "fallback1234";
	char buf[256];
	size_t datalen;
	int wraplen;

	/* Raw and NULL encoders on hostname qtypes fall back to Base32 */
	datalen = sizeof(bin_data) - 1;
	wraplen = payload_wrap(buf, sizeof(buf), bin_data, &datalen, T_CNAME, &raw_ops);
	ck_assert_int_gt(wraplen, 0);
	ck_assert_uint_eq(datalen, sizeof(bin_data) - 1);
	ck_assert_int_eq(buf[0], base32_ops.host_char);
	ck_assert_int_eq(payload_unwrap(buf, (size_t)wraplen, T_CNAME), sizeof(bin_data) - 1);
	ck_assert_mem_eq(buf, bin_data, sizeof(bin_data) - 1);

	datalen = sizeof(bin_data) - 1;
	wraplen = payload_wrap(buf, sizeof(buf), bin_data, &datalen, T_MX, NULL);
	ck_assert_int_gt(wraplen, 0);
	ck_assert_uint_eq(datalen, sizeof(bin_data) - 1);
	ck_assert_int_eq(buf[0], base32_ops.host_char);
	ck_assert_int_eq(payload_unwrap(buf, (size_t)wraplen, T_MX), sizeof(bin_data) - 1);
	ck_assert_mem_eq(buf, bin_data, sizeof(bin_data) - 1);
}
END_TEST

START_TEST(test_payload_wrap_unwrap_bounds)
{
	char bin_data[] = "hello iodine wrap unwrap bounds test";
	char buf[64];
	size_t wrapped_data;
	int wraplen;
	int ret;

	/* Too-small buffers return 0 and report 0 wrapped bytes */
	wrapped_data = sizeof(bin_data);
	ck_assert_int_eq(payload_wrap(buf, 7, bin_data, &wrapped_data, T_CNAME, &base32_ops), 0);
	ck_assert_uint_eq(wrapped_data, 0);

	wrapped_data = sizeof(bin_data);
	ck_assert_int_eq(payload_wrap(buf, 7, bin_data, &wrapped_data, T_MX, &base32_ops), 0);
	ck_assert_uint_eq(wrapped_data, 0);

	wrapped_data = sizeof(bin_data);
	ck_assert_int_eq(payload_wrap(buf, 1, bin_data, &wrapped_data, T_TXT, &base32_ops), 0);
	ck_assert_uint_eq(wrapped_data, 0);

	/* Tight MX buffer: wraps partial data without writing past buflen */
	memset(buf, '!', sizeof(buf));
	wrapped_data = 5;
	wraplen = payload_wrap(buf, 10, bin_data, &wrapped_data, T_MX, &base64_ops);
	ck_assert_int_eq(wraplen, 9);
	ck_assert_uint_eq(wrapped_data, 3);
	ck_assert_int_eq(buf[10], '!');
	ret = payload_unwrap(buf, (size_t)wraplen, T_MX);
	ck_assert_int_eq(ret, 3);
	ck_assert_mem_eq(buf, bin_data, 3);

	/* Mismatched / truncated inputs to payload_unwrap return 0 */
	memcpy(buf, "habcd.xy", 9);
	ck_assert_int_eq(payload_unwrap(buf, 4, T_CNAME), 0);
	memcpy(buf, "habcd.xy", 9);
	ck_assert_int_eq(payload_unwrap(buf, 8, T_TXT), 0);
	memcpy(buf, "tabcdefg", 9);
	ck_assert_int_eq(payload_unwrap(buf, 8, T_CNAME), 0);
	ck_assert_int_eq(payload_unwrap(buf, 1, T_TXT), 0);
	ck_assert_int_eq(payload_unwrap(buf, 8, T_NULL), 0);
}
END_TEST

TCase *
test_create(void)
{
	TCase *tc;

	tc = tcase_create("Encoding");
	tcase_add_loop_test(tc, test_inline_dotify, 0, TUPLES);
	tcase_add_loop_test(tc, test_inline_undotify, 0, TUPLES);
	tcase_add_test(tc, test_build_hostname);
	tcase_add_test(tc, test_unpack_data_bounds);
	tcase_add_test(tc, test_get_encoder_by_name);
	tcase_add_loop_test(tc, test_payload_wrap_unwrap, 0, NUM_WRAP_QTYPES);
	tcase_add_test(tc, test_payload_wrap_raw_fallback);
	tcase_add_test(tc, test_payload_wrap_unwrap_bounds);

	return tc;
}
