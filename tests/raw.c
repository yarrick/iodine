/*
 * Copyright (c) 2026 Erik Ekman <yarrick@kryo.se>
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

#include "src/raw.h"
#include "test_main.h"

START_TEST(test_raw_encode_decode_data)
{
	char buf[64];
	const char payload[] = "hello raw";
	struct raw_msg in = {
		.cmd = RAW_HDR_CMD_DATA,
		.userid = 5,
		.data = payload,
		.len = sizeof(payload) - 1,
	};
	struct raw_msg out;
	int len;

	len = raw_encode(buf, sizeof(buf), &in);
	ck_assert_int_eq(len, RAW_HDR_LEN + 9);
	ck_assert_uint_eq((unsigned char) buf[0], 0x10);
	ck_assert_uint_eq((unsigned char) buf[1], 0xd1);
	ck_assert_uint_eq((unsigned char) buf[2], 0x9e);
	ck_assert_uint_eq((unsigned char) buf[3], 0x25);

	ck_assert_int_eq(raw_decode(&out, buf, len), 1);
	ck_assert_uint_eq(out.cmd, RAW_HDR_CMD_DATA);
	ck_assert_uint_eq(out.userid, 5);
	ck_assert_uint_eq(out.len, 9);
	ck_assert_mem_eq(out.data, payload, 9);
}
END_TEST

START_TEST(test_raw_encode_decode_ping)
{
	char buf[16];
	struct raw_msg in = {
		.cmd = RAW_HDR_CMD_PING,
		.userid = 0x0f,
	};
	struct raw_msg out;
	int len;

	len = raw_encode(buf, sizeof(buf), &in);
	ck_assert_int_eq(len, RAW_HDR_LEN);
	ck_assert_int_eq(raw_decode(&out, buf, len), 1);
	ck_assert_uint_eq(out.cmd, RAW_HDR_CMD_PING);
	ck_assert_uint_eq(out.userid, 0x0f);
	ck_assert_uint_eq(out.len, 0);
}
END_TEST

START_TEST(test_raw_encode_limits)
{
	char buf[8];
	const char payload[] = "0123456789";
	struct raw_msg in = {
		.cmd = 0x3f,
		.userid = 0xfc,
		.data = payload,
		.len = 10,
	};
	struct raw_msg out;
	int len;

	/* Buffer too small for header */
	ck_assert_int_eq(raw_encode(buf, RAW_HDR_LEN - 1, &in), -1);

	/* Payload truncated to fit buffer; cmd/userid masked to nibbles */
	len = raw_encode(buf, sizeof(buf), &in);
	ck_assert_int_eq(len, (int) sizeof(buf));
	ck_assert_int_eq(raw_decode(&out, buf, len), 1);
	ck_assert_uint_eq(out.cmd, 0x30);
	ck_assert_uint_eq(out.userid, 0x0c);
	ck_assert_uint_eq(out.len, sizeof(buf) - RAW_HDR_LEN);
	ck_assert_mem_eq(out.data, "0123", 4);
}
END_TEST

START_TEST(test_raw_decode_invalid)
{
	struct raw_msg out;
	const unsigned char bad_magic[] = { 0x10, 0xd1, 0x9f, 0x20, 0x01 };
	const unsigned char short_pkt[] = { 0x10, 0xd1, 0x9e };

	ck_assert_int_eq(raw_decode(&out, (const char *) short_pkt, sizeof(short_pkt)), 0);
	ck_assert_int_eq(raw_decode(&out, (const char *) bad_magic, sizeof(bad_magic)), 0);
}
END_TEST

TCase *
test_create(void)
{
	TCase *tc;

	tc = tcase_create("Raw");
	tcase_add_test(tc, test_raw_encode_decode_data);
	tcase_add_test(tc, test_raw_encode_decode_ping);
	tcase_add_test(tc, test_raw_encode_limits);
	tcase_add_test(tc, test_raw_decode_invalid);

	return tc;
}
