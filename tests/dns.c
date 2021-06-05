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
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif

#include "common.h"
#include "dns.h"
#include "encoding.h"
#include "test.h"

static void dump_packet(char *, size_t);

static char query_packet[] =
	"\x05\x39\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x2D\x41\x6A\x62\x63"
	"\x75\x79\x74\x63\x70\x65\x62\x30\x67\x71\x30\x6C\x74\x65\x62\x75\x78"
	"\x67\x69\x64\x75\x6E\x62\x73\x73\x61\x33\x64\x66\x6F\x6E\x30\x63\x61"
	"\x7A\x64\x62\x6F\x72\x71\x71\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00"
	"\x0A\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00";

static char answer_packet[] =
	"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";

static char answer_packet_high_trans_id[] =
	"\x85\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";
static char *msgData = "this is the message to be delivered";
static char *topdomain = "kryo.se";

static char *innerData = "HELLO this is the test data";

START_TEST(test_encode_query)
{
	char buf[512];
	char resolv[512];
	struct query q;
	const struct encoder *enc;
	char *d;
	size_t len;
	size_t enclen;
	int ret;

	enclen = sizeof(resolv);
	memset(&buf, 0, sizeof(buf));
	memset(&resolv, 0, sizeof(resolv));
	memset(&q, 0, sizeof(struct query));
	q.type = T_NULL;
	q.id = 1337;
	d = resolv;
	enc = &base32_ops;

	*d++ = 'A';
	enc->encode(d, &enclen, innerData, strlen(innerData));
	d = resolv + strlen(resolv);
	if (*d != '.') {
		*d++ = '.';
	}
	strcpy(d, topdomain);
	len = sizeof(buf);
	ret = dns_encode(buf, len, &q, QR_QUERY, resolv, strlen(resolv));
	len = sizeof(query_packet) - 1; /* Skip extra null character */

	if (strncmp(query_packet, buf, sizeof(query_packet)) || ret != len) {
		printf("\n");
		dump_packet(query_packet, len);
		dump_packet(buf, ret);
	}
	ck_assert_msg(strncmp(query_packet, buf, sizeof(query_packet)) == 0,
		"Did not compile expected packet");
	ck_assert_msg(ret == len,
		"Bad packet length: %d, expected %zu", ret, len);
}
END_TEST

START_TEST(test_decode_query)
{
	char buf[512];
	char *domain;
	struct query q;
	const struct encoder *enc;
	size_t len;

	memset(&q, 0, sizeof(struct query));
	memset(&buf, 0, sizeof(buf));
	q.id = 0;
	len = sizeof(query_packet) - 1;
	enc = &base32_ops;

	dns_decode(buf, sizeof(buf), &q, QR_QUERY, query_packet, len);
	domain = strstr(q.name, topdomain);
	len = sizeof(buf);
	unpack_data(buf, len, &(q.name[1]), (int) (domain - q.name) - 1, enc);

	ck_assert_msg(strncmp(buf, innerData, strlen(innerData)) == 0,
		"Did not extract expected host: '%s'", buf);
	ck_assert_msg(strlen(buf) == strlen(innerData),
		"Bad host length: %zu, expected %zu: '%s'",
		strlen(buf), strlen(innerData), buf);
}
END_TEST

START_TEST(test_encode_response)
{
	char buf[512];
	char *host = "silly.host.of.iodine.code.kryo.se";
	struct query q;
	int len;
	int ret;

	len = sizeof(buf);
	memset(&buf, 0, sizeof(buf));
	memset(&q, 0, sizeof(struct query));
	strncpy(q.name, host, strlen(host));
	q.type = T_NULL;
	q.id = 1337;

	ret = dns_encode(buf, len, &q, QR_ANSWER, msgData, strlen(msgData));
	len = sizeof(answer_packet) - 1; /* Skip extra null character */

	ck_assert_msg(strncmp(answer_packet, buf, sizeof(answer_packet)) == 0,
		"Did not compile expected packet");
	ck_assert_msg(ret == len,
		"Bad packet length: %d, expected %d", ret, len);
}
END_TEST

START_TEST(test_decode_response)
{
	char buf[512];
	struct query q;
	int len;
	int ret;

	len = sizeof(buf);
	memset(&buf, 0, sizeof(buf));

	ret = dns_decode(buf, len, &q, QR_ANSWER, answer_packet, sizeof(answer_packet)-1);
	ck_assert_msg(ret == strlen(msgData),
		"Bad data length: %d, expected %zu", ret, strlen(msgData));
	ck_assert_msg(strncmp(msgData, buf, strlen(msgData)) == 0,
		"Did not extract expected data");
	ck_assert(q.id == 0x0539);
}
END_TEST

START_TEST(test_decode_response_with_high_trans_id)
{
	char buf[512];
	struct query q;
	int len;
	int ret;

	len = sizeof(buf);
	memset(&buf, 0, sizeof(buf));

	ret = dns_decode(buf, len, &q, QR_ANSWER, answer_packet_high_trans_id, sizeof(answer_packet_high_trans_id)-1);
	ck_assert_msg(ret == strlen(msgData),
		"Bad data length: %d, expected %zu", ret, strlen(msgData));
	ck_assert_msg(strncmp(msgData, buf, strlen(msgData)) == 0,
		"Did not extract expected data");
	ck_assert_msg(q.id == 0x8539,
		"q.id was %08X instead of %08X!", q.id, 0x8539);
}
END_TEST

START_TEST(test_get_id_short_packet)
{
	char buf[5];
	int len;
	unsigned short id;

	len = sizeof(buf);
	memset(&buf, 5, sizeof(buf));

	id = dns_get_id(buf, len);
	ck_assert(id == 0);
}
END_TEST

START_TEST(test_get_id_low)
{
	unsigned short id;

	id = dns_get_id(answer_packet, sizeof(answer_packet));
	ck_assert(id == 1337);
}
END_TEST

START_TEST(test_get_id_high)
{
	unsigned short id;

	id = dns_get_id(answer_packet_high_trans_id, sizeof(answer_packet_high_trans_id));
	ck_assert(id == 0x8539);
}
END_TEST

static void
dump_packet(char *buf, size_t len)
{
	int pos;

	for (pos = 0; pos < len; pos++) {
		printf("\\x%02X", (unsigned char) buf[pos]);
	}
	printf("\n");
	for (pos = 0; pos < len; pos++) {
		if (isalnum((unsigned char) buf[pos])) {
			printf(" %c  ", (unsigned char) buf[pos]);
		} else {
			printf("    ");
		}
	}
	printf("\n");
}

TCase *
test_dns_create_tests()
{
	TCase *tc;

	tc = tcase_create("Dns");
	tcase_add_test(tc, test_encode_query);
	tcase_add_test(tc, test_decode_query);
	tcase_add_test(tc, test_encode_response);
	tcase_add_test(tc, test_decode_response);
	tcase_add_test(tc, test_decode_response_with_high_trans_id);
	tcase_add_test(tc, test_get_id_short_packet);
	tcase_add_test(tc, test_get_id_low);
	tcase_add_test(tc, test_get_id_high);

	return tc;
}
