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

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif
#include <sys/stat.h>
#ifdef DARWIN
#include <arpa/nameser_compat.h>
#endif

#include "common.h"
#include "compat.h"
#include "dns.h"
#include "encoding.h"
#include "read.h"
#include "test_main.h"

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
	len = sizeof(resolv) - (d - resolv);
	strlcpy(d, topdomain, len);
	len = sizeof(buf);
	ret = dns_encode(buf, len, &q, QR_QUERY, resolv, strlen(resolv));
	len = sizeof(query_packet) - 1; /* Skip extra null character */

	if (strncmp(query_packet, buf, sizeof(query_packet)) || ret != (int)len) {
		printf("\n");
		dump_packet(query_packet, len);
		dump_packet(buf, ret);
	}
	ck_assert_mem_eq(query_packet, buf, sizeof(query_packet));
	ck_assert_int_eq(ret, len);
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

	ck_assert_str_eq(buf, innerData);
	ck_assert_int_eq(strlen(buf), strlen(innerData));
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
	strlcpy(q.name, host, QUERY_NAME_SIZE);
	q.type = T_NULL;
	q.id = 1337;

	ret = dns_encode(buf, len, &q, QR_ANSWER, msgData, strlen(msgData));
	len = sizeof(answer_packet) - 1; /* Skip extra null character */

	ck_assert_str_eq(answer_packet, buf);
	ck_assert_int_eq(ret, len);
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
	ck_assert_int_eq(ret, strlen(msgData));
	ck_assert_str_eq(msgData, buf);
	ck_assert_int_eq(q.id, 0x0539);
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
	ck_assert_int_eq(ret, strlen(msgData));
	ck_assert_str_eq(msgData, buf);
	ck_assert_int_eq(q.id, 0x8539);
}
END_TEST

START_TEST(test_decode_response_overflow_rlen)
{
	/* A well-formed T_NULL answer (same header/question as
	   answer_packet) whose answer advertises rlen=0xFFFF while only a
	   few rdata bytes are actually present in the packet. */
	char packet[] =
		"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
		"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
		"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
		"\x01\x62\x00\x00\x0A\x00\x01\x00\x00\x00\x00\xFF\xFF\x78\x78\x78";
	char buf[512];
	struct query q;
	int ret;

	memset(&q, 0, sizeof(q));
	memset(&buf, 0, sizeof(buf));
	ret = dns_decode(buf, sizeof(buf), &q, QR_ANSWER,
			   packet, sizeof(packet) - 1);
	ck_assert_msg(ret == 0,
			"Overlong advertised rlen (0xFFFF) was not rejected: rv=%d",
			ret);
}
END_TEST

START_TEST(test_decode_response_compressed_mx)
{
	char packet[4096];
	char out[4096];
	unsigned int answers;

	for (answers = 1; answers < 20; answers++) {
		char *p = packet;
		struct query q;
		unsigned int i;
		int ret;

		memset(packet, 0, sizeof(packet));
		/* Response, one question, many MX answers. */
		putshort(&p, 0x1234);
		putshort(&p, 0x8000);
		putshort(&p, 1);
		putshort(&p, answers);
		putshort(&p, 0);
		putshort(&p, 0);

		/* A 253-character presentation name (255 bytes on the wire). */
		for (i = 0; i < 4; i++) {
			int label_len = (i == 3) ? 61 : 63;
			*p++ = (unsigned char)label_len;
			memset(p, 'a' + i, (size_t)label_len);
			p += label_len;
		}
		*p++ = 0;
		putshort(&p, 15); /* MX */
		putshort(&p, 1);  /* IN */

		for (i = 0; i < answers; i++) {
			/* Owner and exchange both compress to the question at offset 12. */
			putshort(&p, 0xc00c);
			putshort(&p, 15); /* MX */
			putshort(&p, 1);  /* IN */
			putlong(&p, 0);
			putshort(&p, 4);
			putshort(&p, (unsigned int)(10 * (i + 1)));
			putshort(&p, 0xc00c);
		}

		ret = dns_decode(out, sizeof(out), &q, QR_ANSWER,
				 packet, (size_t)(p - packet));
		ck_assert_int_eq(ret, MIN(sizeof(packet) - 1, answers * 254));
	}
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
	ck_assert_int_eq(id, 0);
}
END_TEST

START_TEST(test_get_id_low)
{
	unsigned short id;

	id = dns_get_id(answer_packet, sizeof(answer_packet));
	ck_assert_int_eq(id, 1337);
}
END_TEST

START_TEST(test_get_id_high)
{
	unsigned short id;

	id = dns_get_id(answer_packet_high_trans_id, sizeof(answer_packet_high_trans_id));
	ck_assert_int_eq(id, 0x8539);
}
END_TEST

static void
dump_packet(char *buf, size_t len)
{
	unsigned int pos;

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

START_TEST(test_encode_a_response)
{
	/* Expected response for A query "ns.t.iodine.tun", answer 1.2.3.4 */
	const char expected[] =
		"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" /* Header (qr=1, aa=1, qd=1, an=1) */
		"\x02\x6E\x73\x01\x74\x06\x69\x6F\x64\x69\x6E\x65" /* QUERY: "ns.t.iodine" */
		"\x03\x74\x75\x6E\x00"				   /*   ".tun" */
		"\x00\x01\x00\x01"                                 /*   TYPE: A, CLASS: IN */
		"\xC0\x0C\x00\x01\x00\x01"                         /* ANSWER ptr 0x0C, TYPE: A, CLASS: IN */
		"\x00\x00\x0E\x10"                                 /*   TTL: 3600 */
		"\x00\x04\x01\x02\x03\x04";                        /*   RDLENGTH: 4, RDATA: 1.2.3.4 */
	char buf[512];
	struct query q;
	struct sockaddr_storage address;
	struct sockaddr_in *dest;
	size_t expected_len = sizeof(expected) - 1; /* Skip zero termination of string */
	int ret;

	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "ns.t.iodine.tun", sizeof(q.name));
	q.type = T_A;
	q.id = 1337;

	/* Non-IPv4 destination should fail with -1 */
	address.ss_family = AF_INET6;
	ret = dns_encode_standard_response(buf, sizeof(buf), &q, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, -1);

	/* Valid IPv4 destination (1.2.3.4) */
	dest = (struct sockaddr_in *) &address;
	dest->sin_family = AF_INET;
	dest->sin_addr.s_addr = htonl(0x01020304);

	for (size_t len = 0; len < expected_len; len++) {
		/* Return 0 when encoded response does not fit */
		ret = dns_encode_standard_response(buf, len, &q, (struct sockaddr *) &address);
		ck_assert_int_eq(ret, 0);
	}

	ret = dns_encode_standard_response(buf, sizeof(buf), &q, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, expected_len);
	ck_assert_mem_eq(buf, expected, expected_len);
}
END_TEST

START_TEST(test_encode_aaaa_response)
{
	/* Expected response for AAAA query "ns.t.iodine.tun", answer 2001:db8::1:f2:f03:f004 */
	const char expected[] =
		"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" /* Header (qr=1, aa=1, qd=1, an=1) */
		"\x02\x6E\x73\x01\x74\x06\x69\x6F\x64\x69\x6E\x65" /* QUERY: "ns.t.iodine" */
		"\x03\x74\x75\x6E\x00"				   /*   ".tun" */
		"\x00\x1C\x00\x01"                                 /*   TYPE: AAAA, CLASS: IN */
		"\xC0\x0C\x00\x1C\x00\x01"                         /* ANSWER ptr 0x0C, TYPE: AAAA, CLASS: IN */
		"\x00\x00\x0E\x10\x00\x10"                         /*   TTL: 3600, RDLENGTH: 16 */
		"\x20\x01\x0D\xB8\x00\x00\x00\x00\x00\x01\x00\xF2\x0F\x03\xF0\x04";   /*   RDATA: 2001:db8::1:f2:f03:f004 */
	char buf[512];
	struct query q;
	struct sockaddr_storage address;
	struct sockaddr_in6 *dest;
	size_t expected_len = sizeof(expected) - 1; /* Skip zero termination of string */
	int ret;

	memset(&q, 0, sizeof(q));
	strlcpy(q.name, "ns.t.iodine.tun", sizeof(q.name));
	q.type = T_AAAA;
	q.id = 1337;

	/* Non-IPv6 destination should fail with -1 */
	address.ss_family = AF_INET;
	ret = dns_encode_standard_response(buf, sizeof(buf), &q, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, -1);

	dest = (struct sockaddr_in6 *) &address;
	dest->sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1:f2:f03:f004", &dest->sin6_addr);

	for (size_t len = 0; len < expected_len; len++) {
		/* Return 0 when encoded response does not fit */
		ret = dns_encode_standard_response(buf, len, &q, (struct sockaddr *) &address);
		ck_assert_int_eq(ret, 0);
	}

	ret = dns_encode_standard_response(buf, sizeof(buf), &q, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, expected_len);
	ck_assert_mem_eq(buf, expected, expected_len);
}
END_TEST

START_TEST(test_encode_ns_response)
{
	/* Expected response for NS query "abc.t.iodine.tun" in "t.iodine.tun", NS 1.2.3.4 */
	char expected[] =
		"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x01" /* Header (id=1337, qr=1, aa=1, qd=1, an=1, ar=1) */
		"\x03\x61\x62\x63"                                 /* QUERY (0x0C): "abc" */
		"\x01\x74\x06\x69\x6F\x64\x69\x6E\x65"             /*       (0x10): ".t.iodine" */
		"\x03\x74\x75\x6E\x00"                             /*               ".tun" */
		"\x00\x02\x00\x01"                                 /*   TYPE: NS, CLASS: IN */
		"\xC0\x0C\x00\x02\x00\x01"                         /* ANSWER ptr 0x0C, TYPE: NS, CLASS: IN */
		"\x00\x00\x0E\x10"                                 /*   TTL: 3600 */
		"\x00\x05\x02\x6E\x73\xC0\x10"                     /*   RDLENGTH: 5, RDATA (0x2E): "ns" + ptr 0x10 */
		"\xC0\x2E\x00\x01\x00\x01"                         /* ADDITIONAL ptr 0x2E, TYPE: A, CLASS: IN */
		"\x00\x00\x0E\x10"                                 /*   TTL: 3600 */
		"\x00\x04\x01\x02\x03\x04";                        /*   RDLENGTH: 4, RDATA: 1.2.3.4 */
	char buf[512];
	struct query q;
	struct sockaddr_storage address;
	struct sockaddr_in *dest;
	size_t expected_len = sizeof(expected) - 1; /* Skip zero termination of string */
	int ret;

	memset(&q, 0, sizeof(q));
	q.type = T_NS;
	q.id = 1337;

	strlcpy(q.name, "abc.t.iodine.tun", sizeof(q.name));
	dest = (struct sockaddr_in *) &address;
	dest->sin_family = AF_INET;
	dest->sin_addr.s_addr = htonl(0x01020304);

	for (size_t len = 0; len < expected_len; len++) {
		/* Return 0 when encoded response does not fit */
		ret = dns_encode_ns_response(buf, len, &q, 4, (struct sockaddr *) &address);
		ck_assert_int_eq(ret, 0);
	}

	for (int offset = -1; offset < 50; offset++) {
		if (offset == 0) continue;  /* abc.t.iodine.tun */
		if (offset == 4) continue;  /* t.iodine.tun */
		if (offset == 6) continue;  /* iodine.tun */
		if (offset == 13) continue; /* tun */
		/* Return -1 when topdomain offset in incorrect */
		ret = dns_encode_ns_response(buf, sizeof(buf), &q, offset, (struct sockaddr *) &address);
		ck_assert_int_eq(ret, -1);
	}

	ret = dns_encode_ns_response(buf, sizeof(buf), &q, 4, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, expected_len);
	ck_assert_mem_eq(buf, expected, expected_len);

	/* Non-IPv4 destination omits the 16-byte additional A record */
	address.ss_family = AF_INET6;
	expected[11] = 0; /* Expect arcount == 0 */
	ret = dns_encode_ns_response(buf, sizeof(buf), &q, 4, (struct sockaddr *) &address);
	ck_assert_int_eq(ret, expected_len - 16);
	ck_assert_mem_eq(buf, expected, expected_len - 16);
}
END_TEST


TCase *
test_create(void)
{
	TCase *tc;

	tc = tcase_create("Dns");
	tcase_add_test(tc, test_encode_query);
	tcase_add_test(tc, test_decode_query);
	tcase_add_test(tc, test_encode_response);
	tcase_add_test(tc, test_decode_response);
	tcase_add_test(tc, test_decode_response_with_high_trans_id);
	tcase_add_test(tc, test_decode_response_overflow_rlen);
	tcase_add_test(tc, test_decode_response_compressed_mx);
	tcase_add_test(tc, test_get_id_short_packet);
	tcase_add_test(tc, test_get_id_low);
	tcase_add_test(tc, test_get_id_high);
	tcase_add_test(tc, test_encode_a_response);
	tcase_add_test(tc, test_encode_aaaa_response);
	tcase_add_test(tc, test_encode_ns_response);

	return tc;
}
