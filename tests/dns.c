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
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>

#include "common.h"
#include "dns.h"
#include "encoding.h"
#include "test.h"

static void dump_packet(char *, size_t);

static char queryPacket[] = 
	"\x05\x39\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x32\x41\x4A\x42\x43"
	"\x55\x59\x54\x43\x50\x45\x42\x39\x47\x51\x39\x4C\x54\x45\x42\x55\x58"
	"\x47\x49\x44\x55\x4E\x42\x53\x53\x41\x36\x44\x46\x4F\x4E\x39\x43\x41"
	"\x5A\x44\x42\x32\x41\x41\x41\x41\x41\x36\x44\x42\x04\x6B\x72\x79\x6F"
	"\x02\x73\x65\x00\x00\x0A\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00"
	"\x00\x00";

static char answerPacket[] = 
	"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";
	
static char *msgData = "this is the message to be delivered";
static char *topdomain = "kryo.se";
	
static char *queryData = "HELLO this is the test data";
static char *recData = "AHELLO this is the test data";	/* The A flag is added */

START_TEST(test_encode_query)
{
	char buf[512];
	char resolv[512];
	struct query q;
	char *d;
	int len;
	int ret;

	len = sizeof(buf);
	memset(&buf, 0, sizeof(buf));
	memset(&resolv, 0, sizeof(resolv));
	memset(&q, 0, sizeof(struct query));
	q.type = T_NULL;
	q.id = 1337;
	d = resolv;

	*d++ = 'A';
	encode_data(queryData, strlen(queryData), 100, d);
	d = resolv + strlen(resolv);
	if (*d != '.') {
		*d++ = '.';
	}
	strcpy(d, topdomain);
	ret = dns_encode(buf, len, &q, QR_QUERY, resolv, strlen(resolv));
	len = sizeof(queryPacket) - 1; /* Skip extra null character */

	if (strncmp(queryPacket, buf, sizeof(queryPacket)) || ret != len) {
		printf("\n");
		dump_packet(queryPacket, len);
		dump_packet(buf, ret);
	}
	fail_unless(strncmp(queryPacket, buf, sizeof(queryPacket)) == 0, "Did not compile expected packet");
	fail_unless(ret == len, va_str("Bad packet length: %d, expected %d", ret, len));
}
END_TEST

START_TEST(test_decode_query)
{
	char buf[512];
	char *domain;
	struct query q;
	int len;
	int ret;

	memset(&q, 0, sizeof(struct query));
	memset(&buf, 0, sizeof(buf));
	q.id = 0;
	len = sizeof(queryPacket) - 1;

	dns_decode(buf, sizeof(buf), &q, QR_QUERY, queryPacket, len);
	domain = strstr(q.name, topdomain);
	ret = decode_data(buf, sizeof(buf), q.name, domain);

	fail_unless(strncmp(buf, recData, ret) == 0, "Did not extract expected host: '%s'", buf);
	fail_unless(strlen(buf) == strlen(recData), va_str("Bad host length: %d, expected %d", strlen(q.name), strlen(recData)));
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
	len = sizeof(answerPacket) - 1; /* Skip extra null character */

	fail_unless(strncmp(answerPacket, buf, sizeof(answerPacket)) == 0, "Did not compile expected packet");
	fail_unless(ret == len, va_str("Bad packet length: %d, expected %d", ret, len));
}
END_TEST

START_TEST(test_decode_response)
{
	char buf[512];
	int len;
	int ret;

	len = sizeof(buf);
	memset(&buf, 0, sizeof(buf));

	ret = dns_decode(buf, len, NULL, QR_ANSWER, answerPacket, sizeof(answerPacket)-1);
	fail_unless(strncmp(msgData, buf, sizeof(msgData)) == 0, "Did not extract expected data");
	fail_unless(ret == strlen(msgData), va_str("Bad data length: %d, expected %d", ret, strlen(msgData)));
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

	return tc;
}
