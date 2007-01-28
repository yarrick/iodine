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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>

#include "structs.h"
#include "dns.h"
#include "test.h"

static char queryPacket[] = 
	"\x05\x39\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00";

static char answerPacket[] = 
	"\x05\x39\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x05\x73\x69\x6C\x6C"
	"\x79\x04\x68\x6F\x73\x74\x02\x6F\x66\x06\x69\x6F\x64\x69\x6E\x65\x04"
	"\x63\x6F\x64\x65\x04\x6B\x72\x79\x6F\x02\x73\x65\x00\x00\x0A\x00\x01"
	"\xC0\x0C\x00\x0A\x00\x01\x00\x00\x00\x00\x00\x23\x74\x68\x69\x73\x20"
	"\x69\x73\x20\x74\x68\x65\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x74\x6F"
	"\x20\x62\x65\x20\x64\x65\x6C\x69\x76\x65\x72\x65\x64";
	
static char *msgData = "this is the message to be delivered";

START_TEST(test_encode_hostname)
{
	char out[] = "\x06" "BADGER\x06" "BADGER\x04" "KRYO\x02" "SE\x00";
	char buf[256];
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	ret = dns_encode_hostname("BADGER.BADGER.KRYO.SE", buf, len);
	fail_unless(strncmp(buf, out, ret) == 0, "Happy flow failed");
}
END_TEST
	
START_TEST(test_encode_hostname_nodot)
{
	char buf[256];
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	ret = dns_encode_hostname(	// More than 63 chars between dots
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		, buf, len);
	fail_unless(ret == -1, NULL);
}
END_TEST
	
START_TEST(test_encode_hostname_toolong)
{
	char buf[256];
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	ret = dns_encode_hostname(	// More chars than fits into array
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		, buf, len);

	fail_unless(ret == -1, NULL);
	fail_unless(strlen(buf) < len, NULL);
}
END_TEST

START_TEST(test_encode_query)
{
	char buf[512];
	char *host = "silly.host.of.iodine.code.kryo.se";
	struct query q;
	int len;
	int ret;

	len = sizeof(buf);
	memset(&q, 0, sizeof(struct query));
	q.type = T_NULL;
	q.id = 1337;

	ret = dns_encode(buf, len, &q, QR_QUERY, host, strlen(host));
	len = sizeof(queryPacket) - 1; // Skip extra null character

	fail_unless(strncmp(queryPacket, buf, sizeof(queryPacket)) == 0, "Did not compile expected packet");
	fail_unless(ret == len, va_str("Bad packet length: %d, expected %d", ret, len));
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
	memset(&q, 0, sizeof(struct query));
	strncpy(q.name, host, strlen(host));
	q.type = T_NULL;
	q.id = 1337;

	ret = dns_encode(buf, len, &q, QR_ANSWER, msgData, strlen(msgData));
	len = sizeof(answerPacket) - 1; // Skip extra null character

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

	ret = dns_decode(buf, len, QR_ANSWER, answerPacket, sizeof(answerPacket)-1);
	fail_unless(strncmp(msgData, buf, sizeof(msgData)) == 0, "Did not extract expected data");
	fail_unless(ret == strlen(msgData), va_str("Bad data length: %d, expected %d", ret, strlen(msgData)));
}
END_TEST

TCase *
test_dns_create_tests()
{
	TCase *tc;

	tc = tcase_create("Dns");
	tcase_add_test(tc, test_encode_hostname);
	tcase_add_test(tc, test_encode_hostname_nodot);
	tcase_add_test(tc, test_encode_hostname_toolong);
	tcase_add_test(tc, test_encode_query);
	tcase_add_test(tc, test_encode_response);
	tcase_add_test(tc, test_decode_response);

	return tc;
}
