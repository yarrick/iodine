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

TCase *
test_dns_create_tests()
{
	TCase *tc;

	tc = tcase_create("Dns");
	tcase_add_test(tc, test_encode_hostname);
	tcase_add_test(tc, test_encode_hostname_nodot);
	tcase_add_test(tc, test_encode_hostname_toolong);

	return tc;
}
