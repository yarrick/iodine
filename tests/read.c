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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "common.h"
#include "encoding.h"
#include "dns.h"
#include "read.h"
#include "test.h"

START_TEST(test_read_putshort)
{
	unsigned short k;
	unsigned short l;
	char* p;
	int i;

	for (i = 0; i < 65536; i++) {
		p = (char*)&k;
		putshort(&p, i);
		fail_unless(ntohs(k) == i,
				"Bad value on putshort for %d: %d != %d",
					i, ntohs(k), i);

		p = (char*)&k;
		readshort(NULL, &p, (short *) &l);
		fail_unless(l == i,
				"Bad value on readshort for %d: %d != %d",
					i, l, i);
	}
}
END_TEST

START_TEST(test_read_putlong)
{
	uint32_t k;
	uint32_t l;
	char* p;
	int i;
	int j;

	for (i = 0; i < 32; i++) {
		p = (char*)&k;
		j = 0xf << i;

		putlong(&p, j);

		fail_unless(ntohl(k) == j,
				"Bad value on putlong for %d: %d != %d", i, ntohl(j), j);

		p = (char*)&k;
		readlong(NULL, &p, &l);

		fail_unless(l == j,
				"Bad value on readlong for %d: %d != %d", i, l, j);
	}
}
END_TEST

START_TEST(test_read_name)
{
	unsigned char emptyloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
	unsigned char infloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 'A', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
	unsigned char longname[] =
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x00\x00\x01\x00\x01";
	unsigned char onejump[] =
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x02hh\xc0\x15\x00\x01\x00\x01\x05zBCDE\x00";
	unsigned char badjump[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 };
	unsigned char badjump2[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 'B', 'A', 0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 };
	unsigned char *jumper;
	char buf[1024];
	char *data;
	int rv;

	memset(buf, 0, sizeof(buf));
	data = (char*) emptyloop + sizeof(HEADER);
	buf[1023] = 'A';
	rv = readname((char *) emptyloop, sizeof(emptyloop), &data, buf, 1023);
	fail_unless(buf[1023] == 'A', NULL);

	memset(buf, 0, sizeof(buf));
	data = (char*) infloop + sizeof(HEADER);
	buf[4] = '\a';
	rv = readname((char*) infloop, sizeof(infloop), &data, buf, 4);
	fail_unless(buf[4] == '\a', NULL);

	memset(buf, 0, sizeof(buf));
	data = (char*) longname + sizeof(HEADER);
	buf[256] = '\a';
	rv = readname((char*) longname, sizeof(longname), &data, buf, 256);
	fail_unless(buf[256] == '\a', NULL);

	memset(buf, 0, sizeof(buf));
	data = (char*) onejump + sizeof(HEADER);
	rv = readname((char*) onejump, sizeof(onejump), &data, buf, 256);
	fail_unless(rv == 9, NULL);

	/* These two tests use malloc to cause segfault if jump is executed */
	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump));
	if (jumper) {
		memcpy(jumper, badjump, sizeof(badjump));
		data = (char*) jumper + sizeof(HEADER);
		rv = readname((char*) jumper, sizeof(badjump), &data, buf, 256);

		fail_unless(rv == 0, NULL);
		fail_unless(buf[0] == 0, NULL);
	}
	free(jumper);

	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump2));
	if (jumper) {
		memcpy(jumper, badjump2, sizeof(badjump2));
		data = (char*) jumper + sizeof(HEADER);
		rv = readname((char*) jumper, sizeof(badjump2), &data, buf, 256);

		fail_unless(rv == 4, NULL);
		fail_unless(strcmp("BA.", buf) == 0,
				"buf is not BA: %s", buf);
	}
	free(jumper);
}
END_TEST

START_TEST(test_putname)
{
	char out[] = "\x06" "BADGER\x06" "BADGER\x04" "KRYO\x02" "SE\x00";
	char buf[256];
	char *domain = "BADGER.BADGER.KRYO.SE";
	char *b;
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, domain);

	fail_unless(ret == strlen(domain) + 1, NULL);
	fail_unless(strncmp(buf, out, ret) == 0, "Happy flow failed");
}
END_TEST

START_TEST(test_putname_nodot)
{
	char buf[256];
	char *nodot =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *b;
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, nodot);

	fail_unless(ret == -1, NULL);
	fail_unless(b == buf, NULL);
}
END_TEST

START_TEST(test_putname_toolong)
{
	char buf[256];
	char *toolong =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.";
	char *b;
	int len;
	int ret;

	len = 256;

	memset(buf, 0, 256);
	b = buf;
	ret = putname(&b, 256, toolong);

	fail_unless(ret == -1, NULL);
	fail_unless(b == buf, NULL);
}
END_TEST


TCase *
test_read_create_tests()
{
	TCase *tc;

	tc = tcase_create("Read");
	tcase_set_timeout(tc, 60);
	tcase_add_test(tc, test_read_putshort);
	tcase_add_test(tc, test_read_putlong);
	tcase_add_test(tc, test_read_name);
	tcase_add_test(tc, test_putname);
	tcase_add_test(tc, test_putname_nodot);
	tcase_add_test(tc, test_putname_toolong);

	return tc;
}
