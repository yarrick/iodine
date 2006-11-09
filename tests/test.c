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
#include <assert.h>

#include "structs.h"
#include "encoding.h"
#include "dns.h"
#include "read.h"
	
static void
test_readputshort()
{
	short tshort;
	short putted;
	short temps;
	char buf[4];
	short *s;
	char* p;
	int i;

	printf(" * Testing read/putshort... ");
	fflush(stdout);

	for (i = 0; i < 65536; i++) {
		tshort = (unsigned short) i;
		temps = htons(tshort);
		p = buf;
		putshort(&p, tshort);
		s = &putted;
		memcpy(s, buf, sizeof(short));
		if (putted != temps) {
			printf("Bad value on putshort for %d\n", i);
			exit(1);
		}
		s = &temps;
		memcpy(buf, s, sizeof(short));
		p = buf;
		readshort(NULL, &p, &temps);
		if (temps != tshort) {
			printf("Bad value on readshort for %d\n", i);
			exit(1);
		}
	}

	printf("OK\n");
}

static void
test_readputlong()
{
	char buf[4];
	uint32_t putint;
	uint32_t tempi;
	uint32_t tint;
	uint32_t *l;
	char* p;
	int i;

	printf(" * Testing read/putlong... ");
	fflush(stdout);

	for (i = 0; i < 32; i++) {
		tint = 0xF << i;
		tempi = htonl(tint);
		p = buf;
		putlong(&p, tint);
		l = &putint;
		memcpy(l, buf, sizeof(uint32_t));
		if (putint != tempi) {
			printf("Bad value on putlong for %d\n", i);
			exit(2);
		}
		l = &tempi;
		memcpy(buf, l, sizeof(uint32_t));
		p = buf;
		readlong(NULL, &p, &tempi);
		if (tempi != tint) {
			printf("Bad value on readlong for %d\n", i);
			exit(2);
		}
	}

	printf("OK\n");
}


static void
test_readname()
{
	char emptyloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 }; 
	char infloop[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 'A', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 }; 
	char longname[] = 
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x3FzBCDEFGHIJKLMNOPQURSTUVXYZ0123456789abcdefghijklmnopqrstuvxyzAA"
		"\x00\x00\x01\x00\x01";
	char onejump[] = 
		"AA\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x02hh\xc0\x15\x00\x01\x00\x01\x05zBCDE\x00";
	char badjump[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 }; 
	char badjump2[] = {
		'A', 'A', 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 'B', 'A', 0xfe, 0xcc, 0x00, 0x01, 0x00, 0x01 }; 
	char *jumper;
	char buf[1024];
	char *data;
	int rv;

	printf(" * Testing readname... ");
	fflush(stdout);

	memset(buf, 0, sizeof(buf));
	data = emptyloop + sizeof(HEADER);
	buf[1023] = 'A';
	rv = readname(emptyloop, sizeof(emptyloop), &data, buf, 1023);
	assert(buf[1023] == 'A');
	
	memset(buf, 0, sizeof(buf));
	data = infloop + sizeof(HEADER);
	buf[4] = '\a';
	rv = readname(infloop, sizeof(infloop), &data, buf, 4);
	assert(buf[4] == '\a');
	
	memset(buf, 0, sizeof(buf));
	data = longname + sizeof(HEADER);
	buf[256] = '\a';
	rv = readname(longname, sizeof(longname), &data, buf, 256);
	assert(buf[256] == '\a');

	memset(buf, 0, sizeof(buf));
	data = onejump + sizeof(HEADER);
	rv = readname(onejump, sizeof(onejump), &data, buf, 256);
	assert(rv == 9);
	
	// These two tests use malloc to cause segfault if jump is executed
	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump));
	if (jumper) {
		memcpy(jumper, badjump, sizeof(badjump));
		data = jumper + sizeof(HEADER);
		rv = readname(jumper, sizeof(badjump), &data, buf, 256);
		assert(rv == 0);
	}
	free(jumper);
	
	memset(buf, 0, sizeof(buf));
	jumper = malloc(sizeof(badjump2));
	if (jumper) {
		memcpy(jumper, badjump2, sizeof(badjump2));
		data = jumper + sizeof(HEADER);
		rv = readname(jumper, sizeof(badjump2), &data, buf, 256);
		assert(rv == 4);
		assert(strcmp("BA.", buf) == 0);
	}
	free(jumper);

	printf("OK\n");
}

static void
test_encode_hostname() {
	char buf[256];
	int len;
	int ret;

	len = 256;
	printf(" * Testing hostname encoding... ");
	fflush(stdout);

	memset(buf, 0, 256);
	ret = dns_encode_hostname(	// More than 63 chars between dots
		"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
		, buf, len);
	assert(ret == -1);
	
	memset(buf, 0, 256);
	ret = dns_encode_hostname(	// More chars than fits into array
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ.ABCDEFGHIJKLMNOPQRSTUVWXYZ."
		, buf, len);
	assert(ret == -1);
	assert(strlen(buf) < len);
	
	printf("OK\n");
}

static void
test_base32() {
	char temp[256];
	char *start = "HELLOTEST";
	char *out = "1HELLOTEST";
	char *end;
	char *tempend;
	int codedlength;

	printf(" * Testing base32 encoding... ");
	fflush(stdout);

	memset(temp, 0, sizeof(temp));
	end = malloc(16);
	memset(end, 0, 16);

	codedlength = encode_data(start, 9, 256, temp, 0);
	tempend = temp + strlen(temp);
	decode_data(end, 16, temp, tempend);
	assert(strcmp(out, end) == 0);
	free(end);
	
	printf("OK\n");
}

int
main()
{
	printf("** iodine test suite\n");

	test_readputshort();
	test_readputlong();
	test_readname();
	test_encode_hostname();
	test_base32();

	printf("** All went well :)\n");
	return 0;
}
