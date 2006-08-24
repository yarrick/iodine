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

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "structs.h"
#include "dns.h"
#include "read.h"

int
main()
{
	short tshort;
	short temps;
	short putted;
	short *s;

	long tint;
	long tempi;
	long putint;
	long *l;
	
	int i;
	char buf[4];
	char* p;

	printf("iodine test suite\n");
	printf("Testing read/putshort... ");
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

	printf("Testing read/putlong... ");
	fflush(stdout);

	for (i = 0; i < 32; i++) {
		tint = 0xF << i;
		tempi = htonl(tint);
		p = buf;
		putlong(&p, tint);
		l = &putint;
		memcpy(l, buf, sizeof(int));
		if (putint != tempi) {
			printf("Bad value on putlong for %d\n", i);
			exit(2);
		}
		l = &tempi;
		memcpy(buf, l, sizeof(int));
		p = buf;
		readlong(NULL, &p, &tempi);
		if (tempi != tint) {
			printf("Bad value on readlong for %d\n", i);
			exit(2);
		}
	}

	printf("OK\n");


	printf("All went well :)\n");
	return 0;
}
