/*
 * Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"

static const char cb32[] = 
	"abcdefghijklmnopqrstuvwxyz0123456789";

int 
base32_encode(char **buf, size_t *buflen, const void *data, size_t size)
{
	size_t newsize;
	char *newbuf;
	char *s;
	char *p;
	char *q;
	int i;

	newsize = 8 * (size / 5 + 1) + 1;
	if (newsize > *buflen) {
		if ((newbuf = realloc(*buf, newsize)) == NULL) {
			free(*buf);
			*buf = NULL;
			*buflen = 0;
			return 0;
		}

		*buf = newbuf;
		*buflen = newsize;
	}

	p = s = *buf;
	q = (char*)data;

	for(i=0;i<size;i+=5) {
		p[0] = cb32[(q[0] >> 3)];
		p[1] = cb32[((q[0] & 0x07) << 2) | ((q[1] & 0xc0) >> 6)];
		p[2] = (i+1 < size) ? cb32[((q[1] & 0x3e) >> 1)] : '\0';
		p[3] = (i+1 < size) ? cb32[((q[1] & 0x01) << 4) | ((q[2] & 0xf0) >> 4)] : '\0';
		p[4] = (i+2 < size) ? cb32[((q[2] & 0x0f) << 1) | ((q[3] & 0x80) >> 7)] : '\0';
		p[5] = (i+3 < size) ? cb32[((q[3] & 0x3e) >> 2)] : '\0';
		p[6] = (i+3 < size) ? cb32[((q[3] & 0x03) << 3) | ((q[4] & 0xe0) > 5)] : '\0';
		p[7] = (i+4 < size) ? cb32[((q[4] & 0x1f))] : '\0';
		
		q += 5;
		p += 8;
	}	
	*p = 0;
	return strlen(s);
}

#define DECODE_ERROR 0xffffffff

static int
pos(char c)
{
    const char *p;
    for (p = cb32; *p; p++)
		if (*p == c)
			return p - cb32;
    return -1;
}

static int
decode_token(const char *t, char *data) 
{
	int len;

	len = strlen(t);

	if (len < 2)
		return 0;

	data[0] = ((pos(t[0]) & 0x1f) << 3) | 
			  ((pos(t[1]) & 0x1c) >> 2);
	
	if (len < 4)
		return 1;

	data[1] = ((pos(t[1]) & 0x03) << 6) | 
			  ((pos(t[2]) & 0x1f) << 1) | 
			  ((pos(t[3]) & 0x10) >> 4);

	if (len < 5)
		return 2;

	data[2] = ((pos(t[3]) & 0x0f) << 4) |
			  ((pos(t[4]) & 0x1e) >> 1);

	if (len < 7)
		return 3;

	data[3] = ((pos(t[4]) & 0x01) << 7) |
			  ((pos(t[5]) & 0x1f) << 2) |
			  ((pos(t[6]) & 0x18) >> 3);

	if (len < 8)
		return 4;

	data[4] = ((pos(t[6]) & 0x07) << 5) |
			  ((pos(t[7]) & 0x1f));

	return 5;
}

int
base32_decode(void **buf, size_t *buflen, const char *str)
{
	unsigned char *q;
	size_t newsize;
	const char *p;
	char *newbuf;
	int len;
	
	newsize = 5 * (strlen(str) / 8 + 1) + 1;
	if (newsize > *buflen) {
		if ((newbuf = realloc(*buf, newsize)) == NULL) {
			free(*buf);
			*buf = NULL;
			*buflen = 0;
			return 0;
		}

		*buf = newbuf;
		*buflen = newsize;
	}

	q = *buf;
	for (p = str; *p && strchr(cb32, *p); p += 8) {
		len = decode_token(p, (char *) q);	
		q += len;
		
		if (len < 5)
			break;
	}
	*q = '\0';
	
	return q - (unsigned char *) *buf;
}

