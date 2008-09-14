/*
 * Copyright (c) 2006-2008 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include "encoding.h"
#include "common.h"
#include "base64.h"

static const char cb64[] = 
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+";
static unsigned char rev64[128];
static int reverse_init = 0;

#define REV64(x) rev64[(int) (x)]

static struct encoder base64_encoder =
{
	"BASE64",
	base64_encode,
	base64_decode,
	base64_handles_dots,
	base64_handles_dots
};

struct encoder
*get_base64_encoder()
{
	return &base64_encoder;
}

int 
base64_handles_dots()
{
	return 0;
}

int 
base64_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	size_t newsize;
	size_t maxsize;
	unsigned char c;
	unsigned char *s;
	unsigned char *p;
	unsigned char *q;
	int i;

	memset(buf, 0, *buflen);
	
	if (!reverse_init) {
		for (i = 0; i < 64; i++) {
			c = cb64[i];
			rev64[(int) c] = i;
		}
		reverse_init = 1;
	}

	/* how many chars can we encode within the buf */
	maxsize = 3 * (*buflen / 4 - 1) - 1;
	/* how big will the encoded data be */
	newsize = 4 * (size / 3 + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		size = maxsize;
	}

	p = s = (unsigned char *) buf;
	q = (unsigned char *)data;

	for(i=0;i<size;i+=3) {
		p[0] = cb64[((q[0] & 0xfc) >> 2)];
		p[1] = cb64[(((q[0] & 0x03) << 4) | ((q[1] & 0xf0) >> 4))];
		p[2] = (i+1 < size) ? cb64[((q[1] & 0x0f) << 2 ) | ((q[2] & 0xc0) >> 6)] : '\0';
		p[3] = (i+2 < size) ? cb64[(q[2] & 0x3f)] : '\0';
		
		q += 3;
		p += 4;
	}	
	*p = 0;

	/* store number of bytes from data that was used */
	*buflen = size;

	return strlen(buf) - 1;
}

#define DECODE_ERROR 0xffffffff

static int
decode_token(const unsigned char *t, unsigned char *data, size_t len) 
{
	if (len < 2)
		return 0;

	data[0] = ((REV64(t[0]) & 0x3f) << 2) | 
			  ((REV64(t[1]) & 0x30) >> 4);

	if (len < 3)
		return 1;

	data[1] = ((REV64(t[1]) & 0x0f) << 4) | 
			  ((REV64(t[2]) & 0x3c) >> 2);

	if (len < 4)
		return 2;

	data[2] = ((REV64(t[2]) & 0x03) << 6) |
			  (REV64(t[3]) & 0x3f);

	return 3;
}

int
base64_decode(void *buf, size_t *buflen, const char *str, size_t slen)
{
	unsigned char *q;
	size_t newsize;
	size_t maxsize;
	const char *p;
	unsigned char c;
	unsigned char block[4];
	int len;
	int i;

	if (!reverse_init) {
		for (i = 0; i < 64; i++) {
			c = cb64[i];
			rev64[(int) c] = i;
		}
		reverse_init = 1;
	}
	
	/* chars needed to decode slen */
	newsize = 3 * (slen / 4 + 1) + 1;
	/* encoded chars that fit in buf */
	maxsize = 4 * (*buflen / 3 + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		slen = maxsize;
	}
	

	q = buf;
	for (p = str; *p; p += 4) {
		/* since the str is const, we unescape in another buf */
		for (i = 0; i < 4; i++) {
			block[i] = p[i];
		}
		len = decode_token(block, (unsigned char *) q, slen);	
		q += len;
		slen -= 4;
		
		if (len < 3)
			break;
	}
	*q = '\0';
	
	return q - (unsigned char *) buf;
}

