/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#define BLKSIZE_RAW 3
#define BLKSIZE_ENC 4

static const char cb64[] = 
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+";
static unsigned char rev64[128];
static int reverse_init = 0;

static int base64_encode(char *, size_t *, const void *, size_t);
static int base64_decode(void *, size_t *, const char *, size_t);
static int base64_handles_dots();
static int base64_blksize_raw();
static int base64_blksize_enc();

#define REV64(x) rev64[(int) (x)]

static struct encoder base64_encoder =
{
	"Base64",
	base64_encode,
	base64_decode,
	base64_handles_dots,
	base64_handles_dots,
	base64_blksize_raw,
	base64_blksize_enc
};

struct encoder
*get_base64_encoder()
{
	return &base64_encoder;
}

static int 
base64_handles_dots()
{
	return 0;
}

static int 
base64_blksize_raw()
{
	return BLKSIZE_RAW;
}

static int 
base64_blksize_enc()
{
	return BLKSIZE_ENC;
}

static int 
base64_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	size_t newsize;
	size_t maxsize;
	unsigned char *s;
	unsigned char *p;
	unsigned char *q;
	int i;

	memset(buf, 0, *buflen);
	
	/* how many chars can we encode within the buf */
	maxsize = BLKSIZE_RAW * (*buflen / BLKSIZE_ENC);
	/* how big will the encoded data be */
	newsize = BLKSIZE_ENC * (size / BLKSIZE_RAW);
	if (size % BLKSIZE_RAW) {
		newsize += BLKSIZE_ENC;
	}

	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		size = maxsize;
	}

	p = s = (unsigned char *) buf;
	q = (unsigned char *)data;

	for(i=0;i<size;i+=BLKSIZE_RAW) {
		p[0] = cb64[((q[0] & 0xfc) >> 2)];
		p[1] = cb64[(((q[0] & 0x03) << 4) | ((q[1] & 0xf0) >> 4))];
		p[2] = (i+1 < size) ? cb64[((q[1] & 0x0f) << 2 ) | ((q[2] & 0xc0) >> 6)] : '\0';
		p[3] = (i+2 < size) ? cb64[(q[2] & 0x3f)] : '\0';
		
		q += BLKSIZE_RAW;
		p += BLKSIZE_ENC;
	}	
	*p = 0;

	/* store number of bytes from data that was used */
	*buflen = size;

	return strlen(buf);
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

static int
base64_decode(void *buf, size_t *buflen, const char *str, size_t slen)
{
	unsigned char *q;
	size_t newsize;
	size_t maxsize;
	const char *p;
	unsigned char c;
	unsigned char block[BLKSIZE_ENC];
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
	newsize = BLKSIZE_RAW * (slen / BLKSIZE_ENC + 1) + 1;
	/* encoded chars that fit in buf */
	maxsize = BLKSIZE_ENC * (*buflen / BLKSIZE_RAW + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		slen = maxsize;
	}
	

	q = buf;
	for (p = str; *p; p += BLKSIZE_ENC) {
		/* since the str is const, we unescape in another buf */
		for (i = 0; i < BLKSIZE_ENC; i++) {
			block[i] = p[i];
		}
		len = decode_token(block, (unsigned char *) q, slen);	
		q += len;
		slen -= BLKSIZE_ENC;
		
		if (len < BLKSIZE_RAW)
			break;
	}
	*q = '\0';
	
	return q - (unsigned char *) buf;
}

