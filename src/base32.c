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
#include "base32.h"

#define BLKSIZE_RAW 5
#define BLKSIZE_ENC 8

static const char cb32[] = 
	"abcdefghijklmnopqrstuvwxyz012345";
static unsigned char rev32[128];
static int reverse_init = 0;

static int base32_decode(void *, size_t *, const char *, size_t);
static int base32_encode(char *, size_t *, const void *, size_t);
static int base32_handles_dots();
static int base32_blksize_raw();
static int base32_blksize_enc();

static struct encoder base32_encoder =
{
	"Base32",
	base32_encode,
	base32_decode,
	base32_handles_dots,
	base32_handles_dots,
	base32_blksize_raw,
	base32_blksize_enc
};

struct encoder
*get_base32_encoder()
{
	return &base32_encoder;
}

static int 
base32_handles_dots()
{
	return 0;
}

static int 
base32_blksize_raw()
{
	return BLKSIZE_RAW;
}

static int 
base32_blksize_enc()
{
	return BLKSIZE_ENC;
}

int
b32_5to8(int in)
{
	return cb32[in & 31];
}

int
b32_8to5(int in)
{
	int i;
	int c;
	if (!reverse_init) {
		for (i = 0; i < 32; i++) {
			c = cb32[i];
			rev32[(int) c] = i;
		}
		reverse_init = 1;
	}
	return rev32[in];
}

static int 
base32_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	size_t newsize;
	size_t maxsize;
	unsigned char *p;
	unsigned char *q;
	int i;

	memset(buf, 0, *buflen);

	/* how many chars can we encode within the buf */
	maxsize = BLKSIZE_RAW * (*buflen / BLKSIZE_ENC - 1) - 1;
	/* how big will the encoded data be */
	newsize = BLKSIZE_ENC * (size / BLKSIZE_RAW + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		size = maxsize;
	}

	p = (unsigned char *) buf;
	q = (unsigned char *)data;

	for(i=0;i<size;i+=BLKSIZE_RAW) {
		p[0] = cb32[((q[0] & 0xf8) >> 3)];
		p[1] = cb32[(((q[0] & 0x07) << 2) | ((q[1] & 0xc0) >> 6))];
		p[2] = (i+1 < size) ? cb32[((q[1] & 0x3e) >> 1)] : '\0';
		p[3] = (i+1 < size) ? cb32[((q[1] & 0x01) << 4) | ((q[2] & 0xf0) >> 4)] : '\0';
		p[4] = (i+2 < size) ? cb32[((q[2] & 0x0f) << 1) | ((q[3] & 0x80) >> 7)] : '\0';
		p[5] = (i+3 < size) ? cb32[((q[3] & 0x7c) >> 2)] : '\0';
		p[6] = (i+3 < size) ? cb32[((q[3] & 0x03) << 3) | ((q[4] & 0xe0) >> 5)] : '\0';
		p[7] = (i+4 < size) ? cb32[((q[4] & 0x1f))] : '\0';
		
		q += BLKSIZE_RAW;
		p += BLKSIZE_ENC;
	}	
	*p = 0;

	/* store number of bytes from data that was used */
	*buflen = size;

	return strlen(buf) - 1;
}

#define DECODE_ERROR 0xffffffff
#define REV32(x) rev32[(int) (x)]

static int
decode_token(const unsigned char *t, unsigned char *data, size_t len) 
{
	if (len < 2)
		return 0;

	data[0] = ((REV32(t[0]) & 0x1f) << 3) | 
			  ((REV32(t[1]) & 0x1c) >> 2);
	
	if (len < 4)
		return 1;

	data[1] = ((REV32(t[1]) & 0x03) << 6) | 
			  ((REV32(t[2]) & 0x1f) << 1) | 
			  ((REV32(t[3]) & 0x10) >> 4);

	if (len < 5)
		return 2;

	data[2] = ((REV32(t[3]) & 0x0f) << 4) |
			  ((REV32(t[4]) & 0x1e) >> 1);

	if (len < 7)
		return 3;

	data[3] = ((REV32(t[4]) & 0x01) << 7) |
			  ((REV32(t[5]) & 0x1f) << 2) |
			  ((REV32(t[6]) & 0x18) >> 3);

	if (len < 8)
		return 4;

	data[4] = ((REV32(t[6]) & 0x07) << 5) |
			  ((REV32(t[7]) & 0x1f));

	return 5;
}

static int
base32_decode(void *buf, size_t *buflen, const char *str, size_t slen)
{
	unsigned char *q;
	size_t newsize;
	size_t maxsize;
	const char *p;
	unsigned char c;
	int len;
	int i;

	if (!reverse_init) {
		for (i = 0; i < 32; i++) {
			c = cb32[i];
			rev32[(int) c] = i;
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
	for (p = str; *p && strchr(cb32, *p); p += BLKSIZE_ENC) {
		len = decode_token((unsigned char *) p, (unsigned char *) q, slen);	
		q += len;
		slen -= BLKSIZE_ENC;
		
		if (len < BLKSIZE_RAW)
			break;
	}
	*q = '\0';
	
	return q - (unsigned char *) buf;
}

