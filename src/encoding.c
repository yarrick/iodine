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

#include <stdio.h>
#include <strings.h>
#include <string.h>

/* For FreeBSD */
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define SPACING 63
#define ENC_CHUNK 8
#define RAW_CHUNK 5

static const char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ98765-";
static const char padder[] = " 1234";
static char reverse32[128];
static int reverse_init = 0;

/* Eat 5 bytes from src, write 8 bytes to dest */
static void
encode_chunk(char *dest, const char *src)
{
	unsigned char c;

	*dest++ = base32[(*src & 0xF8) >> 3];	/* 1111 1000 first byte */

	c = (*src++ & 0x07) << 2;		/* 0000 0111 first byte */
	c |=  ((*src & 0xC0) >> 6);		/* 1100 0000 second byte */
	*dest++ = base32[(int) c];

	*dest++ = base32[(*src & 0x3E) >> 1];	/* 0011 1110 second byte */

	c = (*src++ & 0x01) << 4;		/* 0000 0001 second byte */
	c |=  ((*src & 0xF0) >> 4);		/* 1111 0000 third byte */
	*dest++ = base32[(int) c];
	
	c = (*src++ & 0x0F) << 1;		/* 0000 1111 third byte */
	c |=  ((*src & 0x80) >> 7);		/* 1000 0000 fourth byte */
	*dest++ = base32[(int) c];
	
	*dest++ = base32[(*src & 0x7C) >> 2];	/* 0111 1100 fourth byte */

	c = (*src++ & 0x03) << 3;		/* 0000 0011 fourth byte */
	c |=  ((*src & 0xE0) >> 5);		/* 1110 0000 fifth byte */
	*dest++ = base32[(int) c];

	*dest++ = base32[*src++ & 0x1F];	/* 0001 1111 fifth byte */
}

/* Eat 8 bytes from src, write 5 bytes to dest */
static void
decode_chunk(char *dest, char *src)
{
	unsigned char c;
	int i;

	if (!reverse_init) {
		for (i = 0; i < 32; i++) {
			c = base32[i];
			reverse32[(int) c] = i;
		}
		reverse_init = 1;
	}

	c = reverse32[(int) *src++] << 3;		/* Take bits 11111 from byte 1 */
	c |= (reverse32[(int) *src] & 0x1C) >> 2;	/* Take bits 11100 from byte 2 */
	*dest++ = c;
	
	c = (reverse32[(int) *src++] & 0x3) << 6;	/* Take bits 00011 from byte 2 */
	c |= reverse32[(int) *src++] << 1;		/* Take bits 11111 from byte 3 */
	c |= (reverse32[(int) *src] & 0x10) >> 4;	/* Take bits 10000 from byte 4 */
	*dest++ = c;
	
	c = (reverse32[(int) *src++] & 0xF) << 4;	/* Take bits 01111 from byte 4 */
	c |= (reverse32[(int) *src] & 0x1E) >> 1;	/* Take bits 11110 from byte 5 */
	*dest++ = c;
	
	c = reverse32[(int) *src++] << 7;		/* Take bits 00001 from byte 5 */
	c |= reverse32[(int) *src++] << 2;		/* Take bits 11111 from byte 6 */
	c |= (reverse32[(int) *src] & 0x18) >> 3;	/* Take bits 11000 from byte 7 */
	*dest++ = c;
	
	c = (reverse32[(int) *src++] & 0x7) << 5;	/* Take bits 00111 from byte 7 */
	c |= reverse32[(int) *src++];			/* Take bits 11111 from byte 8 */
	*dest++ = c;
}

int
encode_data(const char *buf, const size_t len, int space, char *dest)
{
	int final;
	int write;
	int realwrite;
	int chunks;
	int leftovers;
	int i;
	char encoded[255];
	char padding[5];
	const char *dp;
	char *pp;
	char *ep;

	space -= space / SPACING;
	chunks = (space - 1) / ENC_CHUNK;
	while ((chunks + 1) * ENC_CHUNK + 1 > space) {
		chunks--;
	}
	write = RAW_CHUNK * chunks;
	write = MIN(write, len); /* do not use more bytes than is available; */
	final = (write == len);	/* is this the last block? */
	chunks = write / RAW_CHUNK;
	leftovers = write % RAW_CHUNK;

	memset(encoded, 0, sizeof(encoded));
	ep = encoded;
	dp = buf;
	for (i = 0; i < chunks; i++) {
		encode_chunk(ep, dp);
		ep += ENC_CHUNK;
		dp += RAW_CHUNK;
	}
	realwrite = ENC_CHUNK * chunks;
	memset(padding, 0, sizeof(padding));
	pp = padding;
	if (leftovers) {
		pp += RAW_CHUNK - leftovers;
		memcpy(pp, dp, leftovers);

		pp = padding;
		*ep++ = padder[leftovers];
		encode_chunk(ep, pp);
		
		realwrite += ENC_CHUNK + 1;	/* plus padding character */
	}
	ep = encoded;
	if (len > 0) {
		for (i = 1; i <= realwrite; i++) {
			if (i % SPACING == 0) {
				*dest++ = '.';
			}
			*dest++ = *ep++;
		}
	}
	
	return write;
}

int
decode_data(char *dest, int size, const char *src, char *srcend)
{
	int len;
	int i;
	int chunks;
	int padded;
	char encoded[255];
	char padding[5];
	int enclen;
	char *pp;
	char *ep;

	memset(encoded, 0, sizeof(encoded));
	memset(dest, 0, size);

	/* First byte is not encoded */
	*dest++ = *src++;
	len = 1;

	ep = encoded;
	enclen = 0;
	while(enclen < sizeof(encoded) && src < srcend) {
		if(*src == '.') {
			src++;
			continue;
		}

		*ep++ = *src++;
		enclen++;
	}
	chunks = enclen / 8;
	padded = enclen % 8;

	ep = encoded;
	for (i = 0; i < chunks-1; i++) {
		decode_chunk(dest, ep);
		dest += RAW_CHUNK;
		ep += ENC_CHUNK;
		len += RAW_CHUNK;
	}
	/* Read last chunk */
	if (padded) {
		pp = padding;
		padded = *ep++ - '0';
		decode_chunk(pp, ep);
		pp += RAW_CHUNK - padded;
		memcpy(dest, pp, padded);
		len += padded;
	} else {
		decode_chunk(dest, ep);
		len += RAW_CHUNK;
	}

	return len;
}

