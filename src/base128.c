/*
 * Copyright (C) 2009 J.A.Bezemer@opensourcepartners.nl
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

/*
 * raw	76543210 76543210 76543210 76543210 76543210 76543210 76543210
 * enc	65432106 54321065 43210654 32106543 21065432 10654321 06543210
 *	^      ^       ^       ^       ^       ^       ^       ^
 *
 *	0001 1  0001 1
 *	0011 3  0011 3
 *	0111 7  0111 7
 *	1111 f  0110 6
 *	1110 e  0100 4
 *	1100 c
 *	1000 8
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "base128.h"

#define BLKSIZE_RAW 7
#define BLKSIZE_ENC 8

/* Don't use '-' (restricted to middle of labels), prefer iso_8859-1
 * accent chars since they might readily be entered in normal use,
 * don't use 254-255 because of possible function overloading in DNS systems.
 */
static const uint8_t cb128[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	"\274\275\276\277"
	"\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317"
	"\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337"
	"\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357"
	"\360\361\362\363\364\365\366\367\370\371\372\373\374\375";
static uint8_t rev128[256];
static int reverse_init = 0;

static size_t base128_encode(uint8_t *, size_t *, const uint8_t *, size_t);
static size_t base128_decode(uint8_t *, size_t *, const uint8_t *, size_t);
static int base128_handles_dots();
static size_t base128_blksize_raw();
static size_t base128_blksize_enc();
static size_t base128_encoded_length(size_t inputlen);
static size_t base128_raw_length(size_t inputlen);

static struct encoder base128_encoder =
{
	"Base128",
	base128_encode,
	base128_decode,
	base128_handles_dots,
	base128_handles_dots,
	base128_blksize_raw,
	base128_blksize_enc,
	base128_encoded_length,
	base128_raw_length
};

struct encoder
*get_base128_encoder()
{
	return &base128_encoder;
}

static int
base128_handles_dots()
{
	return 0;
}

static size_t
base128_blksize_raw()
{
	return BLKSIZE_RAW;
}

static size_t
base128_blksize_enc()
{
	return BLKSIZE_ENC;
}

static size_t
base128_encoded_length(size_t inputlen)
{
	return (BLKSIZE_ENC * inputlen) / BLKSIZE_RAW + (((BLKSIZE_ENC * inputlen) % BLKSIZE_RAW) ? 1 : 0);
}

static size_t
base128_raw_length(size_t inputlen)
{
	return (BLKSIZE_RAW * inputlen) / BLKSIZE_ENC + (((BLKSIZE_RAW * inputlen) % BLKSIZE_ENC) ? 1 : 0);
}

inline static void
base128_reverse_init()
{
	int i;
	unsigned char c;

	if (!reverse_init) {
		memset (rev128, 0, 256);
		for (i = 0; i < 128; i++) {
			c = cb128[i];
			rev128[(int) c] = i;
		}
		reverse_init = 1;
	}
}

static size_t
base128_encode(uint8_t *ubuf, size_t *buflen, const uint8_t *udata, size_t size)
/*
 * Fills *buf with max. *buflen characters, encoding size bytes of *data.
 *
 * NOTE: *buf space should be at least 1 byte _more_ than *buflen
 * to hold the trailing '\0'.
 *
 * return value    : #bytes filled in buf   (excluding \0)
 * sets *buflen to : #bytes encoded from data
 */
{
	size_t iout = 0;	/* to-be-filled output char */
	size_t iin = 0;	/* one more than last input byte that can be
			   successfully decoded */

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0xfe) >> 1)];
		iout++;

		if (iout >= *buflen || iin >= size) {
			iout--; 	/* previous char is useless */
			break;
		}
		ubuf[iout] = cb128[((udata[iin] & 0x01) << 6) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0xfc) >> 2) : 0)];
		iin++;			/* 0 complete, iin=1 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0x03) << 5) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0xf8) >> 3) : 0)];
		iin++;			/* 1 complete, iin=2 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0x07) << 4) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0xf0) >> 4) : 0)];
		iin++;			/* 2 complete, iin=3 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0x0f) << 3) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0xe0) >> 5) : 0)];
		iin++;			/* 3 complete, iin=4 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0x1f) << 2) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0xc0) >> 6) : 0)];
		iin++;			/* 4 complete, iin=5 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[((udata[iin] & 0x3f) << 1) |
				   ((iin + 1 < size) ?
				    ((udata[iin + 1] & 0x80) >> 7) : 0)];
		iin++;			/* 5 complete, iin=6 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		ubuf[iout] = cb128[(udata[iin] & 0x7f)];
		iin++;			/* 6 complete, iin=7 */
		iout++;
	}

	ubuf[iout] = '\0';

	/* store number of bytes from data that was used */
	*buflen = iin;

	return iout;
}

#define REV128(x) rev128[(int) (x)]

static size_t
base128_decode(uint8_t *buf, size_t *buflen, const uint8_t *str, size_t slen)
/*
 * Fills *buf with max. *buflen bytes, decoded from slen chars in *str.
 * Decoding stops early when *str contains \0.
 * Illegal encoded chars are assumed to decode to zero.
 *
 * NOTE: *buf space should be at least 1 byte _more_ than *buflen
 * to hold a trailing '\0' that is added (though *buf will usually
 * contain full-binary data).
 *
 * return value    : #bytes filled in buf   (excluding \0)
 */
{
	int iout = 0;	/* to-be-filled output byte */
	int iin = 0;	/* next input char to use in decoding */

	base128_reverse_init ();

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x7f) << 1) |
			     ((REV128(str[iin + 1]) & 0x40) >> 6);
		iin++;  		/* 0 used up, iin=1 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x3f) << 2) |
			     ((REV128(str[iin + 1]) & 0x60) >> 5);
		iin++;  		/* 1 used up, iin=2 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x1f) << 3) |
			     ((REV128(str[iin + 1]) & 0x70) >> 4);
		iin++;  		/* 2 used up, iin=3 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x0f) << 4) |
			     ((REV128(str[iin + 1]) & 0x78) >> 3);
		iin++;  		/* 3 used up, iin=4 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x07) << 5) |
			     ((REV128(str[iin + 1]) & 0x7c) >> 2);
		iin++;  		/* 4 used up, iin=5 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x03) << 6) |
			     ((REV128(str[iin + 1]) & 0x7e) >> 1);
		iin++;  		/* 5 used up, iin=6 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		buf[iout] = ((REV128(str[iin]) & 0x01) << 7) |
			     ((REV128(str[iin + 1]) & 0x7f));
		iin += 2;  		/* 6,7 used up, iin=8 */
		iout++;
	}

	buf[iout] = '\0';

	return iout;
}
