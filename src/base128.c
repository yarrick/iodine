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

#define BASE128_BLKSIZE_RAW 7
#define BASE128_BLKSIZE_ENC 8

/* Don't use '-' (restricted to middle of labels), prefer iso_8859-1
 * accent chars since they might readily be entered in normal use,
 * don't use 254-255 because of possible function overloading in DNS systems.
 */
static const unsigned char cb128[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	"\274\275\276\277"
	"\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317"
	"\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337"
	"\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357"
	"\360\361\362\363\364\365\366\367\370\371\372\373\374\375";
static unsigned char rev128[256];
static int reverse_init = 0;

inline static void base128_reverse_init(void)
{
	int i;
	unsigned char c;

	if (!reverse_init) {
		memset(rev128, 0, 256);
		for (i = 0; i < 128; i++) {
			c = cb128[i];
			rev128[(int) c] = i;
		}
		reverse_init = 1;
	}
}

/*
 * Fills *buf with max. *buflen characters, encoding size bytes of *data.
 *
 * NOTE: *buf space should be at least 1 byte _more_ than *buflen
 * to hold the trailing '\0'.
 *
 * return value    : #bytes filled in buf   (excluding \0)
 * sets *buflen to : #bytes encoded from data
 */
static int base128_encode(char *buf, size_t *buflen, const void *data,
			  size_t size)
{
	unsigned char *ubuf = (unsigned char *) buf;
	unsigned char *udata = (unsigned char *) data;
	int iout = 0;	/* to-be-filled output char */
	int iin = 0;	/* one more than last input byte that can be
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
static int base128_decode(void *buf, size_t *buflen, const char *str,
			  size_t slen)
{
	unsigned char *ustr = (unsigned char *) str;
	unsigned char *ubuf = (unsigned char *) buf;
	int iout = 0;	/* to-be-filled output byte */
	int iin = 0;	/* next input char to use in decoding */

	base128_reverse_init();

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x7f) << 1) |
			     ((REV128(ustr[iin + 1]) & 0x40) >> 6);
		iin++;  		/* 0 used up, iin=1 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x3f) << 2) |
			     ((REV128(ustr[iin + 1]) & 0x60) >> 5);
		iin++;  		/* 1 used up, iin=2 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x1f) << 3) |
			     ((REV128(ustr[iin + 1]) & 0x70) >> 4);
		iin++;  		/* 2 used up, iin=3 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x0f) << 4) |
			     ((REV128(ustr[iin + 1]) & 0x78) >> 3);
		iin++;  		/* 3 used up, iin=4 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x07) << 5) |
			     ((REV128(ustr[iin + 1]) & 0x7c) >> 2);
		iin++;  		/* 4 used up, iin=5 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x03) << 6) |
			     ((REV128(ustr[iin + 1]) & 0x7e) >> 1);
		iin++;  		/* 5 used up, iin=6 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV128(ustr[iin]) & 0x01) << 7) |
			     ((REV128(ustr[iin + 1]) & 0x7f));
		iin += 2;  		/* 6,7 used up, iin=8 */
		iout++;
	}

	ubuf[iout] = '\0';

	return iout;
}

const struct encoder base128_ops = {
	.name = "Base128",

	.encode = base128_encode,
	.decode = base128_decode,

	.places_dots = false,
	.eats_dots = false,

	.blocksize_raw = BASE128_BLKSIZE_RAW,
	.blocksize_encoded = BASE128_BLKSIZE_ENC,
};
