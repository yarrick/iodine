/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 * Mostly rewritten 2009 J.A.Bezemer@opensourcepartners.nl
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"

#define BASE64_BLKSIZE_RAW 3
#define BASE64_BLKSIZE_ENC 4

/* Note: the "unofficial" char is last here, which means that the \377 pattern
   in DOWNCODECCHECK1 ('Y' request) will properly test it. */
static const char cb64[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+";
static unsigned char rev64[256];
static int reverse_init = 0;

inline static void base64_reverse_init(void)
{
	int i;
	unsigned char c;

	if (!reverse_init) {
		memset(rev64, 0, 256);
		for (i = 0; i < 64; i++) {
			c = cb64[i];
			rev64[(int) c] = i;
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
static int base64_encode(char *buf, size_t *buflen, const void *data,
			 size_t size)
{
	unsigned char *udata = (unsigned char *) data;
	int iout = 0;	/* to-be-filled output char */
	int iin = 0;	/* one more than last input byte that can be
			   successfully decoded */

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb64[((udata[iin] & 0xfc) >> 2)];
		iout++;

		if (iout >= *buflen || iin >= size) {
			iout--;		/* previous char is useless */
			break;
		}
		buf[iout] = cb64[((udata[iin] & 0x03) << 4) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xf0) >> 4) : 0)];
		iin++;			/* 0 complete, iin=1 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb64[((udata[iin] & 0x0f) << 2) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xc0) >> 6) : 0)];
		iin++;			/* 1 complete, iin=2 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb64[(udata[iin] & 0x3f)];
		iin++;			/* 2 complete, iin=3 */
		iout++;
	}

	buf[iout] = '\0';

	/* store number of bytes from data that was used */
	*buflen = iin;

	return iout;
}

#define REV64(x) rev64[(int) (x)]

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
static int base64_decode(void *buf, size_t *buflen, const char *str,
			 size_t slen)
{
	unsigned char *ubuf = (unsigned char *) buf;
	int iout = 0;	/* to-be-filled output byte */
	int iin = 0;	/* next input char to use in decoding */

	base64_reverse_init();

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV64(str[iin]) & 0x3f) << 2) |
			     ((REV64(str[iin + 1]) & 0x30) >> 4);
		iin++;  		/* 0 used up, iin=1 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV64(str[iin]) & 0x0f) << 4) |
			     ((REV64(str[iin + 1]) & 0x3c) >> 2);
		iin++;  		/* 1 used up, iin=2 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV64(str[iin]) & 0x03) << 6) |
			     (REV64(str[iin + 1]) & 0x3f);
		iin += 2;  		/* 2,3 used up, iin=4 */
		iout++;
	}

	ubuf[iout] = '\0';

	return iout;
}

const struct encoder base64_ops = {
	.name = "Base64",

	.encode = base64_encode,
	.decode = base64_decode,

	.places_dots = false,
	.eats_dots = false,

	.blocksize_raw = BASE64_BLKSIZE_RAW,
	.blocksize_encoded = BASE64_BLKSIZE_ENC,
};
