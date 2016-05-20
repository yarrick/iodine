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
#include "base32.h"

#define BLKSIZE_RAW 5
#define BLKSIZE_ENC 8

static const char cb32[] =
	"abcdefghijklmnopqrstuvwxyz012345";
static const char cb32_ucase[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static unsigned char rev32[256];
static int reverse_init = 0;

static size_t base32_encode(uint8_t *, size_t *, const uint8_t *, size_t);
static size_t base32_decode(uint8_t *, size_t *, const uint8_t *, size_t);
static int base32_handles_dots();
static size_t base32_blksize_raw();
static size_t base32_blksize_enc();
static size_t base32_encoded_length(size_t inputlen);
static size_t base32_raw_length(size_t inputlen);


static struct encoder base32_encoder =
{
	"Base32",
	base32_encode,
	base32_decode,
	base32_handles_dots,
	base32_handles_dots,
	base32_blksize_raw,
	base32_blksize_enc,
	base32_encoded_length,
	base32_raw_length
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

static size_t
base32_blksize_raw()
{
	return BLKSIZE_RAW;
}

static size_t
base32_blksize_enc()
{
	return BLKSIZE_ENC;
}

static size_t
base32_encoded_length(size_t inputlen)
{
	return (BLKSIZE_ENC * inputlen) / BLKSIZE_RAW + (((BLKSIZE_ENC * inputlen) % BLKSIZE_RAW) ? 1 : 0);
}

static size_t
base32_raw_length(size_t inputlen)
{
	return (BLKSIZE_RAW * inputlen) / BLKSIZE_ENC + (((BLKSIZE_RAW * inputlen) % BLKSIZE_ENC) ? 1 : 0);
}


inline static void
base32_reverse_init()
{
	int i;
	unsigned char c;

	if (!reverse_init) {
		memset (rev32, 0, 256);
		for (i = 0; i < 32; i++) {
			c = cb32[i];
			rev32[(int) c] = i;
			c = cb32_ucase[i];
			rev32[(int) c] = i;
		}
		reverse_init = 1;
	}
}

int
b32_5to8(int in)
{
	return cb32[in & 31];
}

int
b32_8to5(int in)
{
	base32_reverse_init();
	return rev32[in];
}

static size_t
base32_encode(uint8_t *buf, size_t *buflen, const uint8_t *udata, size_t size)
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
		buf[iout] = cb32[((udata[iin] & 0xf8) >> 3)];
		iout++;

		if (iout >= *buflen || iin >= size) {
			iout--; 	/* previous char is useless */
			break;
		}
		buf[iout] = cb32[((udata[iin] & 0x07) << 2) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xc0) >> 6) : 0)];
		iin++;			/* 0 complete, iin=1 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x3e) >> 1)];
		iout++;

		if (iout >= *buflen || iin >= size) {
			iout--;		/* previous char is useless */
			break;
		}
		buf[iout] = cb32[((udata[iin] & 0x01) << 4) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xf0) >> 4) : 0)];
		iin++;			/* 1 complete, iin=2 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x0f) << 1) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0x80) >> 7) : 0)];
		iin++;			/* 2 complete, iin=3 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x7c) >> 2)];
		iout++;

		if (iout >= *buflen || iin >= size) {
			iout--;		/* previous char is useless */
			break;
		}
		buf[iout] = cb32[((udata[iin] & 0x03) << 3) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xe0) >> 5) : 0)];
		iin++;			/* 3 complete, iin=4 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x1f))];
		iin++;			/* 4 complete, iin=5 */
		iout++;
	}

	buf[iout] = '\0';

	/* store number of bytes from data that was used */
	*buflen = iin;

	return iout;
}

#define REV32(x) rev32[(int) (x)]

static size_t
base32_decode(uint8_t *ubuf, size_t *buflen, const uint8_t *str, size_t slen)
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
	size_t iout = 0;	/* to-be-filled output byte */
	size_t iin = 0;	/* next input char to use in decoding */

	base32_reverse_init ();

	/* Note: Don't bother to optimize manually. GCC optimizes
	   better(!) when using simplistic array indexing. */

	while (1) {
		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV32(str[iin]) & 0x1f) << 3) |
			     ((REV32(str[iin + 1]) & 0x1c) >> 2);
		iin++;  		/* 0 used up, iin=1 */
		iout++;

		if (iout >= *buflen || iin + 2 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0' ||
		    str[iin + 2] == '\0')
			break;
		ubuf[iout] = ((REV32(str[iin]) & 0x03) << 6) |
			     ((REV32(str[iin + 1]) & 0x1f) << 1) |
			     ((REV32(str[iin + 2]) & 0x10) >> 4);
		iin += 2;  		/* 1,2 used up, iin=3 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV32(str[iin]) & 0x0f) << 4) |
			     ((REV32(str[iin + 1]) & 0x1e) >> 1);
		iin++;  		/* 3 used up, iin=4 */
		iout++;

		if (iout >= *buflen || iin + 2 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0' ||
		    str[iin + 2] == '\0')
			break;
		ubuf[iout] = ((REV32(str[iin]) & 0x01) << 7) |
			     ((REV32(str[iin + 1]) & 0x1f) << 2) |
			     ((REV32(str[iin + 2]) & 0x18) >> 3);
		iin += 2;  		/* 4,5 used up, iin=6 */
		iout++;

		if (iout >= *buflen || iin + 1 >= slen ||
		    str[iin] == '\0' || str[iin + 1] == '\0')
			break;
		ubuf[iout] = ((REV32(str[iin]) & 0x07) << 5) |
			     ((REV32(str[iin + 1]) & 0x1f));
		iin += 2;  		/* 6,7 used up, iin=8 */
		iout++;
	}

	ubuf[iout] = '\0';

	return iout;
}
