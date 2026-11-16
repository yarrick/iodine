/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
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

#include <string.h>
#include "config.h"
#include "common.h"
#include "compat.h"
#include "encoding.h"

size_t
hostname_need(const char *topdomain)
{
	/* 8 = 5 max header length + 1 dot before topdomain + 2 safety */
	return strlen(topdomain) + 8;
}

int
build_hostname(char *buf, size_t buflen, const char *data,
	       const size_t datalen, const char *topdomain,
	       const struct encoder *encoder, int maxlen)
{
	size_t space;
	char *b;
	size_t need;
	size_t cap;
	size_t remain;

	need = hostname_need(topdomain);
	cap = MIN((size_t)maxlen, buflen);
	if (cap < need) {
		/* The topdomain plus the fixed overhead do not fit into
		   the maximum hostname length. Without this check the
		   subtraction below underflows (size_t) and the encoder
		   gets an output limit of ~2^64 bytes, writing past the
		   end of buf. Clamp to 0: no payload fits, emit just the
		   topdomain (the client refuses such a configuration at
		   startup anyway - see iodine.c). */
		space = 0;
	} else {
		space = cap - need;
	}

	space -= (space / 57); /* space for dots */

	memset(buf, 0, buflen);

	encoder->encode(buf, &space, data, datalen);

	inline_dotify(buf, buflen);

	b = buf + strlen(buf);

	if (b > buf) {
		/* move b back one step to see if the dot is there */
		b--;
		if (*b != '.')
			*++b = '.';
		/* move b ahead of the string so we can copy to it */
		b++;
	} else {
		/* No encoded data fit; use the buffer start so the
		   topdomain does not get an empty label in front. */
		b = buf;
	}

	remain = buflen - (b - buf);
	strlcpy(b, topdomain, remain);

	return space;
}

int
unpack_data(char *buf, size_t buflen, char *data, size_t datalen,
	    const struct encoder *enc)
{
	if (buflen == 0)
		return 0;
	buflen--;
	datalen = inline_undotify(data, datalen);
	return enc->decode(buf, &buflen, data, datalen);
}

int
inline_dotify(char *buf, size_t buflen)
{
	unsigned dots;
	unsigned pos;
	unsigned total;
	char *reader, *writer;

	total = strlen(buf);
	dots = total / 57;

	writer = buf;
	writer += total;
	writer += dots;

	total += dots;
	if (strlen(buf) + dots > buflen) {
		writer = buf;
		writer += buflen;
		total = buflen;
	}

	reader = writer - dots;
	pos = (unsigned) (reader - buf) + 1;

	while (dots) {
		*writer-- = *reader--;
		pos--;
		if (pos % 57 == 0) {
			*writer-- = '.';
			dots--;
		}
	}

	/* return new length of string */
	return total;
}

int
inline_undotify(char *buf, size_t len)
{
	unsigned pos;
	unsigned dots;
	char *reader, *writer;

	writer = buf;
	reader = writer;

	pos = 0;
	dots = 0;

	while (pos < len) {
		if (*reader == '.') {
			reader++;
			pos++;
			dots++;
			continue;
		}
		*writer++ = *reader++;
		pos++;
	}

	/* return new length of string */
	return len - dots;
}

static unsigned int
raw_encode(char *dst, size_t *dstlen, const void *src, size_t srclen)
{
	size_t len = MIN(*dstlen, srclen);

	memcpy(dst, src, len);
	dst[len] = '\0';
	*dstlen = len;
	return len;
}

static unsigned int
raw_decode(void *dst, size_t *dstlen, const char *src, size_t srclen)
{
	size_t len = MIN(*dstlen, srclen);

	memcpy(dst, src, len);
	((char *)dst)[len] = '\0';
	return len;
}

const struct encoder raw_ops = {
	.name = "Raw",

	.encode = raw_encode,
	.decode = raw_decode,

	.blocksize_raw = 1,
	.blocksize_encoded = 1,
	.host_char = '\0',
	.down_char = 'r',
};

const struct encoder *const encoders[] = {
	&base32_ops,
	&base64_ops,
	&base64u_ops,
	&base128_ops,
	&raw_ops,
	NULL,
};

const struct encoder *
get_encoder_by_host_char(char c)
{
	const struct encoder *const *enc;

	c = ascii_tolower((unsigned char)c);
	if (c == '\0')
		return NULL;

	for (enc = encoders; *enc != NULL; enc++) {
		if ((*enc)->host_char == c)
			return *enc;
	}
	return NULL;
}

const struct encoder *
get_encoder_by_down_char(char c)
{
	const struct encoder *const *enc;

	c = ascii_tolower((unsigned char)c);
	if (c == '\0')
		return NULL;

	for (enc = encoders; *enc != NULL; enc++) {
		if ((*enc)->down_char == c)
			return *enc;
	}
	return NULL;
}
