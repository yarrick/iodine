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
#include "common.h"
#include "encoding.h"

int build_hostname(char *buf, size_t buflen, const char *data,
		   const size_t datalen, const char *topdomain,
		   const struct encoder *encoder, int maxlen)
{
	size_t space;
	char *b;

	space = MIN((size_t)maxlen, buflen) - strlen(topdomain) - 8;
	/* 8 = 5 max header length + 1 dot before topdomain + 2 safety */

	if (!encoder->places_dots)
		space -= (space / 57); /* space for dots */

	memset(buf, 0, buflen);

	encoder->encode(buf, &space, data, datalen);

	if (!encoder->places_dots)
		inline_dotify(buf, buflen);

	b = buf;
	b += strlen(buf);

	/* move b back one step to see if the dot is there */
	b--;
	if (*b != '.')
		*++b = '.';
	b++;
	/* move b ahead of the string so we can copy to it */

	strncpy(b, topdomain, strlen(topdomain)+1);

	return space;
}

int unpack_data(char *buf, size_t buflen, char *data, size_t datalen,
		const struct encoder *enc)
{
	if (!enc->eats_dots)
		datalen = inline_undotify(data, datalen);
	return enc->decode(buf, &buflen, data, datalen);
}

int inline_dotify(char *buf, size_t buflen)
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

int inline_undotify(char *buf, size_t len)
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
