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

size_t
get_raw_length(size_t enc_bytes, struct encoder *enc, const char *topdomain)
/* Returns the maximum length of raw data that can be encoded into max_enc_bytes */
{
	size_t enc_datalen = enc_bytes - strlen(topdomain);
	/* Number of dots in length of encoded data */
	size_t dots = enc_datalen / (DNS_MAXLABEL + 1);
	if (!enc->eats_dots()) /* Dots are not included in encoded data length */
		enc_datalen -= dots;
	return enc->get_raw_length(enc_datalen);
}

size_t
get_encoded_length(size_t raw_bytes, struct encoder *enc, const char *topdomain)
/* Returns length of encoded data from original data length orig_len; */
{
	size_t dots = 1; /* dot before topdomain */
	size_t len = enc->get_encoded_length(raw_bytes) + strlen(topdomain);
	if (!enc->places_dots())
		dots += len / 63; /* number of dots needed in data */
	return len;
}

int
build_hostname(char *buf, size_t buflen, const char *data, const size_t datalen,
		const char *topdomain, struct encoder *encoder, size_t maxlen, size_t header_len)
/* Builds DNS-compatible hostname for data using specified encoder and topdomain
 * NB: Does not account for header length. Data is encoded at start of buf to
 * (buf + MIN(maxlen, buflen)). */
{
	size_t space;
	char *b;

	space = get_encoded_length(MIN(maxlen, buflen), encoder, topdomain);
	buf += header_len;
	buflen -= header_len;
	maxlen -= header_len;

	memset(buf, 0, buflen);

	encoder->encode(buf, &space, data, datalen);

	if (!encoder->places_dots())
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

int
unpack_data(char *buf, size_t buflen, char *data, size_t datalen, struct encoder *enc)
{
	if (!enc->eats_dots())
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
	dots = total / 63;

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
		if (pos % 63 == 0) {
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
