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
get_raw_length_from_dns(size_t enc_bytes, struct encoder *enc, const char *topdomain)
/* Returns the maximum length of raw data that can be encoded into enc_bytes */
{
	/* 2 byte for something - seems necessary */
	size_t enc_datalen = enc_bytes - strlen(topdomain) - 2;
	/* Number of dots in length of encoded data */
	size_t dots = 1;
	if (!enc->eats_dots()) /* Dots are not included in encoded data length */
		 dots += enc_datalen / (DNS_MAXLABEL);
	enc_datalen -= dots;
	return enc->get_raw_length(enc_datalen);
}

size_t
get_encoded_dns_length(size_t raw_bytes, struct encoder *enc, const char *topdomain)
/* Returns length of encoded data from original data length orig_len; */
{
	size_t dots = 1; /* dot before topdomain */
	size_t len = enc->get_encoded_length(raw_bytes);
	if (!enc->places_dots())
		dots += len / DNS_MAXLABEL; /* number of dots needed in data */
	return len + dots + strlen(topdomain);
}

size_t
build_hostname(uint8_t *buf, size_t buflen, const uint8_t *data, const size_t datalen,
		const char *topdomain, struct encoder *encoder, size_t maxlen, size_t header_len)
/* Builds DNS-compatible hostname for data using specified encoder and topdomain
 * Encoded data is placed into buf. */
{
	size_t space, enc;
	uint8_t *b;

	buflen -= header_len;
	buf += header_len;
	maxlen -= header_len;
	memset(buf, 0, buflen);

	maxlen = MIN(maxlen, buflen);

	/* 1 byte for dot before topdomain + 1 byte extra for something */
	space = maxlen - strlen(topdomain) - (maxlen / DNS_MAXLABEL) - 2;

	enc = encoder->encode(buf, &space, data, datalen);
//	warnx("build_hostname: enc %lu, predicted %lu; maxlen %lu, header %lu, datalen %lu, space %lu",
//		  encdata_len, encoder->get_encoded_length(datalen), maxlen, header_len, datalen, space);

	if (!encoder->places_dots())
		enc = inline_dotify(buf - header_len, buflen + header_len) - header_len;

	b = buf + enc;

	/* move b back one step to see if the dot is there */
	b--;
	if (*b != '.')
		*++b = '.';
	b++;
	/* move b ahead of the string so we can copy to it */

	strncpy((char *)b, topdomain, strlen(topdomain)+1);
//	warnx("build_hostname: host '%s' (sl %lu, actual %lu), topdomain '%s'",
//			buf - header_len, strlen(buf - header_len), encdata_len + header_len + strlen(topdomain)+1, b);

	return space;
}

size_t
unpack_data(uint8_t *buf, size_t buflen, uint8_t *data, size_t datalen, struct encoder *enc)
{
	if (!enc->eats_dots())
		datalen = inline_undotify(data, datalen);
	return enc->decode(buf, &buflen, data, datalen);
}

size_t
inline_dotify(uint8_t *buf, size_t buflen)
{
	unsigned dots;
	size_t pos, total;
	uint8_t *reader, *writer;

	total = strlen((char *)buf);
	dots = total / DNS_MAXLABEL;

	writer = buf;
	writer += total;
	writer += dots;

	total += dots;
	if (strlen((char *)buf) + dots > buflen) {
		writer = buf;
		writer += buflen;
		total = buflen;
	}

	reader = writer - dots;
	pos = (reader - buf) + 1;

	while (dots) {
		*writer-- = *reader--;
		pos--;
		if (pos % DNS_MAXLABEL == 0) {
			*writer-- = '.';
			dots--;
		}
	}

	/* return new length of string */
	return total;
}

size_t
inline_undotify(uint8_t *buf, size_t len)
{
	size_t pos;
	unsigned dots;
	uint8_t *reader, *writer;

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
