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

#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "common.h"
#include "compat.h"
#include "dns.h"
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
	.switch_bits = 0,
};

static const struct encoder *const encoders[] = {
	&base32_ops,
	&base64_ops,
	&base64u_ops,
	&base128_ops,
	&raw_ops,
	NULL,
};

const struct encoder *
get_encoder_by_name(const char *name)
{
	const struct encoder *const *enc;

	if (!name)
		return NULL;

	for (enc = encoders; *enc != NULL; enc++) {
		if (strcasecmp(name, (*enc)->name) == 0)
			return *enc;
	}
	return NULL;
}

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

const struct encoder *
get_encoder_by_switch_bits(int bits)
{
	const struct encoder *const *enc;

	if (bits == 0)
		return NULL;

	for (enc = encoders; *enc != NULL; enc++) {
		if ((*enc)->switch_bits == bits)
			return *enc;
	}
	return NULL;
}

int
encoder_valid_for_qtype(const struct encoder *enc, unsigned short qtype)
{
	if (!enc)
		return 0;
	switch (qtype) {
	case T_TXT:
		return 1;
	case T_CNAME:
	case T_A:
	case T_MX:
	case T_SRV:
		return enc->host_char != '\0';
	case T_NULL:
	case T_PRIVATE:
		return enc == &raw_ops;
	default:
		return 0;
	}
}

static int
unwrap_hostname(char *outdata, size_t outdatalen, char *buf, size_t buflen)
/* Decodes *buf to *outdata.
 * *buf WILL be changed by undotify.
 * Note: buflen must be _exactly_ strlen(buf) before undotifying.
 * (undotify of reduced-len won't copy \0, base-X decode will decode too much.)
 * Returns #bytes usefully filled in outdata.
 */
{
	const struct encoder *enc;

	if (outdatalen <= 0 || buflen < 1)
		return 0;

	enc = get_encoder_by_host_char(buf[0]);
	if (!enc) {
		warnx("Received unsupported hostname encoding");
		return 0;
	}

	/* Need 1 byte for codec, 3 bytes ".xy", >=1 byte data */
	if (buflen < 5)
		return 0;

	/* this also does undotify */
	return unpack_data(outdata, outdatalen, buf + 1, buflen - 4, enc);
}

int
payload_unwrap(char *buf, size_t buflen, unsigned short rtype)
{
	char data[64*1024];
	size_t rv = 0;

	/* CNAME can also be returned from an A question */
	if (rtype == T_CNAME) {
		/*
		 * buf is a hostname or txt stream that we still need to
		 * decode to binary
		 *
		 * also update rv with the number of valid bytes
		 *
		 * data is unused here, and will certainly hold the smaller binary
		 */
		rv = unwrap_hostname(data, sizeof(data), buf, buflen);
	} else if (rtype == T_TXT) {
		const struct encoder *enc;
		size_t datalen = sizeof(data) - 1;

		if (buflen < 2)
			return 0;

		/* TXT uses down char to signal codec */
		enc = get_encoder_by_down_char(buf[0]);
		if (!enc) {
			warnx("Received unsupported encoding in TXT");
			return 0;
		}
		rv = enc->decode(data, &datalen, buf + 1, buflen - 1);
	} else if (rtype == T_MX || rtype == T_SRV) {
		/* buf is like "Hname.com\0Hanother.com\0\0" */
		int buftotal = buflen;	/* idx of last \0 */
		int bufoffset = 0;
		int dataoffset = 0;
		int thispartlen, dataspace, datanew;

		while (1) {
			thispartlen = strlen(buf + bufoffset);
			thispartlen = MIN(thispartlen, buftotal-bufoffset);
			dataspace = sizeof(data) - dataoffset;
			if (thispartlen <= 0 || dataspace <= 0)
				break;

			datanew = unwrap_hostname(data + dataoffset, dataspace,
						  buf + bufoffset, thispartlen);
			if (datanew <= 0)
				break;

			bufoffset += thispartlen + 1;
			dataoffset += datanew;
		}
		rv = dataoffset;
	}
	rv = MIN(rv, buflen);
	if (rv > 0)
		memcpy(buf, data, rv);
	return rv;
}

static size_t
wrap_hostname(char *buf, size_t buflen, const char *data, size_t datalen,
	      const struct encoder *downenc)
/* Returns #bytes of data that were encoded */
{
	static int td1 = 0;
	static int td2 = 0;
	size_t space;
	char *b;

	/* Make a rotating topdomain to prevent filtering */
	td1 = (td1 + 3) % 26;
	td2 = (td2 + 7) % 25;

	/* encode data,datalen to CNAME/MX answer
	   (adapted from build_hostname() in encoding.c)
	 */

	/* Avoid using raw codec */
	if (!downenc || !downenc->host_char)
		downenc = &base32_ops;

	if (buflen <= 7)
		return 0;

	space = MIN(0xFF, buflen) - 4 - 2;
	/* -1 encoding type, -3 ".xy", -2 for safety */

	memset(buf, 0, buflen);
	space -= (space / 57);	/* space for dots */

	buf[0] = downenc->host_char;
	downenc->encode(buf+1, &space, data, datalen);
	inline_dotify(buf, buflen);

	/* Add dot (if it wasn't there already) and topdomain */
	b = buf;
	b += strlen(buf) - 1;
	if (*b != '.')
		*++b = '.';
	b++;

	*b = 'a' + td1;
	b++;
	*b = 'a' + td2;
	b++;
	*b = '\0';

	return space;
}

int
payload_wrap(char *buf, size_t buflen, const char *data, size_t *datalen,
	     unsigned short qtype, const struct encoder *downenc)
{
	if (qtype == T_CNAME || qtype == T_A) {
		if (buflen <= 7) {
			*datalen = 0;
			return 0;
		}
		*datalen = wrap_hostname(buf, buflen, data, *datalen, downenc);
		return strlen(buf);
	} else if (qtype == T_MX || qtype == T_SRV) {
		char *b = buf;
		size_t offset = 0;
		size_t res;

		if (buflen <= 7) {
			*datalen = 0;
			return 0;
		}

		while (1) {
			res = wrap_hostname(b, buflen - (b - buf),
					    data + offset,
					    *datalen - offset, downenc);
			if (res < 1) {
				/* nothing encoded */
				if (offset == 0) {
					*datalen = 0;
					return 0;
				}
				break;
			}

			b = b + strlen(b) + 1;

			offset += res;
			if (offset >= *datalen)
				break;
		}

		/* Add final \0 */
		*b = '\0';
		*datalen = offset;
		return b - buf;
	} else if (qtype == T_TXT) {
		int len;
		size_t space;

		if (buflen < 2) {
			*datalen = 0;
			return 0;
		}
		/* TXT with codec prefix */
		space = buflen - 2;
		memset(buf, 0, buflen);
		buf[0] = downenc->down_char;
		len = 1 + downenc->encode(buf+1, &space, data, *datalen);
		*datalen = space;
		return len;
	}
	*datalen = 0;
	return 0;
}
