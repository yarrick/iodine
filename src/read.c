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
#include <stdint.h>
#include <stdlib.h>

#include "read.h"

static int
readname_loop(char *packet, int packetlen, char **src, char *dst, size_t length, size_t loop)
{
	char *dummy;
	char *s;
	char *d;
	int len;
	int offset;
	char c;

	if (loop <= 0)
		return 0;

	len = 0;
	s = *src;
	d = dst;
	while(*s && len < length - 2) {
		c = *s++;

		/* is this a compressed label? */
		if ((c & 0xc0) == 0xc0) {
			offset = (((s[-1] & 0x3f) << 8) | (s[0] & 0xff));
			if (offset > packetlen) {
				if (len == 0) {
					/* Bad jump first in packet */
					return 0;
				} else {
					/* Bad jump after some data */
					break;
				}
			}
			dummy = packet + offset;
			len += readname_loop(packet, packetlen, &dummy, d, length - len, loop - 1);
			goto end;
		}

		while(c && len < length - 1) {
			*d++ = *s++;
			len++;

			c--;
		}

		if (len >= length - 1) {
			break; /* We used up all space */
		}

		if (*s != 0) {
			*d++ = '.';
			len++;
		}
	}
	dst[len++] = '\0';

end:
	(*src) = s+1;
	return len;
}

int
readname(char *packet, int packetlen, char **src, char *dst, size_t length)
{
	return readname_loop(packet, packetlen, src, dst, length, 10);
}

int
readshort(char *packet, char **src, unsigned short *dst)
{
	unsigned char *p;

	p = (unsigned char *) *src;
	*dst = (p[0] << 8) | p[1];

	(*src) += sizeof(unsigned short);
	return sizeof(unsigned short);
}

int
readlong(char *packet, char **src, uint32_t *dst)
{
	/* A long as described in dns protocol is always 32 bits */
	unsigned char *p;

	p = (unsigned char *) *src;

	*dst = ((uint32_t)p[0] << 24)
		 | ((uint32_t)p[1] << 16)
		 | ((uint32_t)p[2] << 8)
		 | ((uint32_t)p[3]);

	(*src) += sizeof(uint32_t);
	return sizeof(uint32_t);
}

int
readdata(char *packet, char **src, char *dst, size_t len)
{
	memcpy(dst, *src, len);

	(*src) += len;

	return len;
}

int
readtxtbin(char *packet, char **src, size_t srcremain, char *dst, size_t dstremain)
{
	unsigned char *uc;
	int tocopy;
	int dstused = 0;

	while (srcremain > 0)
	{
		uc = (unsigned char*) (*src);
		tocopy = *uc;
		(*src)++;
		srcremain--;

		if (tocopy > srcremain)
			return 0;	/* illegal, better have nothing */
		if (tocopy > dstremain)
			return 0;	/* doesn't fit, better have nothing */

		memcpy(dst, *src, tocopy);
		dst += tocopy;
		(*src) += tocopy;
		srcremain -= tocopy;
		dstremain -= tocopy;
		dstused += tocopy;
	}
	return dstused;
}

int
putname(char **buf, size_t buflen, const char *host)
{
	char *word;
	int left;
	char *h;
	char *p;

	h = strdup(host);
	left = buflen;
	p = *buf;

	word = strtok(h, ".");
	while(word) {
		if (strlen(word) > 63 || strlen(word) > left) {
			free(h);
			return -1;
		}

		left -= (strlen(word) + 1);
		*p++ = (char)strlen(word);
		memcpy(p, word, strlen(word));
		p += strlen(word);

		word = strtok(NULL, ".");
	}

	*p++ = 0;

	free(h);

	*buf = p;
	return buflen - left;
}

int
putbyte(char **dst, unsigned char value)
{
	**dst = value;
	(*dst)++;

	return sizeof(char);
}

int
putshort(char **dst, unsigned short value)
{
	unsigned char *p;

	p = (unsigned char *) *dst;

	*p++ = (value >> 8);
	*p++ = value;

	(*dst) = (char *) p;
	return sizeof(short);
}

int
putlong(char **dst, uint32_t value)
{
	/* A long as described in dns protocol is always 32 bits */
	unsigned char *p;

	p = (unsigned char *) *dst;

	*p++ = (value >> 24);
	*p++ = (value >> 16);
	*p++ = (value >> 8);
	*p++ = (value);

	(*dst) = (char *) p;
	return sizeof(uint32_t);
}

int
putdata(char **dst, const char *data, size_t len)
{
	memcpy(*dst, data, len);

	(*dst) += len;
	return len;
}

int
puttxtbin(char **buf, size_t bufremain, const char *from, size_t fromremain)
{
	unsigned char uc;
	unsigned char *ucp = &uc;
	char *cp = (char *) ucp;
	int tocopy;
	int bufused = 0;

	while (fromremain > 0)
	{
		tocopy = fromremain;
		if (tocopy > 252)
			tocopy = 252;	/* allow off-by-1s in caches etc */
		if (tocopy + 1 > bufremain)
			return -1;	/* doesn't fit, better have nothing */

		uc = tocopy;
		**buf = *cp;
		(*buf)++;
		bufremain--;
		bufused++;

		memcpy(*buf, from, tocopy);
		(*buf) += tocopy;
		from += tocopy;
		bufremain -= tocopy;
		fromremain -= tocopy;
		bufused += tocopy;
	}
	return bufused;
}
