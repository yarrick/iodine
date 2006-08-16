/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

int
readname(char *packet, char **src, char *dst, size_t length)
{
	char *dummy;
	int len;
	char *p;
	char c;

	len = 0;

	p = *src;

	p = *src;
	while(*p && len < length) {
		c = *p++;

		/* is this a compressed label? */
		if((c & 0xc0) == 0xc0) {
			dummy = packet + (((p[-1] & 0x3f) << 8) | p[0]);
			readname(packet, &dummy, dst, length - len);
			break;
		}

		while(c && len < length) {
			*dst++ = *p++;
			len++;

			c--;
		}

		if (*p != 0)
			*dst = '.';
		else 
			*dst = '\0';
	}
	(*src) = p+1;

	return strlen(dst);
}

int
readshort(char *packet, char **src, short *dst)
{
	char *p;

	p = *src;
	*dst = ((short)p[0] << 8) 
		 | ((short)p[1]);

	(*src) += sizeof(short);
	return sizeof(short);
}

int
readlong(char *packet, char **src, long *dst)
{
	char *p;

	p = *src;

	*dst = ((long)p[0] << 24) 
		 | ((long)p[1] << 16) 
		 | ((long)p[2] << 8)
		 | ((long)p[3]);

	(*src) += sizeof(long);
	return sizeof(long);
}

int
readdata(char *packet, char **src, char *dst, size_t len)
{
	memcpy(dst, *src, len);

	(*src) += len;

	return len;
}

int
putbyte(char **dst, char value)
{
	**dst = value;
	(*dst)++;

	return sizeof(char);
}

int
putshort(char **dst, short value)
{
	char *p;

	p = *dst;

	*p++ = (value >> 8);
	*p++ = value;

	(*dst) = p;
	return sizeof(short);
}

int
putlong(char **dst, long value)
{
	char *p;

	p = *dst;

	*p++ = (value >> 24);
	*p++ = (value >> 16);
	*p++ = (value >> 8);
	*p++ = (value);

	(*dst) = p;
	return sizeof(long);
}

int
putdata(char **dst, char *data, size_t len)
{
	memcpy(*dst, data, len);
	
	(*dst) += len;
	return len;
}

