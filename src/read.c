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
#include <stdint.h>

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
		if((c & 0xc0) == 0xc0) {
			offset = (((s[-1] & 0x3f) << 8) | (s[0] & 0xff));
			if (offset > packetlen) {
				if (len == 0) {
					// Bad jump first in packet
					return 0;
				} else {
					// Bad jump after some data
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
readshort(char *packet, char **src, short *dst)
{
	unsigned char *p;

	p = *src;
	*dst = (p[0] << 8) | p[1];

	(*src) += sizeof(short);
	return sizeof(short);
}

int
readlong(char *packet, char **src, uint32_t *dst)
{
	// A long as described in dns protocol is always 32 bits
	unsigned char *p;

	p = *src;

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
	if (len < 0)
		return 0;

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
	unsigned char *p;

	p = *dst;

	*p++ = (value >> 8);
	*p++ = value;

	(*dst) = p;
	return sizeof(short);
}

int
putlong(char **dst, uint32_t value)
{
	// A long as described in dns protocol is always 32 bits
	unsigned char *p;

	p = *dst;

	*p++ = (value >> 24);
	*p++ = (value >> 16);
	*p++ = (value >> 8);
	*p++ = (value);

	(*dst) = p;
	return sizeof(uint32_t);
}

int
putdata(char **dst, char *data, size_t len)
{
	if (len < 0)
		return 0;

	memcpy(*dst, data, len);
	
	(*dst) += len;
	return len;
}

