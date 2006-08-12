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

#include <stdio.h>

// For FreeBSD
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

static const char to_hex[] = "0123456789ABCDEF";

int
encode_data(char *buf, int len, int space, char *dest, char flag)
{
	int final;
	int write;
	int i;
	int t;

#define CHUNK 31
// 31 bytes expands to 62 chars in domain
// We just use hex as encoding right now

	write = space / 2; // use two chars per byte in encoding
	write -= (write/CHUNK); // make space for parts

	write = MIN(write, len); // do not use more bytes than is available;
	final = (write == len);	// is this the last block?

	if (flag != 0) {
		*dest = flag;
	} else {
		// First byte is 0 for middle packet and 1 for last packet
		*dest = '0' + final;
	}
	dest++;

	if (len > 0) {
		for (i = 0; i < write; i++) {
			if (i > 0 && i % CHUNK == 0) {
				*dest = '.';
				dest++;
			}
			t = (buf[i] & 0xF0) >> 4;
			*dest++ = to_hex[t];
			t = buf[i] & 0x0F;
			*dest++ = to_hex[t];
		}
	}
	return write;
}

int
decode_data(char *dest, int size, const char *src, char *srcend)
{
	int r;
	int len;

	len = 1;
	*dest = *src;
	dest++;
	src++;

	while(len < size && src < srcend) {
		if(*src == '.') {
			src++;
			continue;
		}

		sscanf(src, "%02X", &r);
		*dest++ = (char)r;
		src+=2;	
		len++;
	} 
	return len;
}

