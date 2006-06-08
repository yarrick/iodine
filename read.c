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
readname(char *packet, char *dst, char *src)
{
	char l;
	int len;
	int offset;

	len = 0;

	while(*src) {
		l = *src++;
		len++;

		if(l & 0x80 && l & 0x40) {
			offset = ((src[-1] & 0x3f) << 8) | src[0];		
			readname(packet, dst, packet + offset);
			dst += strlen(dst);
			break;
		}

		while(l) {
			*dst++ = *src++;
			l--;
			len++;
		}

		*dst++ = '.';
	}

	*dst = '\0';
	src++;
	len++;

	return len;
}

