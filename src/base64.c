/*
 * Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "common.h"
#include "base64.h"

static const char cb64[] = 
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789.";
static unsigned char rev64[128];
static int reverse_init = 0;

#define REV64(x) rev64[(int) (x)]
#define MODE 	(cb64[62])
#define P62	(cb64[62])
#define P63	(cb64[63])

static struct encoder base64_encoder =
{
	"BASE64",
	base64_encode,
	base64_decode,
	base64_handles_dots,
	base64_handles_dots
};

struct encoder
*get_base64_encoder()
{
	return &base64_encoder;
}

int 
base64_handles_dots()
{
	return 0;
}

static void
findesc(int *count, unsigned char *esc, char c1, char c2, char c3, char c4)
{
	int min1 = 0;
	int min2 = 0;

	int num1 = 0xFF; /* a very big number */
	int num2 = 0xFE; /* a nearly as big number */

	int i;

	/* check if no more escapes needed */
	if (count[62] == 0 && count[63] == 0) {
		esc[0] = MODE;
		esc[1] = MODE;
		return;
	}

	for (i = 0; i < 62; i++) {
		if (i == c1 || i == c2 || i == c3 || i == c4) {
			continue;
		}

		if (count[i] < num1) {
			min2 = min1;
			num2 = num1;
			min1 = i;
			num1 = count[i];
		} else if (count[i] < num2) {
			min2 = i;
			num2 = count[i];
		}
	}

	esc[0] = cb64[min1];
	esc[1] = cb64[min2];
}
	
static void
escape_chars(char *buf, size_t buflen)
{
	int counter[64];
	int escapes;
	int reset;
	int i;
	unsigned char temp[4096];
	unsigned char *r;
	unsigned char *w;
	unsigned char *e;
	unsigned char esc[2];

	memset(counter, 0, sizeof(counter));
	esc[0] = P62;
	esc[1] = P63;

	/* first, find the number of times each token is used */
	r = (unsigned char *) buf;
	w = temp;
	while (*r) {
		counter[REV64(*r)]++;
		*w++ = *r++;
	}

	/* check if work needed */
	if (counter[62] == 0 && counter[63] == 0)
		return;
	
	r = temp;
	w = (unsigned char *) buf;
	reset = 1;
	escapes = 0;
	/* check a block for esc chars */
	while (*r) {
		if (reset == 0 && escapes == 0 && (
		    r[0] == esc[0] || r[1] == esc[0] ||r[2] == esc[0] ||r[2] == esc[0] ||
		    r[0] == esc[1] || r[1] == esc[1] ||r[2] == esc[1] ||r[2] == esc[1])) {
			/* last set of escape chars were unused.
			 * if we reset last escape switch then maybe we dont have to switch now */

			/* change the latest escape switch to 999 (RESET) */
			e[1] = MODE;
			e[2] = MODE;
			 
			/* store default esc chars */
			esc[0] = P62;
			esc[1] = P63;

			reset = 1;
		}
		/* these two if blocks can not be combined because a block can contain both
		 * char 9 and/or . and the current escape chars. */
		if (r[0] == esc[0] || r[1] == esc[0] ||r[2] == esc[0] ||r[2] == esc[0] ||
		    r[0] == esc[1] || r[1] == esc[1] ||r[2] == esc[1] ||r[2] == esc[1]) {
			/* switch escape chars */
			escapes = 0;
			reset = 0;

			/* find 2 suitable escape chars */
			findesc(counter, esc, REV64(r[0]), REV64(r[1]), REV64(r[2]), REV64(r[3]));

			/* store escape switch position */
			e = w;

			/* write new escape chars */
			*w++ = MODE;
			*w++ = esc[0];
			*w++ = esc[1];
		}
		
		/* update counter on remaining chars */
		for (i = 0; i < 4; i++) {
			if (r[i])
				counter[REV64(r[i])]--;
		}

		/* do the escaping */
		for (i = 0; i < 4; i++) {
			if (r[i] == P62) {
				r[i] = esc[0];
				escapes++;
			} else if (r[i] == P63) {
				r[i] = esc[1];
				escapes++;
			}
		}	
		
		/* copy back to buf */
		*w++ = *r++;
		*w++ = *r++;
		*w++ = *r++;
		*w++ = *r++;
	}
}

int 
base64_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	size_t newsize;
	size_t maxsize;
	unsigned char c;
	unsigned char *s;
	unsigned char *p;
	unsigned char *q;
	int i;

	memset(buf, 0, *buflen);
	
	if (!reverse_init) {
		for (i = 0; i < 64; i++) {
			c = cb64[i];
			rev64[(int) c] = i;
		}
		reverse_init = 1;
	}

	/* how many chars can we encode within the buf */
	maxsize = 3 * (*buflen / 4 - 1) - 1;
	/* how big will the encoded data be */
	newsize = 4 * (size / 3 + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		size = maxsize;
	}

	p = s = (unsigned char *) buf;
	q = (unsigned char *)data;

	for(i=0;i<size;i+=3) {
		p[0] = cb64[((q[0] & 0xfc) >> 2)];
		p[1] = cb64[(((q[0] & 0x03) << 4) | ((q[1] & 0xf0) >> 4))];
		p[2] = (i+1 < size) ? cb64[((q[1] & 0x0f) << 2 ) | ((q[2] & 0xc0) >> 6)] : '\0';
		p[3] = (i+2 < size) ? cb64[(q[2] & 0x3f)] : '\0';
		
		q += 3;
		p += 4;
	}	
	*p = 0;

	escape_chars(buf, *buflen);

	/* store number of bytes from data that was used */
	*buflen = size;

	return strlen(buf) - 1;
}

#define DECODE_ERROR 0xffffffff

static int
decode_token(const unsigned char *t, unsigned char *data, size_t len) 
{
	if (len < 2)
		return 0;

	data[0] = ((REV64(t[0]) & 0x3f) << 2) | 
			  ((REV64(t[1]) & 0x30) >> 4);

	if (len < 3)
		return 1;

	data[1] = ((REV64(t[1]) & 0x0f) << 4) | 
			  ((REV64(t[2]) & 0x3c) >> 2);

	if (len < 4)
		return 2;

	data[2] = ((REV64(t[2]) & 0x03) << 6) |
			  (REV64(t[3]) & 0x3f);

	return 3;
}

int
base64_decode(void *buf, size_t *buflen, const char *str, size_t slen)
{
	unsigned char *q;
	size_t newsize;
	size_t maxsize;
	const char *p;
	unsigned char c;
	unsigned char block[4];
	unsigned char prot62;
	unsigned char prot63;
	int len;
	int i;

	if (!reverse_init) {
		for (i = 0; i < 64; i++) {
			c = cb64[i];
			rev64[(int) c] = i;
		}
		reverse_init = 1;
	}
	
	/* chars needed to decode slen */
	newsize = 3 * (slen / 4 + 1) + 1;
	/* encoded chars that fit in buf */
	maxsize = 4 * (*buflen / 3 + 1) + 1;
	/* if the buffer is too small, eat some of the data */
	if (*buflen < newsize) {
		slen = maxsize;
	}
	
	prot62 = P62;
	prot63 = P63;

	q = buf;
	for (p = str; *p; p += 4) {
		/* handle escape instructions */
		if (*p == MODE) {
			p++;
			if (p[0] == MODE && p[1] == MODE) {
				/* reset escape chars */
				prot62 = P62;
				prot63 = P63;
				
				p += 2;
			} else {
				prot62 = *p++;
				prot63 = *p++;
			}
		}
		/* since the str is const, we unescape in another buf */
		for (i = 0; i < 4; i++) {
			block[i] = p[i];
			if (prot62 == block[i]) {
				block[i] = P62;
			} else if (prot63 == block[i]) {
				block[i] = P63;
			}
		}
		len = decode_token(block, (unsigned char *) q, slen);	
		q += len;
		slen -= 4;
		
		if (len < 3)
			break;
	}
	*q = '\0';
	
	return q - (unsigned char *) buf;
}

