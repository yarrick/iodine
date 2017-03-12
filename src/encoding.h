/*
 * Copyright (c) 2006-2014 Erik Ekman
 * 2006-2009 Bjorn Andersson
 * Copyright (c) 2017 Ralf Ramsauer
 *
 * Authors:
 *   Bjorn Andersson <flex@kryo.se>
 *   Erok Ekman <yarrick@kryo.se>,
 *   Ralf Ramsauer <ralf@ramses-pyramidenbau.de>
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

#ifndef _ENCODING_H_
#define _ENCODING_H_

#include <stdbool.h>

/* All-0, all-1, 01010101, 10101010: each 4 times to make sure the pattern
   spreads across multiple encoded chars -> 16 bytes total.
   Followed by 32 bytes from my /dev/random; should be enough.
 */
#define DOWNCODECCHECK1 \
	"\000\000\000\000\377\377\377\377\125\125\125\125\252\252\252\252" \
	"\201\143\310\322\307\174\262\027\137\117\316\311\111\055\122\041" \
	"\141\251\161\040\045\263\006\163\346\330\104\060\171\120\127\277"
#define DOWNCODECCHECK1_LEN  48

struct encoder {
	const char name[8];
	int (*encode)(char *dst, size_t *dstlen, const void *src, size_t srclen);
	int (*decode)(void *dst, size_t *dstlen, const char *src, size_t srclen);

	const bool places_dots;
	const bool eats_dots;

	const int blocksize_raw;
	const int blocksize_encoded;
};

int build_hostname(char *, size_t, const char *, const size_t, const char *,
		   const struct encoder *, int);
int unpack_data(char *, size_t, char *, size_t, const struct encoder *);
int inline_dotify(char *, size_t);
int inline_undotify(char *, size_t);

extern const struct encoder base32_ops;
extern const struct encoder base64_ops;
extern const struct encoder base64u_ops;
extern const struct encoder base128_ops;

int b32_5to8(int);
int b32_8to5(int);

#endif
