/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#ifndef _ENCODING_H_
#define _ENCODING_H_

/* All-0, all-1, 01010101, 10101010: each 4 times to make sure the pattern
   spreads across multiple encoded chars -> 16 bytes total.
   Followed by 32 bytes from my /dev/random; should be enough.
 */
#define DOWNCODECCHECK1      "\000\000\000\000\377\377\377\377\125\125\125\125\252\252\252\252\201\143\310\322\307\174\262\027\137\117\316\311\111\055\122\041\141\251\161\040\045\263\006\163\346\330\104\060\171\120\127\277"
#define DOWNCODECCHECK1_LEN  48

struct encoder {
	char name[8];
	int (*encode) (char *, size_t *, const void *, size_t);
	int (*decode) (void *, size_t *, const char *, size_t);
	int (*places_dots) (void);
	int (*eats_dots) (void);
	int (*blocksize_raw)(void);
	int (*blocksize_encoded)(void);
};

int build_hostname(char *, size_t, const char *, const size_t, const char *, struct encoder *, int);
int unpack_data(char *, size_t, char *, size_t, struct encoder *);
int inline_dotify(char *, size_t);
int inline_undotify(char *, size_t);


#endif /* _ENCODING_H_ */
