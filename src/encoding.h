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

struct encoder {
	char name[8];
	int (*encode) (char *, size_t *, const void *, size_t);
	int (*decode) (void *, size_t *, const char *, size_t);
	int (*places_dots) (void);
	int (*eats_dots) (void);
	int (*blocksize_raw)(void);
	int (*blocksize_encoded)(void);
};

int unpack_data(char *, size_t, char *, size_t, struct encoder *);
int inline_dotify(char *, size_t);
int inline_undotify(char *, size_t);


#endif /* _ENCODING_H_ */
