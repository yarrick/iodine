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

#ifndef _READ_H_
#define _READ_H_

int readname(char *, int, char **, char *, size_t);
int readshort(char *, char **, unsigned short *);
int readlong(char *, char **, uint32_t *);
int readdata(char *, char **, char *, size_t);
int readtxtbin(char *, char **, size_t, char *, size_t);

int putname(char **, size_t, const char *);
int putbyte(char **, unsigned char);
int putshort(char **, unsigned short);
int putlong(char **, uint32_t);
int putdata(char **, const char *, size_t);
int puttxtbin(char **, size_t, const char *, size_t);

#endif
