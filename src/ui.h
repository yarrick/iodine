/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __UI_H__
#define __UI_H__

#include "config.h"

#if HAVE_FORMAT_ATTR
#ifdef __MINGW_PRINTF_FORMAT
#define PRINTF_ATTR(a, b) __attribute__((format(__MINGW_PRINTF_FORMAT, a, b)))
#else
#define PRINTF_ATTR(a, b) __attribute__((format(printf, a, b)))
#endif
#else
#define PRINTF_ATTR(a, b)
#endif

void ui_set_debuglevel(int level);
void ui_debug(int level, const char *fmt, ...) PRINTF_ATTR(2,3);

void ui_log(const char *fmt, ...) PRINTF_ATTR(1,2);
/* For logs not ending with newline, will flush. */
void ui_log_partial(const char *fmt, ...) PRINTF_ATTR(1,2);

void ui_read_password(char*, size_t);
#ifdef WINDOWS
void ui_test_set_getch_fn(int (*getch_fn)(void));
#endif

#endif
