/* Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifdef WINDOWS
#include <conio.h>
#else
#include <termios.h>
#endif

#include "compat.h"
#include "ui.h"

#ifdef WINDOWS
static int (*ui_getch)(void) = getch;

void
ui_test_set_getch_fn(int (*getch_fn)(void))
{
	ui_getch = getch_fn;
}
#endif

static int debuglevel = 0;

static void
vlog(int level, const char *fmt, va_list list)
{
	if (level) {
		fprintf(stderr, "[D%d] ", level);
	}
	vfprintf(stderr, fmt, list);
}

void
ui_set_debuglevel(int level)
{
	debuglevel = level;
}

void
ui_debug(int level, const char *fmt, ...)
{
	va_list list;

	if (debuglevel >= level) {
		va_start(list, fmt);
		vlog(level, fmt, list);
		va_end(list);
	}
}

void
ui_log(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vlog(0, fmt, list);
	va_end(list);
}

void
ui_log_partial(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vlog(0, fmt, list);
	va_end(list);
	fflush(stderr);
}

void
ui_read_password(char *buf, size_t len)
{
#ifdef WINDOWS
	size_t idx = 0;
	size_t typed = 0;

	ui_log_partial("Enter tunnel password: ");
	for (;;) {
		int c = ui_getch();

		if (c == '\r' || c == '\n') {
			break;
		} else if (c == '\b') {
			if (typed > 0) {
				typed--;
				if (typed < len - 1) {
					idx = typed;
				}
			}
		} else {
			if (typed < len - 1) {
				buf[idx++] = c;
			}
			typed++;
		}
	}
	buf[idx] = '\0';
	ui_log("\n");
#else
	char pwd[80] = {0};
	struct termios old;
	struct termios tp;

	tcgetattr(0, &tp);
	old = tp;

	tp.c_lflag &= (~ECHO);
	tcsetattr(0, TCSANOW, &tp);

	ui_log_partial("Enter tunnel password: ");
	fscanf(stdin, "%79[^\n]", pwd);
	ui_log("\n");

	tcsetattr(0, TCSANOW, &old);

	strlcpy(buf, pwd, len);
#endif
}
