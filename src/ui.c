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

#include <stdio.h>
#include <string.h>
#ifdef WINDOWS
#include <conio.h>
#else
#include <termios.h>
#endif

#include "compat.h"
#include "ui.h"

void
ui_log(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);
}

void
ui_log_partial(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);
	fflush(stderr);
}

void
ui_read_password(char *buf, size_t len)
{
	char pwd[80] = {0};
#ifdef WINDOWS
	int i;

	ui_log_partial("Enter tunnel password: ");
	for (i = 0; i < sizeof(pwd); i++) {
		pwd[i] = getch();
		if (pwd[i] == '\r' || pwd[i] == '\n') {
			pwd[i] = 0;
			break;
		} else if (pwd[i] == '\b') {
			i--; 			/* Remove the \b char */
			if (i >=0) i--; 	/* If not first char, remove one more */
		}
	}
	ui_log("\n");

#else
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
#endif

	strlcpy(buf, pwd, len);
}
