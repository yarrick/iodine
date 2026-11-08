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

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "ui.h"
#include "test_main.h"

#ifdef WINDOWS
#include <windows.h>

static const char *mock_input_str = NULL;
static size_t mock_input_pos = 0;

static int
mock_win_getch(void)
{
	if (!mock_input_str || mock_input_str[mock_input_pos] == '\0') {
		return EOF;
	}
	return mock_input_str[mock_input_pos++];
}

static void
inject_console_keys(const char *keys)
{
	mock_input_str = keys;
	mock_input_pos = 0;
	ui_test_set_getch_fn(mock_win_getch);
}
#else
static void
inject_console_keys(const char *keys)
{
	int pipefd[2];
	int ret;

	ck_assert_int_eq(pipe(pipefd), 0);

	ret = write(pipefd[1], keys, strlen(keys));
	ck_assert_int_gt(ret, 0);
	close(pipefd[1]);

	dup2(pipefd[0], STDIN_FILENO);
	close(pipefd[0]);
}
#endif

static struct tuple {
	char *a;
	char *b;
} testpairs[] = {
	{ "banana\n",					"banana"},
	{ "my pass word\n",				"my pass word"},
	{ "12345678901234567890\n",			"123456789012345"},
#ifdef WINDOWS
	/* Windows has to process character by character for them to not show,
	 * verify that erasing works as expected. */
	{ "secrret\b\b\bet123\n",			"secret123"},
	{ "\b\b\b\bhello world\n",			"hello world"},
	{ "12345678901234567890\b\b\b\b\b\b\n",		"12345678901234"},
	{ "12345678901234567890\b\b\b\b\bABC\n",	"123456789012345"},
	{ "12345678901234567890\b\b\b\b\b\bXYZ\n",	"12345678901234X"},
#endif
};
#define TUPLES (sizeof(testpairs) / sizeof(testpairs[0]))

START_TEST(test_read_password)
{
	char buf[16];
	memset(buf, 0, sizeof(buf));

	inject_console_keys(testpairs[_i].a);
	ui_read_password(buf, sizeof(buf));

	ck_assert_str_eq(buf, testpairs[_i].b);
	ck_assert_uint_lt(strlen(buf), sizeof(buf));
}
END_TEST

TCase *
test_create(void)
{
	TCase *tc;

	tc = tcase_create("UI");
	tcase_add_loop_test(tc, test_read_password, 0, TUPLES);

	return tc;
}
