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

#include "config.h"
#include "compat.h"
#include "process.h"

#include <check.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>

START_TEST(test_pidfile_writes_pid)
{
	char path[64];
	char buf[32];
	char expected[16];
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "iodine_test_pidfile_%d", (int)getpid());
	(void)unlink(path);

	do_pidfile(path);

	fd = open(path, O_RDONLY);
	ck_assert_int_ge(fd, 0);
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	ck_assert_int_ge(n, 0);
	buf[n] = 0;
	buf[strcspn(buf, "\n")] = 0;

	snprintf(expected, sizeof(expected), "%d", (int)getpid());
	ck_assert_str_eq(expected, buf);

	(void)unlink(path);
}
END_TEST

#ifndef WINDOWS
START_TEST(test_pidfile_rejects_symlink)
{
	char link[64], target[64];
	char buf[16];
	pid_t pid;
	int status;
	int tfd;
	ssize_t n;

	snprintf(link, sizeof(link), "/tmp/iodine_test_link_%d", (int)getpid());
	snprintf(target, sizeof(target), "/tmp/iodine_test_target_%d", (int)getpid());

	/* Sentinel content in the target so we can detect a redirected write. */
	tfd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ck_assert_int_ge(tfd, 0);
	ck_assert_int_ge(write(tfd, "sentinel", 8), 0);
	close(tfd);

	(void)unlink(link);
	ck_assert_int_eq(symlink(target, link), 0);

	/* do_pidfile() on a symlink must fail and call err(1) -> exit(1).
	 * Run it in a child so the terminating err() cannot kill the harness. */
	pid = fork();
	ck_assert_int_ge(pid, 0);
	if (pid == 0) {
		do_pidfile(link);
		/* Reaching here means do_pidfile did not terminate. */
		_exit(0);
	}

	ck_assert_int_ge(waitpid(pid, &status, 0), 0);
	ck_assert(WIFEXITED(status));
	ck_assert_int_eq(WEXITSTATUS(status), 1);

	/* The symlinked target must be completely untouched. */
	tfd = open(target, O_RDONLY);
	ck_assert_int_ge(tfd, 0);
	memset(buf, 0, sizeof(buf));
	n = read(tfd, buf, sizeof(buf));
	close(tfd);
	ck_assert_int_eq(n, 8);
	ck_assert_str_eq("sentinel", buf);

	(void)unlink(link);
	(void)unlink(target);
}
END_TEST
#endif

TCase *
test_create()
{
	TCase *tc;
	network_init();

	tc = tcase_create("Process");
	tcase_add_test(tc, test_pidfile_writes_pid);
#ifndef WINDOWS
	tcase_add_test(tc, test_pidfile_rejects_symlink);
#endif
	return tc;
}
