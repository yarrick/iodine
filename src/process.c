/* Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 * Copyright (c) 2007 Albert Lee <trisk@acm.jhu.edu>.
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

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "config.h"
#include "common.h"

#ifndef WINDOWS
#include <syslog.h>
#endif
#ifdef HAVE_SETCON
# include <selinux/selinux.h>
#endif

void
do_chroot(char *newroot)
{
#if HAVE_CHROOT
	if (chroot(newroot) != 0 || chdir("/") != 0)
		err(1, "%s", newroot);

	if (seteuid(geteuid()) != 0 || setuid(getuid()) != 0) {
		err(1, "set[e]uid()");
	}
#else
	warnx("chroot not available");
#endif
}

void
do_setcon(char *context)
{
#ifdef HAVE_SETCON
	if (-1 == setcon(context))
		err(1, "%s", context);
#else
	warnx("No SELinux support built in");
#endif
}

void
do_pidfile(char *pidfile)
{
#ifndef WINDOWS
	int fd;
	struct stat st;
	FILE *file;

	/* Open without following symlinks so a local user cannot
	 * redirect the write (done as root) to an arbitrary file.
	 * O_NONBLOCK so a fifo at the path cannot make us block; the
	 * fstat check below rejects everything that is not a regular
	 * file anyway. Explicit 0644 mode so the file is not
	 * world-writable even after do_detach() sets umask(0). */
	fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_NONBLOCK, 0644);
	if (fd == -1) {
		syslog(LOG_ERR, "Cannot write pidfile to %s, exiting", pidfile);
		err(1, "do_pidfile: Can not write pidfile to %s", pidfile);
	}

	/* O_NOFOLLOW rejects symlinks, but fifos, sockets and devices
	 * are not; refuse to write the pid to anything but a regular
	 * file. */
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		syslog(LOG_ERR, "Refusing to write pidfile: %s is not a regular file", pidfile);
		err(1, "do_pidfile: %s is not a regular file", pidfile);
	}

	if ((file = fdopen(fd, "w")) == NULL) {
		close(fd);
		syslog(LOG_ERR, "Cannot write pidfile to %s, exiting", pidfile);
		err(1, "do_pidfile: Can not write pidfile to %s", pidfile);
	} else {
		fprintf(file, "%d\n", (int)getpid());
		fclose(file);
	}
#else
	fprintf(stderr, "Windows version does not support pid file\n");
#endif
}

/* Provide daemon(3) if required and not available */
#if !ANDROID && !WINDOWS && !HAVE_DAEMON
static int daemon(int nochdir, int noclose)
{
	int fd, i;

	switch (fork()) {
		case 0:
			break;
		case -1:
			return -1;
		default:
			_exit(0);
	}

	if (!nochdir) {
		chdir("/");
	}

	if (setsid() < 0) {
		return -1;
	}

	if (!noclose) {
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			for (i = 0; i < 3; i++) {
				dup2(fd, i);
			}
			if (fd > 2) {
				close(fd);
			}
		}
	}
	return 0;
}
#endif

void
do_detach(void)
{
#ifndef WINDOWS
	fprintf(stderr, "Detaching from terminal...\n");
	daemon(0, 0);
	umask(0);
	alarm(0);
#else
	fprintf(stderr, "Windows version does not support detaching\n");
#endif
}

