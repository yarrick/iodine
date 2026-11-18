/*
 * Copyright (c) 2006-2026 Erik Ekman <yarrick@kryo.se>,
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

#include <fcntl.h>
#include <string.h>
#ifdef WINDOWS
#include <winsock2.h>
#else
#include <sys/select.h>
#include <sys/time.h>
#if HAVE_SO_RTABLE
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#endif

#include "compat.h"
#include "sock.h"
#include "ui.h"

int
sock_select_fds(int timeout_ms, fd_set *fds, const int *list, size_t n)
{
	fd_set local_fds;
	struct timeval tv;
	int maxfd = 0;

	if (fds == NULL)
		fds = &local_fds;
	FD_ZERO(fds);

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	for (size_t i = 0; i < n; i++) {
		if (list[i] >= 0) {
			FD_SET(list[i], fds);
			if (list[i] > maxfd)
				maxfd = list[i];
		}
	}

	return select(maxfd + 1, fds, NULL, NULL, &tv);
}

bool
sock_isset(int fd, fd_set *fds)
{
	return fd >= 0 && FD_ISSET(fd, fds);
}

/* Set FD_CLOEXEC flag on socket/file descriptor.
 * This stops it from being inherited by system() calls.
 */
void
sock_set_close_on_exec(int fd)
{
#if HAVE_FD_CLOEXEC
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		err(4, "Failed to get fd flags");
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		err(4, "Failed to set fd flags");
#endif
	(void)fd;
}

void
sock_setrtable(int fd, int rtable)
{
	(void)fd;
	(void)rtable;
#if HAVE_SO_RTABLE
	if (setsockopt(fd, IPPROTO_IP, SO_RTABLE, &rtable, sizeof(rtable)) == -1)
		err(1, "Failed to set routing table %d", rtable);
#else
	ui_log("Routing domain support was not available at compile time.\n");
#endif
}
