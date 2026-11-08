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
#include <stdbool.h>

#include "config.h"
#include "compat.h"
#include "ui.h"

#ifdef WINDOWS
#include <windows.h>
#endif
#if HAVE_SYSLOG
#include <syslog.h>
#endif
#if HAVE_SETCON
# include <selinux/selinux.h>
#endif
#if HAVE_LIBCAPNG
#include <cap-ng.h>
#endif

#if HAVE_CHECKTOKENMEMBERSHIP
bool
is_user_in(WELL_KNOWN_SID_TYPE sid_type) {
	BOOL is_member = FALSE;
	byte sid_buffer[SECURITY_MAX_SID_SIZE];
	PSID sid = (PSID)sid_buffer;
	DWORD sid_size = sizeof(sid_buffer);

	if (CreateWellKnownSid(sid_type, NULL, sid, &sid_size)) {
		CheckTokenMembership(NULL, sid, &is_member);
	}

	return is_member;
}
#endif

void
check_privileges(char *username, int port)
{
	(void)username;
	(void)port;
#if HAVE_LIBCAPNG
	bool capable = true;

	if (capng_get_caps_process() == -1) {
		warnx("Unable to get capabilities");
		exit(-1);
	}

	if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_ADMIN)) {
		warnx("capabilities: CAP_NET_ADMIN required");
		capable = false;
	}

	if (port) {
		unsigned short int ip_unprivileged_port_start = 1024;

		FILE *file = fopen("/proc/sys/net/ipv4/ip_unprivileged_port_start", "r");
		if (!file) {
			warnx("sysctl: unable to get ip_unprivileged_port_start value");
			/* do not bail out here in case systemd.service has ProcSubset=pid set */
		} else {
			fscanf(file, "%hu", &ip_unprivileged_port_start);
			fclose(file);
		}

		if (port < ip_unprivileged_port_start &&
			!capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_BIND_SERVICE)) {
			warnx("capabilities: CAP_NET_BIND_SERVICE required");
			capable = false;
		}
	}

	if (username) {
		if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETUID)) {
			warnx("capabilities: CAP_SETUID required");
			capable = false;
		}
		if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETGID)) {
			warnx("capabilities: CAP_SETGID required");
			capable = false;
		}
	}

	if (!capable) {
		exit(-1);
	}
#elif HAVE_GETEUID
	if (geteuid() != 0) {
		warnx("Run as root and you'll be happy.");
		exit(-1);
	}
#elif HAVE_CHECKTOKENMEMBERSHIP
	if (!is_user_in(WinBuiltinAdministratorsSid) &&
	    !is_user_in(WinBuiltinNetworkConfigurationOperatorsSid)) {
		warnx("Missing admin or network config operator permissions.");
		exit(-1);
	}
#else
	/* No user permission check supported */
#endif
}

void
do_chroot(char *newroot)
{
	(void)newroot;
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
	(void)context;
#if HAVE_SETCON
	if (-1 == setcon(context))
		err(1, "setcon(%s)", context);
#else
	warnx("No SELinux support built in");
#endif
}

void
do_pidfile(char *pidfile)
{
	int fd;
	FILE *file;
#ifdef WINDOWS
	BY_HANDLE_FILE_INFORMATION fileInfo;
	HANDLE hFile = CreateFileA(
		pidfile,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
		hFile = CreateFileA(
			pidfile,
			GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
			NULL);
	}

	if (hFile == INVALID_HANDLE_VALUE) {
		err(1, "do_pidfile: Cannot write pidfile to %s", pidfile);
	}

	if (GetFileInformationByHandle(hFile, &fileInfo)) {
		if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			CloseHandle(hFile);
			errx(1, "do_pidfile: %s is a symbolic link", pidfile);
		}
	}

	if ((GetFileType(hFile) & 0xFFFF) != FILE_TYPE_DISK) {
		CloseHandle(hFile);
		DeleteFileA(pidfile);
		errx(1, "do_pidfile: %s is not a regular file", pidfile);
	}

	/* Truncate file */
	SetEndOfFile(hFile);

	fd = _open_osfhandle((intptr_t)hFile, _O_WRONLY);
	if (fd == -1) {
		CloseHandle(hFile);
		err(1, "do_pidfile: Cannot obtain file descriptor for %s", pidfile);
	}
#else
	struct stat st;

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
#endif

	if ((file = fdopen(fd, "w")) == NULL) {
		close(fd);
		syslog(LOG_ERR, "Cannot write pidfile to %s, exiting", pidfile);
		err(1, "do_pidfile: Can not write pidfile to %s", pidfile);
	} else {
		fprintf(file, "%d\n", (int)getpid());
		fclose(file);
	}
}

/* Provide daemon(3) if required and not available */
#if CAN_DETACH && !HAVE_DAEMON
static int
daemon(int nochdir, int noclose)
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
#if CAN_DETACH
	ui_log("Detaching from terminal...\n");
	daemon(0, 0);
	umask(0);
	alarm(0);
#else
	ui_log("Detaching not supported\n");
#endif
}

