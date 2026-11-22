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
#include "process.h"

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
#if HAVE_LANDLOCK
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
#if HAVE_SECCOMP
#include <errno.h>
#include <seccomp.h>
#include <string.h>
#include <sys/socket.h>
#endif

#if HAVE_CHECKTOKENMEMBERSHIP
bool
is_user_in(WELL_KNOWN_SID_TYPE sid_type) {
	BOOL is_member = FALSE;
	BYTE sid_buffer[SECURITY_MAX_SID_SIZE];
	PSID sid = (PSID)sid_buffer;
	DWORD sid_size = sizeof(sid_buffer);

	if (CreateWellKnownSid(sid_type, NULL, sid, &sid_size)) {
		CheckTokenMembership(NULL, sid, &is_member);
	}

	return is_member;
}
#endif

void
check_privileges(unsigned int privs, int port)
{
	(void)privs;
	(void)port;
#if HAVE_LIBCAPNG
	bool capable = true;

	if (capng_get_caps_process() == -1) {
		warnx("Unable to get capabilities");
		exit(-1);
	}

	if ((privs & PROC_NEED_TUN) &&
	    !capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_ADMIN)) {
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
			if (fscanf(file, "%hu", &ip_unprivileged_port_start) != 1)
				warnx("sysctl: unable to parse ip_unprivileged_port_start value");
			fclose(file);
		}

		if (port < ip_unprivileged_port_start &&
			!capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_BIND_SERVICE)) {
			warnx("capabilities: CAP_NET_BIND_SERVICE required");
			capable = false;
		}
	}

	if (privs & PROC_NEED_SETUID) {
		if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETUID)) {
			warnx("capabilities: CAP_SETUID required");
			capable = false;
		}
		if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETGID)) {
			warnx("capabilities: CAP_SETGID required");
			capable = false;
		}
	}

	if ((privs & PROC_NEED_CHROOT) &&
	    !capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_CHROOT)) {
		warnx("capabilities: CAP_SYS_CHROOT required");
		capable = false;
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

void
do_detach(void)
{
#if CAN_DETACH
	int fd;

	ui_log("Detaching from terminal...\n");

	switch (fork()) {
	case 0:
		break;
	case -1:
		err(1, "fork");
		break;
	default:
		_exit(0);
	}

	if (setsid() < 0) {
		err(1, "setsid");
	}

	if (chdir("/") != 0) {
		err(1, "chdir");
	}

	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		for (int i = 0; i < 3; i++) {
			dup2(fd, i);
		}
		if (fd > 2) {
			close(fd);
		}
	}

	umask(0);
	alarm(0);
#else
	ui_log("Detaching not supported\n");
#endif
}

#if HAVE_LANDLOCK
int
get_landlock_abi(void)
{
	return syscall(SYS_landlock_create_ruleset, NULL, 0,
		       LANDLOCK_CREATE_RULESET_VERSION);
}

static bool
confine_landlock(unsigned int privs)
{
	int abi;
	int ruleset_fd;
	struct landlock_ruleset_attr attr = { 0 };

	abi = get_landlock_abi();
	if (abi < 0)
		return false; /* Kernel does not support Landlock */

	attr.handled_access_fs =
		LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
	if ((privs & PROC_NEED_PIDFILE) == 0)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_MAKE_REG;
	if ((privs & (PROC_NEED_PIDFILE | PROC_NEED_DETACH)) == 0)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	if ((privs & PROC_NEED_DETACH) == 0)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_READ_FILE;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if ((privs & PROC_NEED_PIDFILE) == 0 && abi >= 3)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
	if (abi >= 4)
		attr.handled_access_net =
			LANDLOCK_ACCESS_NET_BIND_TCP |
			LANDLOCK_ACCESS_NET_CONNECT_TCP;
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
	if (abi >= 5)
		attr.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
#ifdef LANDLOCK_SCOPE_SIGNAL
	if (abi >= 6)
		attr.scoped =
			LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
			LANDLOCK_SCOPE_SIGNAL;
#endif

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		err(1, "prctl(PR_SET_NO_NEW_PRIVS)");

	ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd < 0)
		err(1, "landlock_create_ruleset");
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0)
		err(1, "landlock_restrict_self");
	close(ruleset_fd);
	return true;
}
#endif

#if HAVE_SECCOMP
static void
seccomp_block_list(scmp_filter_ctx ctx, const int *syscalls)
{
	for (size_t i = 0; syscalls[i] != __NR_SCMP_ERROR; i++) {
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES),
					  syscalls[i], 0);
		if (rc < 0 && rc != -EDOM) {
			seccomp_release(ctx);
			errx(1, "seccomp_rule_add: %s", strerror(-rc));
		}
	}
}

static bool
confine_seccomp(unsigned int privs)
{
	static const int always_blocked[] = {
		SCMP_SYS(execve), SCMP_SYS(execveat),
		SCMP_SYS(memfd_create), SCMP_SYS(userfaultfd),
		SCMP_SYS(ptrace),
		SCMP_SYS(process_vm_readv), SCMP_SYS(process_vm_writev),
		SCMP_SYS(bpf), SCMP_SYS(perf_event_open),
		SCMP_SYS(io_uring_setup),
		SCMP_SYS(mount), SCMP_SYS(umount2), SCMP_SYS(pivot_root),
		SCMP_SYS(unshare), SCMP_SYS(setns),
		SCMP_SYS(init_module), SCMP_SYS(finit_module),
		SCMP_SYS(delete_module),
		SCMP_SYS(kexec_load), SCMP_SYS(kexec_file_load),
		SCMP_SYS(reboot),
		SCMP_SYS(kill),
		SCMP_SYS(add_key), SCMP_SYS(request_key), SCMP_SYS(keyctl),
		SCMP_SYS(personality), SCMP_SYS(swapon), SCMP_SYS(swapoff),
		SCMP_SYS(bind), SCMP_SYS(listen),
		SCMP_SYS(accept), SCMP_SYS(accept4), SCMP_SYS(socketpair),
		SCMP_SYS(unlink), SCMP_SYS(unlinkat),
		SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
		SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(rmdir),
		SCMP_SYS(symlink), SCMP_SYS(symlinkat),
		SCMP_SYS(link), SCMP_SYS(linkat),
		SCMP_SYS(mknod), SCMP_SYS(mknodat),
		SCMP_SYS(chmod), SCMP_SYS(fchmod), SCMP_SYS(fchmodat),
		SCMP_SYS(chown), SCMP_SYS(fchown), SCMP_SYS(lchown),
		SCMP_SYS(fchownat),
		SCMP_SYS(truncate), SCMP_SYS(ftruncate),
		SCMP_SYS(open_by_handle_at),
		__NR_SCMP_ERROR,
	};
	static const int detach_blocked[] = {
		SCMP_SYS(fork), SCMP_SYS(vfork),
		SCMP_SYS(clone), SCMP_SYS(clone3),
		__NR_SCMP_ERROR,
	};
	static const int chroot_blocked[] = {
		SCMP_SYS(chroot),
		__NR_SCMP_ERROR,
	};
	static const int chdir_blocked[] = {
		SCMP_SYS(chdir), SCMP_SYS(fchdir),
		__NR_SCMP_ERROR,
	};
	static const int setuid_blocked[] = {
		SCMP_SYS(setuid), SCMP_SYS(setgid),
		SCMP_SYS(setreuid), SCMP_SYS(setregid),
		SCMP_SYS(setresuid), SCMP_SYS(setresgid),
		SCMP_SYS(setgroups), SCMP_SYS(capset),
		__NR_SCMP_ERROR,
	};
	static const int open_blocked[] = {
		SCMP_SYS(open), SCMP_SYS(openat),
		SCMP_SYS(openat2), SCMP_SYS(creat),
		__NR_SCMP_ERROR,
	};
	static const int tun_blocked[] = {
		SCMP_SYS(ioctl),
		__NR_SCMP_ERROR,
	};
	scmp_filter_ctx ctx;
	int rc;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		errx(1, "seccomp_init failed");

	seccomp_block_list(ctx, always_blocked);
	if ((privs & PROC_NEED_DETACH) == 0)
		seccomp_block_list(ctx, detach_blocked);
	if ((privs & PROC_NEED_CHROOT) == 0)
		seccomp_block_list(ctx, chroot_blocked);
	if ((privs & (PROC_NEED_DETACH | PROC_NEED_CHROOT)) == 0)
		seccomp_block_list(ctx, chdir_blocked);
	if ((privs & (PROC_NEED_SETUID | PROC_NEED_CHROOT)) == 0)
		seccomp_block_list(ctx, setuid_blocked);
	if ((privs & (PROC_NEED_PIDFILE | PROC_NEED_DETACH)) == 0)
		seccomp_block_list(ctx, open_blocked);
	if ((privs & PROC_NEED_TUN) == 0) {
		seccomp_block_list(ctx, tun_blocked);
		rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES),
				      SCMP_SYS(socket), 1,
				      SCMP_CMP(0, SCMP_CMP_NE, AF_UNIX, 0));
		if (rc < 0 && rc != -EDOM) {
			seccomp_release(ctx);
			errx(1, "seccomp_rule_add: %s", strerror(-rc));
		}
	}

	rc = seccomp_load(ctx);
	seccomp_release(ctx);
	if (rc == -ENOSYS || rc == -EOPNOTSUPP)
		return false;
	if (rc < 0)
		errx(1, "seccomp_load: %s", strerror(-rc));
	return true;
}
#endif

bool
do_confine(unsigned int privs)
{
	bool confined = false;
#if HAVE_PLEDGE
	if (privs == PROC_NEED_NONE) {
		if (pledge("stdio inet", NULL) == -1)
			err(1, "pledge");
		return true;
	}
#endif

	/* PR_SET_NO_NEW_PRIVS interferes with setcon() */
	if (privs & PROC_NEED_SETCON)
		return false;

#if HAVE_LANDLOCK
	if (confine_landlock(privs))
		confined = true;
#endif
#if HAVE_SECCOMP
	if (confine_seccomp(privs))
		confined = true;
#endif
	return confined;
}
