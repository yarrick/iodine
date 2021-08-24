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

#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS32
#include <winsock2.h>
#include <conio.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <termios.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef HAVE_SETCON
# include <selinux/selinux.h>
#endif

#include "common.h"

/* The raw header used when not using DNS protocol */
const unsigned char raw_header[RAW_HDR_LEN] = { 0x10, 0xd1, 0x9e, 0x00 };

/* daemon(3) exists only in 4.4BSD or later, and in GNU libc */
#if !defined(ANDROID) && !defined(WINDOWS32) && !(defined(BSD) && (BSD >= 199306)) && !defined(__GLIBC__)
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

#if defined(__BEOS__) && !defined(__HAIKU__)
int setgroups(int count, int *groups)
{
	/* errno = ENOSYS; */
	return -1;
}
#endif

#ifndef WINDOWS32
void
check_superuser(void)
{
	if (geteuid() != 0) {
		warnx("Run as root and you'll be happy.");
		exit(-1);
	}
}
#endif

char *
format_addr(struct sockaddr_storage *sockaddr, int sockaddr_len)
{
	static char dst[INET6_ADDRSTRLEN + 1];

	memset(dst, 0, sizeof(dst));
	if (sockaddr->ss_family == AF_INET && sockaddr_len >= sizeof(struct sockaddr_in)) {
		getnameinfo((struct sockaddr *)sockaddr, sockaddr_len, dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
	} else if (sockaddr->ss_family == AF_INET6 && sockaddr_len >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sockaddr;
		if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
			struct in_addr ia;
			/* Get mapped v4 addr from last 32bit field */
			memcpy(&ia.s_addr, &addr->sin6_addr.s6_addr[12], sizeof(ia));
			strcpy(dst, inet_ntoa(ia));
		} else {
			getnameinfo((struct sockaddr *)sockaddr, sockaddr_len, dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
		}
	} else {
		dst[0] = '?';
	}
	return dst;
}

int
get_addr(char *host, int port, int addr_family, int flags, struct sockaddr_storage *out)
{
	struct addrinfo hints, *addr;
	int res;
	char portnum[8];

	memset(portnum, 0, sizeof(portnum));
	snprintf(portnum, sizeof(portnum) - 1, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = addr_family;
#if defined(WINDOWS32) || defined(OPENBSD)
	/* AI_ADDRCONFIG misbehaves on windows, and does not exist in OpenBSD */
	hints.ai_flags = flags;
#else
	hints.ai_flags = AI_ADDRCONFIG | flags;
#endif
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	res = getaddrinfo(host, portnum, &hints, &addr);
	if (res == 0) {
		int addrlen = addr->ai_addrlen;
		/* Grab first result */
		memcpy(out, addr->ai_addr, addr->ai_addrlen);
		freeaddrinfo(addr);
		return addrlen;
	}
	return res;
}

int
open_dns(struct sockaddr_storage *sockaddr, size_t sockaddr_len)
{
	return open_dns_opt(sockaddr, sockaddr_len, -1);
}

int
open_dns_opt(struct sockaddr_storage *sockaddr, size_t sockaddr_len, int v6only)
{
	int flag;
	int fd;

	if ((fd = socket(sockaddr->ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		err(1, "socket");
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &flag, sizeof(flag));

#ifndef WINDOWS32
	fd_set_close_on_exec(fd);
#endif

	if (sockaddr->ss_family == AF_INET6 && v6only >= 0) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void*) &v6only, sizeof(v6only));
	}

#ifdef IP_OPT_DONT_FRAG
	/* Set dont-fragment ip header flag */
	flag = DONT_FRAG_VALUE;
	setsockopt(fd, IPPROTO_IP, IP_OPT_DONT_FRAG, (const void*) &flag, sizeof(flag));
#endif

	if (bind(fd, (struct sockaddr*) sockaddr, sockaddr_len) < 0)
		err(1, "bind() to %s", format_addr(sockaddr, sockaddr_len));

	fprintf(stderr, "Opened IPv%d UDP socket\n", sockaddr->ss_family == AF_INET6 ? 6 : 4);

	return fd;
}

int
open_dns_from_host(char *host, int port, int addr_family, int flags)
{
	struct sockaddr_storage addr;
	int addrlen;

	addrlen = get_addr(host, port, addr_family, flags, &addr);
	if (addrlen < 0)
		return addrlen;

	return open_dns(&addr, addrlen);
}

void
close_dns(int fd)
{
	close(fd);
}

void
do_chroot(char *newroot)
{
#if !(defined(WINDOWS32) || defined(__BEOS__) || defined(__HAIKU__))
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
#ifndef WINDOWS32
	FILE *file;

	if ((file = fopen(pidfile, "w")) == NULL) {
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

void
do_detach()
{
#ifndef WINDOWS32
	fprintf(stderr, "Detaching from terminal...\n");
	daemon(0, 0);
	umask(0);
	alarm(0);
#else
	fprintf(stderr, "Windows version does not support detaching\n");
#endif
}

void
read_password(char *buf, size_t len)
{
	char pwd[80] = {0};
#ifndef WINDOWS32
	struct termios old;
	struct termios tp;

	tcgetattr(0, &tp);
	old = tp;

	tp.c_lflag &= (~ECHO);
	tcsetattr(0, TCSANOW, &tp);
#else
	int i;
#endif

	fprintf(stderr, "Enter tunnel password: ");
	fflush(stderr);
#ifndef WINDOWS32
	fscanf(stdin, "%79[^\n]", pwd);
#else
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
#endif
	fprintf(stderr, "\n");

#ifndef WINDOWS32
	tcsetattr(0, TCSANOW, &old);
#endif

	strncpy(buf, pwd, len);
	buf[len-1] = '\0';
}

int
check_topdomain(char *str, int allow_wildcard, char **errormsg)
{
	int i;
	int dots = 0;
	int chunklen = 0;

	if (strlen(str) < 3) {
		if (errormsg) *errormsg = "Too short (< 3)";
		return 1;
	}
	if (strlen(str) > 128) {
		if (errormsg) *errormsg = "Too long (> 128)";
		return 1;
	}

	if (str[0] == '.') {
		if (errormsg) *errormsg = "Starts with a dot";
		return 1;
	}

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '.') {
			dots++;
			if (chunklen == 0) {
				if (errormsg) *errormsg = "Consecutive dots";
				return 1;
			}
			if (chunklen > 63) {
				if (errormsg) *errormsg = "Too long domain part (> 63)";
				return 1;
			}
			chunklen = 0;
		} else {
			chunklen++;
		}
		if ((str[i] >= 'a' && str[i] <= 'z') || (str[i] >= 'A' && str[i] <= 'Z') ||
				isdigit(str[i]) || str[i] == '-' || str[i] == '.') {
			continue;
		} else if (allow_wildcard && str[i] == '*') {
			/* First char allowed to be wildcard, if followed by dot */
			if (i == 0) {
				if (str[i+1] == '.') {
					continue;
				}
				if (errormsg) *errormsg = "Wildcard (*) must be followed by dot";
				return 1;
			} else {
				if (errormsg) *errormsg = "Wildcard (*) only allowed as first char";
				return 1;
			}
		} else {
			if (errormsg) *errormsg = "Contains illegal character (allowed: [a-zA-Z0-9-.])";
			return 1;
		}
	}

	if (dots == 0) {
		if (errormsg) *errormsg = "No dots";
		return 1;
	}
	if (chunklen == 0) {
		if (errormsg) *errormsg = "Ends with a dot";
		return 1;
	}
	if (chunklen > 63) {
		if (errormsg) *errormsg = "Too long domain part (> 63)";
		return 1;
	}

	return 0;
}

int
query_datalen(const char *qname, const char *topdomain)
{
	/* Return number of data bytes embedded in DNS query name,
	 * or -1 if domains do not match.
	 */
	int qpos = strlen(qname);
	int tpos = strlen(topdomain);
	if (tpos < 3 || qpos < tpos) {
		/* Domain or query name too short */
		return -1;
	}
	/* Backward string compare */
	qpos--;
	tpos--;
	while (qpos >= 0) {
		if (topdomain[tpos] == '*') {
			/* Wild match, is first in topdomain */
			if (qname[qpos] == '*') {
				/* Don't match against stars in query name */
				return -1;
			} else if (qpos == 0 || qname[qpos-1] == '.') {
				/* Reached start of query name or chunk separator */
				return qpos;
			}
			qpos--;
		} else if (tolower(qname[qpos]) == tolower(topdomain[tpos])) {
			/* Matching char, exclude wildcard in query name */
			if (tpos == 0) {
				/* Fully matched domain */
				if (qpos == 0 || qname[qpos-1] == '.') {
					/* Start of name or has dot before matching topdomain */
					return qpos;
				}
				/* Query name has longer chunk than topdomain */
				return -1;
			}
			tpos--;
			qpos--;
		} else {
			return -1;
		}
	}
	return -1;
}

#if defined(WINDOWS32) || defined(ANDROID)
#ifndef ANDROID
int
inet_aton(const char *cp, struct in_addr *inp)
{
 inp->s_addr = inet_addr(cp);
 return inp->s_addr != INADDR_ANY;
}
#endif

void
vwarn(const char *fmt, va_list list)
{
	if (fmt) vfprintf(stderr, fmt, list);
#ifndef ANDROID
	if (errno == 0) {
		fprintf(stderr, ": WSA error %d\n", WSAGetLastError());
	} else {
		fprintf(stderr, ": %s\n", strerror(errno));
	}
#endif
}

void
warn(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vwarn(fmt, list);
	va_end(list);
}

void
err(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vwarn(fmt, list);
	va_end(list);
	exit(eval);
}

void
vwarnx(const char *fmt, va_list list)
{
	if (fmt) vfprintf(stderr, fmt, list);
	fprintf(stderr, "\n");
}

void
warnx(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vwarnx(fmt, list);
	va_end(list);
}

void
errx(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vwarnx(fmt, list);
	va_end(list);
	exit(eval);
}
#endif


int recent_seqno(int ourseqno, int gotseqno)
/* Return 1 if we've seen gotseqno recently (current or up to 3 back).
   Return 0 if gotseqno is new (or very old).
*/
{
	int i;
	for (i = 0; i < 4; i++, ourseqno--) {
		if (ourseqno < 0)
			ourseqno = 7;
		if (gotseqno == ourseqno)
			return 1;
	}
	return 0;
}

#ifndef WINDOWS32
/* Set FD_CLOEXEC flag on file descriptor.
 * This stops it from being inherited by system() calls.
 */
void
fd_set_close_on_exec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		err(4, "Failed to get fd flags");
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		err(4, "Failed to set fd flags");
}
#endif

