/* Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
 * Copyright (c) 2007 Albert Lee <trisk@acm.jhu.edu>.
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#ifdef WINDOWS32
#include <winsock2.h>
#include <conio.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif
#include <termios.h>
#include <err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "common.h"

/* daemon(3) exists only in 4.4BSD or later, and in GNU libc */
#if !defined(WINDOWS32) && !(defined(BSD) && (BSD >= 199306)) && !defined(__GLIBC__)
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


void
check_superuser(void (*usage_fn)(void))
{
#ifndef WINDOWS32
	if (geteuid() != 0) {
		warnx("Run as root and you'll be happy.\n");
		usage_fn();
		/* NOTREACHED */
	}
#endif
}

int 
open_dns(int localport, in_addr_t listen_ip) 
{
	struct sockaddr_in addr;
	int flag = 1;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(localport);
	/* listen_ip already in network byte order from inet_addr, or 0 */
	addr.sin_addr.s_addr = listen_ip; 

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "got fd %d\n", fd);
		err(1, "socket");
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &flag, sizeof(flag));

#ifndef WINDOWS32
	/* To get destination address from each UDP datagram, see iodined.c:read_dns() */
	setsockopt(fd, IPPROTO_IP, DSTADDR_SOCKOPT, (const void*) &flag, sizeof(flag));
#endif

#ifdef IP_OPT_DONT_FRAG
	/* Set dont-fragment ip header flag */
	flag = DONT_FRAG_VALUE;
	setsockopt(fd, IPPROTO_IP, IP_OPT_DONT_FRAG, (const void*) &flag, sizeof(flag));
#endif

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
		err(1, "bind");

	fprintf(stderr, "Opened UDP socket\n");

	return fd;
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

	seteuid(geteuid());
	setuid(getuid());
#else
	warnx("chroot not available");
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
	char pwd[80];
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

	fprintf(stderr, "Enter password: ");
	fflush(stderr);
#ifndef WINDOWS32
	scanf("%79s", pwd);
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
check_topdomain(char *str)
{
       int i;

       if(str[0] == '.') /* special case */
               return 1;

       for( i = 0; i < strlen(str); i++) {
               if( isalpha(str[i]) || isdigit(str[i]) || str[i] == '-' || str[i] == '.' )
                       continue;
               else 
		       return 1;
       }
       return 0;
}

#ifdef WINDOWS32
int
inet_aton(const char *cp, struct in_addr *inp)
{
 inp->s_addr = inet_addr(cp);
 return inp->s_addr != INADDR_ANY;
}

void
warn(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	if (fmt) fprintf(stderr, fmt, list);
	if (errno == 0) {
		fprintf(stderr, ": WSA error %d\n", WSAGetLastError()); 
	} else {
		fprintf(stderr, ": %s\n", strerror(errno));
	}
	va_end(list);
}

void
warnx(const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	if (fmt) fprintf(stderr, fmt, list);
	fprintf(stderr, "\n");
	va_end(list);
}

void
err(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	warn(fmt, list);
	va_end(list);
	exit(eval);
}

void
errx(int eval, const char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	warnx(fmt, list);
	va_end(list);
	exit(eval);
}
#endif

