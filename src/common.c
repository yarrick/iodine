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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif
#include <time.h>
#include <err.h>
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
#include <termios.h>

#include "common.h"

/* daemon(3) exists only in 4.4BSD or later, and in GNU libc */
#if !(defined(BSD) && (BSD >= 199306)) && !defined(__GLIBC__)
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

int 
open_dns(int localport, in_addr_t listen_ip) 
{
	struct sockaddr_in addr;
	int flag;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(localport);
	/* listen_ip already in network byte order from inet_addr, or 0 */
	addr.sin_addr.s_addr = listen_ip; 

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		err(1, "socket");

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	/* To get destination address from each UDP datagram, see iodined.c:read_dns() */
	setsockopt(fd, IPPROTO_IP, DSTADDR_SOCKOPT, &flag, sizeof(flag));

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
		err(1, "bind");

	printf("Opened UDP socket\n");

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
#if !defined(__BEOS__) || defined(__HAIKU__)
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
	printf("Detaching from terminal...\n");
	daemon(0, 0);
	umask(0);
	alarm(0);
}

void
read_password(char *buf, size_t len)
{
	struct termios old;
	struct termios tp;
	char pwd[80];

	tcgetattr(0, &tp);
	old = tp;
	
	tp.c_lflag &= (~ECHO);
	tcsetattr(0, TCSANOW, &tp);

	printf("Enter password: ");
	fflush(stdout);
	scanf("%79s", pwd);
	printf("\n");

	tcsetattr(0, TCSANOW, &old);	

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
