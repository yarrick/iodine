/* Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <termios.h>

#include "common.h"

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
	if (chroot(newroot) != 0 || chdir("/") != 0)
		err(1, "%s", newroot);

	seteuid(geteuid());
	setuid(getuid());
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
