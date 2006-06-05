/*
 * Copyright (c) 2006 
 * Bjorn Andersson <flex@kryo.se>,
 * Erik Ekman <yarrick@kryo.se>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <time.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "dns.h"

int 
open_dns() 
{
	int fd;
	int flag;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0; 			// choose an available port
	addr.sin_addr.s_addr = INADDR_ANY; 	// listen on 0.0.0.0

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		err(1, "Could not get UDP socket");
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		err(1, "Could not bind UDP socket locally");
	}

	printf("Opened UDP socket\n");

	return fd;
}

void
close_dns(int fd)
{
	close(fd);
}
