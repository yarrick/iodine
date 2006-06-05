/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include "tun.h"
#include "dns.h"
#include "dnsd.h"

#define MAX(a,b) ((a)>(b)?(a):(b))

int running = 1;


static void
sigint(int sig) {
	running = 0;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	int i;
	int read;
	fd_set fds;
	struct timeval tv;
	struct tun_frame *frame;

	frame = malloc(64*1024);
	
	while (running) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		if(!dnsd_haspacket())
			FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if(i < 0) {
			if (running) {
				warn("select");
			}
			return 1;
		}
		
		if(i != 0) {
			if(FD_ISSET(tun_fd, &fds)) {
				read = read_tun(tun_fd, frame, 64*1024);
				if(read > 0) 
					dnsd_queuepacket(frame->data, read - 4);
			}
			if(FD_ISSET(dns_fd, &fds)) {
				read = dnsd_read(dns_fd, frame->data, 64*1024-4);
				if(read > 0)
					write_tun(tun_fd, frame, read + 4);
			} 
		}
	}

	free(frame);

	return 0;
}

int
main(int argc, char **argv)
{
	int tun_fd;
	int dnsd_fd;

	if (argc != 2) {
		printf("Usage: %s topdomain\n", argv[0]);
		exit(2);
	}

	tun_fd = open_tun();
	dnsd_fd = open_dnsd(argv[1]);

	signal(SIGINT, sigint);
	
	tunnel(tun_fd, dnsd_fd);

	printf("Closing tunnel\n");

	close_dnsd(dnsd_fd);
	close_tun(tun_fd);	

	return 0;
}
