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
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <zlib.h>

#include "tun.h"
#include "structs.h"
#include "dns.h"

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
	
int running = 1;

static void
sighandler(int sig) {
	running = 0;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	char out[64*1024];
	char in[64*1024];
	struct timeval tv;
	long outlen;
	fd_set fds;
	int read;
	int i;
	int rv;

	rv = 0;

	while (running) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		if (!dns_sending()) 
			FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);

		if (!running) {
			rv = 1;
			break;
		}
		
		if(i < 0) {
			warn("select");
			rv = 1;
			break;
		} else if (i > 0) {
			if(FD_ISSET(tun_fd, &fds)) {
				read = read_tun(tun_fd, in, sizeof(in));
				if(read <= 0)
					continue;

				outlen = sizeof(out);
				compress2(out, &outlen, in, read, 9);
				dns_handle_tun(dns_fd, out, outlen);
			}
			if(FD_ISSET(dns_fd, &fds)) {
				read = dns_read(dns_fd, in, sizeof(in));
				if (read <= 0) 
					continue;

				outlen = sizeof(out);
				uncompress(out, &outlen, in, read);

				write_tun(tun_fd, out, outlen);
				if (!dns_sending()) 
					dns_ping(dns_fd);
			} 
		} else
			dns_ping(dns_fd);
	}

	return rv;
}

static int
handshake(int dns_fd)
{
	struct timeval tv;
	char server[65];
	char client[65];
	char in[4096];
	int timeout;
	fd_set fds;
	int read;
	int mtu;
	int i;
	int r;

	timeout = 1;
	
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = timeout++;
		tv.tv_usec = 0;

		dns_handshake(dns_fd);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = dns_read(dns_fd, in, sizeof(in));
			
			if(read < 0) {
				perror("read");
				continue;
			}

			if (read > 0) {
				if (sscanf(in, "%64[^-]-%64[^-]-%d", 
					server, client, &mtu) == 3) {
					
					server[64] = 0;
					client[64] = 0;
					if (tun_setip(client) == 0 && 
						tun_setmtu(mtu) == 0) {

						return 0;
					} else {
						warn("Received handshake with bad data");
					}
				} else {
					printf("Received bad handshake\n");
				}
			}
		}

		printf("Retrying...\n");
	}

	return 1;
}

static void
usage() {
	extern char *__progname;

	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] "
			"nameserver topdomain\n", __progname);
	exit(2);
}

static void
help() {
	extern char *__progname;

	printf("iodine IP over DNS tunneling client\n");
	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] "
			"nameserver topdomain\n", __progname);
	printf("  -v to print version info and exit\n");
	printf("  -h to print this help and exit\n");
	printf("  -f to keep running in foreground\n");
	printf("  -u name to drop privileges and run as user 'name'\n");
	printf("  -t dir to chroot to directory dir\n");
	printf("  -d device to set tunnel device name\n");
	printf("nameserver is the IP number of the relaying nameserver\n");
	printf("topdomain is the FQDN that is delegated to the tunnel endpoint.\n");
	exit(0);
}

static void
version() {
	printf("iodine IP over DNS tunneling client\n");
	printf("version: 0.3.4 from 2006-11-08\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	struct passwd *pw;
	char *username;
	int foreground;
	char *newroot;
	char *device;
	int choice;
	int tun_fd;
	int dns_fd;

	username = NULL;
	foreground = 0;
	newroot = NULL;
	device = NULL;
	
	while ((choice = getopt(argc, argv, "vfhu:t:d:")) != -1) {
		switch(choice) {
		case 'v':
			version();
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help();
			break;
		case 'u':
			username = optarg;
			break;
		case 't':
			newroot = optarg;
			break;
		case 'd':
			device = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	
	if (geteuid() != 0) {
		printf("Run as root and you'll be happy.\n");
		usage();
	}

	argc -= optind;
	argv += optind;
	
	if (argc != 2) 
		usage();
	
	if(username) {
		pw = getpwnam(username);
		if (!pw) {
			printf("User %s does not exist!\n", username);
			usage();
		}
	}

	if ((tun_fd = open_tun(device)) == -1)
		goto cleanup1;
	if ((dns_fd = open_dns(argv[1], 0, INADDR_ANY)) == -1)
		goto cleanup2;
	if (dns_settarget(argv[0]) == -1)
		goto cleanup2;

	printf("Sending queries for %s to %s\n", argv[1], argv[0]);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	if(handshake(dns_fd))
		goto cleanup2;

	if (newroot) {
		if (chroot(newroot) != 0 || chdir("/") != 0)
			err(1, "%s", newroot);
		seteuid(geteuid());
		setuid(getuid());
	}
	
	if (!foreground) {
		printf("Detaching from terminal...\n");
		daemon(0, 0);
		umask(0);
		alarm(0);
	}
	
	if (username) {
		if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			printf("Could not switch to user %s!\n", username);
			usage();
		}
	}

	tunnel(tun_fd, dns_fd);

cleanup2:
	close_dns(dns_fd);
	close_tun(tun_fd);
cleanup1:

	return 0;
}
