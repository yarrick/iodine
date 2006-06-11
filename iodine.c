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

int tun_fd;
int dns_fd;

static void
sighandler(int sig) {
	running = 0;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	int i;
	int read;
	fd_set fds;
	struct timeval tv;
	char in[64*1024];
	long outlen;
	char out[64*1024];

	while (running) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		if (!dns_sending()) 
			FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if(i < 0) {
			if (running) {
				warn("select");
			}
			return 1;
		}
		
		if(i == 0) {
			dns_ping(dns_fd);
		} else {
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
		}
	}

	return 0;
}

static int
handshake(int dns_fd)
{
	int i;
	int r;
	char *p;
	int mtu;
	int read;
	fd_set fds;
	int timeout;
	char in[4096];
	struct timeval tv;

	timeout = 1;
	
	for (i=0;i<5;i++) {
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

			if (read == 0) 
				continue;

			p = strchr(in, '-');
			if (p) {
				*p++ = '\0';
				mtu = atoi(p);

				printf("%s %d\n", in, mtu);

				if (tun_setip(in) == 0 && tun_setmtu(atoi(p)) == 0)
					return 0;
			}
		}

		printf("Retrying...\n");
	}

	return 1;
}

extern char *__progname;

static void
usage() {
	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] "
			"nameserver topdomain\n", __progname);
	exit(2);
}

static void
help() {
	printf("iodine IP over DNS tunneling client\n");
	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] "
			"nameserver topdomain\n", __progname);
	printf("  -f is to keep running in foreground\n");
	printf("  -u name to drop privileges and run as user 'name'\n");
	printf("  -t dir to chroot to directory dir\n");
	printf("nameserver is the IP number of the relaying nameserver\n");
	printf("topdomain is the FQDN that is delegated to the tunnel endpoint.\n");
	exit(0);
}

static void
version() {
	char *svnver = "$Rev$ from $Date$";
	printf("iodine IP over DNS tunneling client\n");
	printf("SVN version: %s\n", svnver);
	exit(0);
}

int
main(int argc, char **argv)
{
	int choice;
	char *newroot;
	char *username;
	int foreground;
	struct passwd *pw;

	newroot = NULL;
	username = NULL;
	foreground = 0;
	
	while ((choice = getopt(argc, argv, "vfhu:t:")) != -1) {
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

	if ((tun_fd = open_tun()) == -1)
		goto cleanup1;
	if ((dns_fd = open_dns(argv[0], argv[1])) == -1)
		goto cleanup2;

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
