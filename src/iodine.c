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

#include "common.h"
#include "dns.h"
#include "login.h"
#include "tun.h"
#include "version.h"

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

int running = 1;
char password[33];

static void
sighandler(int sig) {
	running = 0;
}

static int
tunnel_tun(int tun_fd, int dns_fd)
{
	char out[64*1024];
	char in[64*1024];
	size_t outlen;
	int read;

	read = read_tun(tun_fd, in, sizeof(in));
	if(read > 0) {
		outlen = sizeof(out);
		compress2(out, &outlen, in, read, 9);
		dns_handle_tun(dns_fd, out, outlen);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	char out[64*1024];
	char in[64*1024];
	size_t outlen;
	int read;

	read = dns_read(dns_fd, in, sizeof(in));
	if (read > 0) {
		outlen = sizeof(out);
		uncompress(out, &outlen, in, read);

		write_tun(tun_fd, out, outlen);
		if (!dns_sending()) 
			dns_ping(dns_fd);
	}
	
	return read;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
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

		if (running == 0 || i < 0) {
			rv = 1;
			break;
		}
		
		if (i == 0) /* timeout */
			dns_ping(dns_fd);
		else {	
			if(FD_ISSET(tun_fd, &fds)) {
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
			}
			if(FD_ISSET(dns_fd, &fds)) {
				if (tunnel_dns(tun_fd, dns_fd) <= 0)
					continue;
			} 
		}
	}

	return rv;
}

static int
handshake(int dns_fd)
{
	struct timeval tv;
	char server[65];
	char client[65];
	char login[16];
	char in[4096];
	fd_set fds;
	int read;
	int mtu;
	int seed;
	int version;
	int i;
	int r;

	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		dns_send_version(dns_fd, VERSION);
		
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
				if (strncmp("VACK", in, 4) == 0) {
					if (read >= 8) {
						memcpy(&seed, in + 4, 4);
						seed = ntohl(seed);
						printf("Version ok, both running 0x%08x\n", VERSION);
						break;
					} else {
						printf("Version ok but did not receive proper login challenge\n");
					}
				} else {
					memcpy(&version, in + 4, 4);
					version = ntohl(version);
					printf("You run 0x%08x, server runs 0x%08x. Giving up\n", VERSION, version);
					return 1;
				}
			}
		}
		
		if (i == 4)
			return 1;
		printf("Retrying version check...\n");
	}
	
	login_calculate(login, 16, password, seed);
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		dns_login(dns_fd, login, 16);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = dns_read(dns_fd, in, sizeof(in));
			
			if(read <= 0) {
				perror("read");
				continue;
			}

			if (read > 0) {
				if (strncmp("LNAK", in, 4) == 0) {
					printf("Bad password\n");
					return 1;
				} else if (sscanf(in, "%64[^-]-%64[^-]-%d", 
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

		printf("Retrying login...\n");
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
	char *svnver = "$Rev$ from $Date$";
	printf("iodine IP over DNS tunneling client\n");
	printf("SVN version: %s\n", svnver);
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
	memset(password, 0, 33);
	foreground = 0;
	newroot = NULL;
	device = NULL;
	
	while ((choice = getopt(argc, argv, "vfhu:t:d:P:")) != -1) {
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
		case 'P':
			strncpy(password, optarg, 32);
			password[32] = 0;
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
	
	if (strlen(password) == 0) {
		printf("Enter password on stdin:\n");
		scanf("%32s", password);
		password[32] = 0;
	}

	if ((tun_fd = open_tun(device)) == -1)
		goto cleanup1;
	dns_set_topdomain(argv[1]);
	if ((dns_fd = open_dns(0, INADDR_ANY)) == -1)
		goto cleanup2;
	if (dns_settarget(argv[0]) == -1)
		goto cleanup2;

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	if(handshake(dns_fd))
		goto cleanup2;
	
	printf("Sending queries for %s to %s\n", argv[1], argv[0]);

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
