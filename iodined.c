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
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <zlib.h>

#include "tun.h"
#include "structs.h"
#include "dns.h"

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

int running = 1;

struct packet packetbuf;
struct packet outpacket;
int outid;

struct query q;

int my_mtu;
in_addr_t my_ip;

static void
sigint(int sig) {
	running = 0;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	struct in_addr clientip;
	struct in_addr myip;
	struct timeval tv;
	char out[64*1024];
	char in[64*1024];
	char *tmp[2];
	long outlen;
	fd_set fds;
	int read;
	int code;
	int i;

	while (running) {
		if (q.id != 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 5000;
		} else {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}

		FD_ZERO(&fds);
		if(outpacket.len == 0)
			FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if(i < 0) {
			if (running) 
				warn("select");
			return 1;
		}
	
		if (i==0) {	
			if (q.id != 0) {
				dnsd_send(dns_fd, &q, outpacket.data, outpacket.len);
				outpacket.len = 0;
				q.id = 0;
			}
		} else {
			if(FD_ISSET(tun_fd, &fds)) {
				read = read_tun(tun_fd, in, sizeof(in));
				if (read <= 0)
					continue;
				
				outlen = sizeof(out);
				compress2(out, &outlen, in, read, 9);
				memcpy(outpacket.data, out, outlen);
				outpacket.len = outlen;
			}
			if(FD_ISSET(dns_fd, &fds)) {
				read = dnsd_read(dns_fd, &q, in, sizeof(in));
				if (read <= 0)
			   		continue;

				if(in[0] == 'H' || in[0] == 'h') {
					myip.s_addr = my_ip;	
					clientip.s_addr = my_ip + inet_addr("0.0.0.1");

					tmp[0] = strdup(inet_ntoa(myip));
					tmp[1] = strdup(inet_ntoa(clientip));
					
					read = snprintf(out, sizeof(out), "%s-%s-%d", 
							tmp[0], tmp[1], my_mtu);

					dnsd_send(dns_fd, &q, out, read);
					q.id = 0;

					free(tmp[1]);
					free(tmp[0]);
				} else if((in[0] >= '0' && in[0] <= '9')
						|| (in[0] >= 'a' && in[0] <= 'f')
						|| (in[0] >= 'A' && in[0] <= 'F')) {
					if ((in[0] >= '0' && in[0] <= '9'))
						code = in[0] - '0';
					if ((in[0] >= 'a' && in[0] <= 'f'))
						code = in[0] - 'a' + 10;
					if ((in[0] >= 'A' && in[0] <= 'F'))
						code = in[0] - 'A' + 10;

					memcpy(packetbuf.data + packetbuf.offset, in + 1, read - 1);
					packetbuf.len += read - 1;
					packetbuf.offset += read - 1;

					if (code & 1) {
						outlen = sizeof(out);
						uncompress(out, &outlen, packetbuf.data, packetbuf.len);

						write_tun(tun_fd, out, outlen);

						packetbuf.len = packetbuf.offset = 0;
					}
				}
				if (outpacket.len > 0) {
					dnsd_send(dns_fd, &q, outpacket.data, outpacket.len);
					outpacket.len = 0;
					q.id = 0;
				}
			} 
		}
	}

	return 0;
}

static void
usage() {
	extern char *__progname;

	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] [-m mtu] [-l ip address to listen on] [-p port]"
			" tunnel_ip topdomain\n", __progname);
	exit(2);
}

static void
help() {
	extern char *__progname;

	printf("iodine IP over DNS tunneling server\n");
	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] [-m mtu] [-l ip address to listen on] [-p port]"
		   " tunnel_ip topdomain\n", __progname);
	printf("  -v to print version info and exit\n");
	printf("  -h to print this help and exit\n");
	printf("  -f to keep running in foreground\n");
	printf("  -u name to drop privileges and run as user 'name'\n");
	printf("  -t dir to chroot to directory dir\n");
	printf("  -d device to set tunnel device name\n");
	printf("  -m mtu to set tunnel device mtu\n");
	printf("  -l ip address to listen on for incoming dns traffic (default 0.0.0.0)\n");
	printf("  -p port to listen on for incoming dns traffic (default 53)\n");
	printf("tunnel_ip is the IP number of the local tunnel interface.\n");
	printf("topdomain is the FQDN that is delegated to this server.\n");
	exit(0);
}

static void
version() {
	printf("iodine IP over DNS tunneling server\n");
	printf("version: 0.3.4 from 2006-11-08\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	int choice;
	int tun_fd;
	int dnsd_fd;
	char *newroot;
	char *username;
	char *device;
	int foreground;
	int mtu;
	struct passwd *pw;
	in_addr_t listen_ip;
	int port;

	username = NULL;
	newroot = NULL;
	device = NULL;
	foreground = 0;
	mtu = 1024;
	listen_ip = INADDR_ANY;
	port = 53;

	packetbuf.len = 0;
	packetbuf.offset = 0;
	outpacket.len = 0;
	q.id = 0;
	
	while ((choice = getopt(argc, argv, "vfhu:t:d:m:l:p:")) != -1) {
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
		case 'm':
			mtu = atoi(optarg);
			break;
		case 'l':
			listen_ip = inet_addr(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if (geteuid() != 0) {
		printf("Run as root and you'll be happy.\n");
		usage();
	}

	if (argc != 2) 
		usage();

	if (username) {
		pw = getpwnam(username);
		if (!pw) {
			printf("User %s does not exist!\n", username);
			usage();
		}
	}

	if (mtu == 0) {
		printf("Bad MTU given.\n");
		usage();
	}

	if (listen_ip == INADDR_NONE) {
		printf("Bad IP address to listen on.\n");
		usage();
	}

	if ((tun_fd = open_tun(device)) == -1)
		goto cleanup0;
	if (tun_setip(argv[0]) != 0 || tun_setmtu(mtu) != 0)
		goto cleanup1;
	if ((dnsd_fd = open_dns(argv[1], port, listen_ip)) == -1) 
		goto cleanup2;

	my_ip = inet_addr(argv[0]);
	my_mtu = mtu;

	printf("Listening to dns for domain %s\n", argv[1]);

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

	signal(SIGINT, sigint);
	if (username) {
		if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			printf("Could not switch to user %s!\n", username);
			usage();
		}
	}
	
	tunnel(tun_fd, dnsd_fd);

cleanup2:
	close_dns(dnsd_fd);
cleanup1:
	close_tun(tun_fd);	
cleanup0:

	return 0;
}
