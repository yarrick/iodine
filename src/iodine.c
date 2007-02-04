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
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif

#include "common.h"
#include "dns.h"
#include "login.h"
#include "tun.h"
#include "version.h"

static void send_ping(int fd);

int running = 1;
char password[33];

struct sockaddr_in peer;
static char *topdomain;

uint16_t rand_seed;

/* Current IP packet */
static char activepacket[4096];
static int lastlen;
static int packetpos;
static int packetlen;
static uint16_t chunkid;

static void
sighandler(int sig) 
{
	running = 0;
}

static void
send_packet(int fd, char cmd, const char *data, const size_t datalen)
{
	char packet[4096];
	struct query q;
	char buf[4096];
	size_t len;

	q.id = rand_seed;
	q.type = T_NULL;

	buf[0] = cmd;
	
	len = dns_build_hostname(buf + 1, sizeof(buf) - 1, data, datalen, topdomain);
	len = dns_encode(packet, sizeof(packet), &q, QR_QUERY, buf, strlen(buf));

	sendto(fd, packet, len, 0, (struct sockaddr*)&peer, sizeof(peer));
}

static void
dns_send_chunk(int fd)
{
	char packet[4096];
	struct query q;
	char buf[4096];
	int avail;
	char *p;
	int len;

	q.id = rand_seed;
	q.type = T_NULL;

	p = activepacket;
	p += packetpos;
	avail = packetlen - packetpos;

	lastlen = dns_build_hostname(buf + 1, sizeof(buf) - 1, p, avail, topdomain);
	if (lastlen == avail)
		buf[0] = '1';
	else 
		buf[0] = '0';
		
	len = dns_encode(packet, sizeof(packet), &q, QR_QUERY, buf, strlen(buf));

	sendto(fd, packet, len, 0, (struct sockaddr*)&peer, sizeof(peer));
}

int
dns_sending()
{
	return (packetlen != 0);
}

int
dns_read(int fd, char *buf, int buflen)
{
	struct sockaddr_in from;
	char packet[64*1024];
	socklen_t addrlen;
	struct query q;
	int rv;
	int r;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);
	if(r == -1) {
		perror("recvfrom");
		return 0;
	}

	rv = dns_decode(buf, buflen, &q, QR_ANSWER, packet, r);

	if (dns_sending() && chunkid == q.id) {
		/* Got ACK on sent packet */
		packetpos += lastlen;
		if (packetpos == packetlen) {
			/* Packet completed */
			packetpos = 0;
			packetlen = 0;
			lastlen = 0;
		} else {
			/* More to send */
			dns_send_chunk(fd);
		}
	}
	return rv;
}


static int
tunnel_tun(int tun_fd, int dns_fd)
{
	char out[64*1024];
	char in[64*1024];
	unsigned long outlen;
	unsigned long inlen;
	size_t read;

	read = read_tun(tun_fd, in, sizeof(in));
	if(read > 0) {
		outlen = sizeof(out);
		inlen = read;
		compress2(out, &outlen, in, inlen, 9);
		
		memcpy(activepacket, out, MIN(outlen, sizeof(activepacket)));
		lastlen = 0;
		packetpos = 0;
		packetlen = outlen;

		dns_send_chunk(dns_fd);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	char out[64*1024];
	char in[64*1024];
	unsigned long outlen;
	unsigned long inlen;
	size_t read;

	read = dns_read(dns_fd, in, sizeof(in));
	if (read > 0) {
		outlen = sizeof(out);
		inlen = read;
		uncompress(out, &outlen, in, inlen);

		write_tun(tun_fd, out, outlen);
		if (!dns_sending()) 
			send_ping(dns_fd);
	}
	
	return read;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
	int rv;
	int i;

	rv = 0;

	while (running) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		if (!dns_sending()) 
			FD_SET(tun_fd, &fds);
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if (running == 0)
			break;

		if (i < 0) 
			err(1, "select");

		if (i == 0) /* timeout */
			send_ping(dns_fd);
		else {
			if (FD_ISSET(tun_fd, &fds)) {
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
			}
			if (FD_ISSET(dns_fd, &fds)) {
				if (tunnel_dns(tun_fd, dns_fd) <= 0)
					continue;
			} 
		}
	}

	return rv;
}

void
send_login(int fd, char *login, int len)
{
	char data[18];

	memset(data, 0, sizeof(data));
	memcpy(data, login, MIN(len, 16));

	data[16] = (rand_seed >> 8) & 0xff;
	data[17] = (rand_seed >> 0) & 0xff;
	
	rand_seed++;

	send_packet(fd, 'L', data, sizeof(data));
}

static void
send_ping(int fd)
{
	char data[2];
	
	if (dns_sending()) {
		lastlen = 0;
		packetpos = 0;
		packetlen = 0;
	}

	data[0] = (rand_seed >> 8) & 0xff;
	data[1] = (rand_seed >> 0) & 0xff;
	
	rand_seed++;

	send_packet(fd, 'P', data, sizeof(data));
}

void 
send_version(int fd, uint32_t version)
{
	char data[6];

	data[0] = (version >> 24) & 0xff;
	data[1] = (version >> 16) & 0xff;
	data[2] = (version >> 8) & 0xff;
	data[3] = (version >> 0) & 0xff;

	data[4] = (rand_seed >> 8) & 0xff;
	data[5] = (rand_seed >> 0) & 0xff;
	
	rand_seed++;

	send_packet(fd, 'V', data, sizeof(data));
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

		send_version(dns_fd, VERSION);
		
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
						printf("version ok, both running 0x%08x\n", VERSION);
						break;
					} else {
						printf("version ok but did not receive proper login challenge\n");
					}
				} else {
					memcpy(&version, in + 4, 4);
					version = ntohl(version);
					errx(1, "you run 0x%08x, server runs 0x%08x. giving up\n", 
							VERSION, version);
					/* NOTREACHED */
				}
			}
		}
		
		if (i == 4) 
			errx(1, "couldn't connect to server");
		
		printf("Retrying version check...\n");
	}
	
	login_calculate(login, 16, password, seed);
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_login(dns_fd, login, 16);
		
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

int 
set_target(const char *host) 
{
	struct hostent *h;

	// Init dns target struct
	if ((h = gethostbyname(host)) <= 0)
		err(1, "couldn't resovle name %s", host);

	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(53);
	peer.sin_addr = *((struct in_addr *) h->h_addr);

	return 0;
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
			/* NOTREACHED */
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

	topdomain = strdup(argv[1]);

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
	if ((dns_fd = open_dns(0, INADDR_ANY)) == -1)
		goto cleanup2;
	if (set_target(argv[0]) == -1)
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
