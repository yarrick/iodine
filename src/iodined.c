/*
 * Copyright (c) 2006-2007 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <err.h>
#include <time.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <zlib.h>

#include "common.h"
#include "dns.h"
#include "encoding.h"
#include "base32.h"
#include "user.h"
#include "login.h"
#include "tun.h"
#include "version.h"

static int running = 1;
static char *topdomain;
static char password[33];
static struct encoder *b32;

static int my_mtu;
static in_addr_t my_ip;

static int read_dns(int, struct query *, char *, int);
static void write_dns(int, struct query *, char *, int);

static void
sigint(int sig) 
{
	running = 0;
}

static int
tunnel_tun(int tun_fd, int dns_fd)
{
	unsigned long outlen;
	struct ip *header;
	char out[64*1024];
	char in[64*1024];
	int userid;
	int read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return 0;
	
	/* find target ip in packet, in is padded with 4 bytes TUN header */
	header = (struct ip*) (in + 4);
	userid = find_user_by_ip(header->ip_dst.s_addr);
	if (userid < 0)
		return 0;

	outlen = sizeof(out);
	compress2((uint8_t*)out, &outlen, (uint8_t*)in, read, 9);

	/* if another packet is queued, throw away this one. TODO build queue */
	if (users[userid].outpacket.len == 0) {
		memcpy(users[userid].outpacket.data, out, outlen);
		users[userid].outpacket.len = outlen;
		return outlen;
	} else {
		return 0;
	}
}

typedef enum {
	VERSION_ACK,
	VERSION_NACK,
	VERSION_FULL
} version_ack_t;

static void
send_version_response(int fd, version_ack_t ack, uint32_t payload, struct user *u)
{
	char out[9];
	
	switch (ack) {
	case VERSION_ACK:
		strncpy(out, "VACK", sizeof(out));
		break;
	case VERSION_NACK:
		strncpy(out, "VNAK", sizeof(out));
		break;
	case VERSION_FULL:
		strncpy(out, "VFUL", sizeof(out));
		break;
	}
	
	out[4] = ((payload >> 24) & 0xff);
	out[5] = ((payload >> 16) & 0xff);
	out[6] = ((payload >> 8) & 0xff);
	out[7] = ((payload) & 0xff);
	out[8] = u->id;


	write_dns(fd, &u->q, out, sizeof(out));
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	struct in_addr tempip;
	struct user dummy;
	struct ip *hdr;
	unsigned long outlen;
	char logindata[16];
	char out[64*1024];
	char in[64*1024];
	char unpacked[64*1024];
	char *tmp[2];
	int userid;
	int touser;
	int version;
	int read;
	int code;

	userid = -1;
	if ((read = read_dns(dns_fd, &(dummy.q), in, sizeof(in))) <= 0)
		return 0;
				
	if(in[0] == 'V' || in[0] == 'v') {
		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), read - 1, b32);
		/* Version greeting, compare and send ack/nak */
		if (read > 4) { 
			/* Received V + 32bits version */
			version = (((unpacked[0] & 0xff) << 24) |
					   ((unpacked[1] & 0xff) << 16) |
					   ((unpacked[2] & 0xff) << 8) |
					   ((unpacked[3] & 0xff)));
		}

		if (version == VERSION) {
			userid = find_available_user();
			if (userid >= 0) {
				users[userid].seed = rand();
				memcpy(&(users[userid].host), &(dummy.q.from), dummy.q.fromlen);
				memcpy(&(users[userid].q), &(dummy.q), sizeof(struct query));
				users[userid].addrlen = dummy.q.fromlen;
				users[userid].encoder = get_base32_encoder();
				send_version_response(dns_fd, VERSION_ACK, users[userid].seed, &users[userid]);
				users[userid].q.id = 0;
			} else {
				/* No space for another user */
				send_version_response(dns_fd, VERSION_FULL, USERS, &dummy);
			}
		} else {
			send_version_response(dns_fd, VERSION_NACK, VERSION, &dummy);
		}
	} else if(in[0] == 'L' || in[0] == 'l') {
		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), read - 1, b32);
		/* Login phase, handle auth */
		userid = unpacked[0];
		if (userid < 0 || userid >= USERS) {
			write_dns(dns_fd, &(dummy.q), "BADIP", 5);
			return 0; /* illegal id */
		}
		users[userid].last_pkt = time(NULL);
		login_calculate(logindata, 16, password, users[userid].seed);

		if (dummy.q.fromlen != users[userid].addrlen ||
				memcmp(&(users[userid].host), &(dummy.q.from), dummy.q.fromlen) != 0) {
			write_dns(dns_fd, &(dummy.q), "BADIP", 5);
		} else {
			if (read >= 18 && (memcmp(logindata, unpacked+1, 16) == 0)) {
				/* Login ok, send ip/mtu info */

				tempip.s_addr = my_ip;
				tmp[0] = strdup(inet_ntoa(tempip));
				tempip.s_addr = users[userid].tun_ip;
				tmp[1] = strdup(inet_ntoa(tempip));

				read = snprintf(out, sizeof(out), "%s-%s-%d", 
						tmp[0], tmp[1], my_mtu);

				write_dns(dns_fd, &(dummy.q), out, read);
				dummy.q.id = 0;

				free(tmp[1]);
				free(tmp[0]);
			} else {
				write_dns(dns_fd, &(dummy.q), "LNAK", 4);
			}
		}
	} else if(in[0] == 'P' || in[0] == 'p') {
		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), read - 1, b32);
		/* Ping packet, store userid */
		userid = unpacked[0];
		if (userid < 0 || userid >= USERS) {
			write_dns(dns_fd, &(dummy.q), "BADIP", 5);
			return 0; /* illegal id */
		}
		memcpy(&(users[userid].q), &(dummy.q), sizeof(struct query));
		users[userid].last_pkt = time(NULL);
	} else if(in[0] == 'Z' || in[0] == 'z') {
		/* Case conservation check */

		/* Reply with received hostname as data */
		write_dns(dns_fd, &(dummy.q), in, read);
		return 0;
	} else if((in[0] >= '0' && in[0] <= '9')
			|| (in[0] >= 'a' && in[0] <= 'f')
			|| (in[0] >= 'A' && in[0] <= 'F')) {
		if ((in[0] >= '0' && in[0] <= '9'))
			code = in[0] - '0';
		if ((in[0] >= 'a' && in[0] <= 'f'))
			code = in[0] - 'a' + 10;
		if ((in[0] >= 'A' && in[0] <= 'F'))
			code = in[0] - 'A' + 10;

		userid = code >> 1;
		if (userid < 0 || userid >= USERS) {
			write_dns(dns_fd, &(dummy.q), "BADIP", 5);
			return 0; /* illegal id */
		}

		/* Check sending ip number */
		if (dummy.q.fromlen != users[userid].addrlen ||
				memcmp(&(users[userid].host), &(dummy.q.from), dummy.q.fromlen) != 0) {
			write_dns(dns_fd, &(dummy.q), "BADIP", 5);
		} else {
			/* decode with this users encoding */
			read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), read - 1, 
					   users[userid].encoder);

			users[userid].last_pkt = time(NULL);
			memcpy(&(users[userid].q), &(dummy.q), sizeof(struct query));
			users[userid].addrlen = dummy.q.fromlen;
			memcpy(users[userid].inpacket.data + users[userid].inpacket.offset, unpacked, read);
			users[userid].inpacket.len += read;
			users[userid].inpacket.offset += read;

			if (code & 1) {
				outlen = sizeof(out);
				uncompress((uint8_t*)out, &outlen, 
						   (uint8_t*)users[userid].inpacket.data, users[userid].inpacket.len);

				hdr = (struct ip*) (out + 4);
				touser = find_user_by_ip(hdr->ip_dst.s_addr);

				if (touser == -1) {
					/* send the uncompressed packet to tun device */
					write_tun(tun_fd, out, outlen);
				} else {
					/* send the compressed packet to other client
					 * if another packet is queued, throw away this one. TODO build queue */
					if (users[touser].outpacket.len == 0) {
						memcpy(users[touser].outpacket.data, users[userid].inpacket.data, users[userid].inpacket.len);
						users[touser].outpacket.len = users[userid].inpacket.len;
					}
				}
				users[userid].inpacket.len = users[userid].inpacket.offset = 0;
			}
		}
	}
	/* userid must be set for a reply to be sent */
	if (userid >= 0 && userid < USERS && dummy.q.fromlen == users[userid].addrlen &&
			memcmp(&(users[userid].host), &(dummy.q.from), dummy.q.fromlen) == 0 &&
			users[userid].outpacket.len > 0) {

		write_dns(dns_fd, &(dummy.q), users[userid].outpacket.data, users[userid].outpacket.len);
		users[userid].outpacket.len = 0;
		users[userid].q.id = 0;
	}

	return 0;
}

static int
tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
	int i;
	int j;

	while (running) {
		if (users_waiting_on_reply()) {
			tv.tv_sec = 0;
			tv.tv_usec = 5000;
		} else {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}

		FD_ZERO(&fds);
		/* TODO : use some kind of packet queue */
		if(!all_users_waiting_to_send()) {
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if(i < 0) {
			if (running) 
				warn("select");
			return 1;
		}
	
		if (i==0) {	
			for (j = 0; j < USERS; j++) {
				if (users[j].q.id != 0) {
					write_dns(dns_fd, &(users[j].q), users[j].outpacket.data, users[j].outpacket.len);
					users[j].outpacket.len = 0;
					users[j].q.id = 0;
				}
			}
		} else {
			if(FD_ISSET(tun_fd, &fds)) {
				tunnel_tun(tun_fd, dns_fd);
				continue;
			}
			if(FD_ISSET(dns_fd, &fds)) {
				tunnel_dns(tun_fd, dns_fd);
				continue;
			} 
		}
	}

	return 0;
}

static int
read_dns(int fd, struct query *q, char *buf, int buflen)
{
	struct sockaddr_in from;
	char packet[64*1024];
	char *domain;
	socklen_t addrlen;
	int rv;
	int r;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

	if (r > 0) {
		dns_decode(buf, buflen, q, QR_QUERY, packet, r);
		domain = strstr(q->name, topdomain);
		if (domain) {
			rv = (int) (domain - q->name); 
			memcpy(buf, q->name, MIN(rv, buflen));
			q->fromlen = addrlen;
			memcpy((struct sockaddr*)&q->from, (struct sockaddr*)&from, addrlen);
		} else {
			rv = 0;
		}
	} else if (r < 0) { 
		/* Error */
		warn("read dns");
		rv = 0;
	}

	return rv;
}

static void
write_dns(int fd, struct query *q, char *data, int datalen)
{
	char buf[64*1024];
	int len;

	len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, data, datalen);
	
	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

static void
usage() {
	extern char *__progname;

	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] [-m mtu] "
		"[-l ip address to listen on] [-p port] [-P password]"
		" tunnel_ip topdomain\n", __progname);
	exit(2);
}

static void
help() {
	extern char *__progname;

	printf("iodine IP over DNS tunneling server\n");
	printf("Usage: %s [-v] [-h] [-f] [-u user] [-t chrootdir] [-d device] [-m mtu] "
		"[-l ip address to listen on] [-p port] [-P password]"
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
	printf("  -P password used for authentication (max 32 chars will be used)\n");
	printf("tunnel_ip is the IP number of the local tunnel interface.\n");
	printf("topdomain is the FQDN that is delegated to this server.\n");
	exit(0);
}

static void
version() {
	printf("iodine IP over DNS tunneling server\n");
	printf("version: 0.4.1 from 2007-11-30\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	in_addr_t listen_ip;
	struct passwd *pw;
	int foreground;
	char *username;
	char *newroot;
	char *device;
	int dnsd_fd;
	int tun_fd;
	int choice;
	int port;
	int mtu;

	username = NULL;
	newroot = NULL;
	device = NULL;
	foreground = 0;
	mtu = 1024;
	listen_ip = INADDR_ANY;
	port = 53;

	b32 = get_base32_encoder();

	memset(password, 0, sizeof(password));
	srand(time(NULL));
	
	while ((choice = getopt(argc, argv, "vfhu:t:d:m:l:p:P:")) != -1) {
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
			if (port) {
				printf("ALERT! Other dns servers expect you to run on port 53.\n");
				printf("You must manually forward port 53 to port %d for things to work.\n", port);
			}
			break;
		case 'P':
			strncpy(password, optarg, sizeof(password));
			password[sizeof(password)-1] = 0;
			
			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg)); 
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (geteuid() != 0) {
		warnx("Run as root and you'll be happy.\n");
		usage();
	}

	if (argc != 2) 
		usage();

	topdomain = strdup(argv[1]);
	if (strlen(topdomain) > 128 || topdomain[0] == '.') {
		warnx("Use a topdomain max 128 chars long. Do not start it with a dot.\n");
		usage();
	}

	if (username != NULL) {
		if ((pw = getpwnam(username)) == NULL) {
			warnx("User %s does not exist!\n", username);
			usage();
		}
	}

	if (mtu == 0) {
		warnx("Bad MTU given.\n");
		usage();
	}

	if (listen_ip == INADDR_NONE) {
		warnx("Bad IP address to listen on.\n");
		usage();
	}

	if (strlen(password) == 0)
		read_password(password, sizeof(password));

	if ((tun_fd = open_tun(device)) == -1)
		goto cleanup0;
	if (tun_setip(argv[0]) != 0 || tun_setmtu(mtu) != 0)
		goto cleanup1;
	if ((dnsd_fd = open_dns(port, listen_ip)) == -1) 
		goto cleanup2;

	my_ip = inet_addr(argv[0]);
	my_mtu = mtu;
	init_users(my_ip);

	printf("Listening to dns for domain %s\n", topdomain);

	if (foreground == 0) 
		do_detach();
	
	if (newroot != NULL)
		do_chroot(newroot);

	signal(SIGINT, sigint);
	if (username != NULL) {
		if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			warnx("Could not switch to user %s!\n", username);
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
