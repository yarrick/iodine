/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#endif

#include "common.h"
#include "tun.h"
#include "client.h"
#include "util.h"

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#endif

#if !defined(BSD) && !defined(__GLIBC__)
static char *__progname;
#else
extern char *__progname;
#endif

#define PASSWORD_ENV_VAR "IODINE_PASS"

static void
sighandler(int sig)
{
	client_stop();
}

#if defined(__GNUC__) || defined(__clang__)
/* mark as no return to help some compilers to avoid warnings
 * about use of uninitialized variables */
static inline void usage(void) __attribute__((noreturn));
static inline void help(FILE * stream, bool verbose) __attribute__((noreturn));
#endif

static void help(FILE *stream, bool verbose)
{
	fprintf(stream,
		"iodine IP over DNS tunneling client\n\n"
		"Usage: %s [-46fhrv] [-u user] [-t chrootdir] [-d device] [-P password]\n"
		"              [-m maxfragsize] [-M maxlen] [-T type] [-O enc] [-L 0|1] [-I sec]\n"
		"              [-z context] [-F pidfile] [nameserver] topdomain\n", __progname);

	if (!verbose)
		exit(2);

	fprintf(stream,
		"\nOptions to try if connection doesn't work:\n"
		"  -4 to connect only to IPv4\n"
		"  -6 to connect only to IPv6\n"
		"  -T force dns type: NULL, PRIVATE, TXT, SRV, MX, CNAME, A (default: autodetect)\n"
		"  -O force downstream encoding for -T other than NULL: Base32, Base64, Base64u,\n"
		"     Base128, or (only for TXT:) Raw  (default: autodetect)\n"
		"  -I max interval between requests (default 4 sec) to prevent DNS timeouts\n"
		"  -L 1: use lazy mode for low-latency (default). 0: don't (implies -I1)\n"
		"  -m max size of downstream fragments (default: autodetect)\n"
		"  -M max size of upstream hostnames (~100-255, default: 255)\n"
		"  -r to skip raw UDP mode attempt\n"
		"  -P password used for authentication (max 32 chars will be used)\n\n"
		"Other options:\n"
		"  -v to print version info and exit\n"
		"  -h to print this help and exit\n"
		"  -f to keep running in foreground\n"
		"  -u name to drop privileges and run as user 'name'\n"
		"  -t dir to chroot to directory dir\n"
		"  -d device to set tunnel device name\n"
		"  -z context, to apply specified SELinux context after initialization\n"
		"  -F pidfile to write pid to a file\n\n"
		"nameserver is the IP number/hostname of the relaying nameserver. If absent,\n"
		"           /etc/resolv.conf is used\n"
		"topdomain is the FQDN that is delegated to the tunnel endpoint.\n");

	exit(0);
}

static inline void usage(void)
{
	help(stderr, false);
}

static void version(void)
{
	fprintf(stderr, "iodine IP over DNS tunneling client\n"
			"Git version: %s\n", GITREVISION);

	exit(0);
}

int main(int argc, char **argv)
{
	char *nameserv_host;
	char *topdomain;
	char *errormsg;
#ifndef WINDOWS32
	struct passwd *pw;
#endif
	char *username;
	char password[33];
	int foreground;
	char *newroot;
	char *context;
	char *device;
	char *pidfile;
	int choice;
	int tun_fd;
	int dns_fd;
	int max_downstream_frag_size;
	int autodetect_frag_size;
	int retval;
	int raw_mode;
	int lazymode;
	int selecttimeout;
	int hostname_maxlen;
#ifdef OPENBSD
	int rtable = 0;
#endif
	struct sockaddr_storage nameservaddr;
	int nameservaddr_len;
	int nameserv_family;

	nameserv_host = NULL;
	topdomain = NULL;
	errormsg = NULL;
#ifndef WINDOWS32
	pw = NULL;
#endif
	username = NULL;
	memset(password, 0, 33);
	srand(time(NULL));
	foreground = 0;
	newroot = NULL;
	context = NULL;
	device = NULL;
	pidfile = NULL;

	autodetect_frag_size = 1;
	max_downstream_frag_size = 3072;
	retval = 0;
	raw_mode = 1;
	lazymode = 1;
	selecttimeout = 4;
	hostname_maxlen = 0xFF;
	nameserv_family = AF_UNSPEC;

#ifdef WINDOWS32
	WSAStartup(req_version, &wsa_data);
#endif

	srand((unsigned) time(NULL));
	client_init();

#if !defined(BSD) && !defined(__GLIBC__)
	__progname = strrchr(argv[0], '/');
	if (__progname == NULL)
		__progname = argv[0];
	else
		__progname++;
#endif

	while ((choice = getopt(argc, argv, "46vfhru:t:d:R:P:m:M:F:T:O:L:I:")) != -1) {
		switch(choice) {
		case '4':
			nameserv_family = AF_INET;
			break;
		case '6':
			nameserv_family = AF_INET6;
			break;
		case 'v':
			version();
			/* NOTREACHED */
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help(stdout, true);
			/* NOTREACHED */
			break;
		case 'r':
			raw_mode = 0;
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
#ifdef OPENBSD
		case 'R':
			rtable = atoi(optarg);
			break;
#endif
		case 'P':
			strncpy(password, optarg, sizeof(password));
			password[sizeof(password)-1] = 0;

			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg));
			break;
		case 'm':
			autodetect_frag_size = 0;
			max_downstream_frag_size = atoi(optarg);
			break;
		case 'M':
			hostname_maxlen = atoi(optarg);
			if (hostname_maxlen > 255)
				hostname_maxlen = 255;
			if (hostname_maxlen < 10)
				hostname_maxlen = 10;
			break;
		case 'z':
			context = optarg;
			break;
		case 'F':
			pidfile = optarg;
			break;
		case 'T':
			if (client_set_qtype(optarg))
				errx(5, "Invalid query type '%s'", optarg);
			break;
		case 'O':       /* not -D, is Debug in server */
			client_set_downenc(optarg);
			break;
		case 'L':
			lazymode = atoi(optarg);
			if (lazymode > 1)
				lazymode = 1;
			if (lazymode < 0)
				lazymode = 0;
			if (!lazymode)
				selecttimeout = 1;
			break;
		case 'I':
			selecttimeout = atoi(optarg);
			if (selecttimeout < 1)
				selecttimeout = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	check_superuser();

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		nameserv_host = get_resolvconf_addr();
		topdomain = strdup(argv[0]);
		break;
	case 2:
		nameserv_host = argv[0];
		topdomain = strdup(argv[1]);
		break;
	default:
		usage();
		/* NOTREACHED */
	}

	if (max_downstream_frag_size < 1 || max_downstream_frag_size > 0xffff) {
		warnx("Use a max frag size between 1 and 65535 bytes.\n");
		usage();
		/* NOTREACHED */
	}

	if (nameserv_host) {
		nameservaddr_len = get_addr(nameserv_host, DNS_PORT, nameserv_family, 0, &nameservaddr);
		if (nameservaddr_len < 0) {
			errx(1, "Cannot lookup nameserver '%s': %s ",
				nameserv_host, gai_strerror(nameservaddr_len));
		}
		client_set_nameserver(&nameservaddr, nameservaddr_len);
	} else {
		warnx("No nameserver found - not connected to any network?\n");
		usage();
		/* NOTREACHED */
	}

	if (check_topdomain(topdomain, 0, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	client_set_selecttimeout(selecttimeout);
	client_set_lazymode(lazymode);
	client_set_topdomain(topdomain);
	client_set_hostname_maxlen(hostname_maxlen);

	if (username != NULL) {
#ifndef WINDOWS32
		if ((pw = getpwnam(username)) == NULL) {
			warnx("User %s does not exist!\n", username);
			usage();
			/* NOTREACHED */
		}
#endif
	}

	if (strlen(password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(password, sizeof(password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(password, sizeof(password));
	}

	client_set_password(password);

	if ((tun_fd = open_tun(device)) == -1) {
		retval = 1;
		goto cleanup1;
	}
	if ((dns_fd = open_dns_from_host(NULL, 0, nameservaddr.ss_family, AI_PASSIVE)) < 0) {
		retval = 1;
		goto cleanup2;
	}
#ifdef OPENBSD
	if (rtable > 0)
		socket_setrtable(dns_fd, rtable);
#endif

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	fprintf(stderr, "Sending DNS queries for %s to %s\n",
		topdomain, format_addr(&nameservaddr, nameservaddr_len));

	if (client_handshake(dns_fd, raw_mode, autodetect_frag_size, max_downstream_frag_size)) {
		retval = 1;
		goto cleanup2;
	}

	if (client_get_conn() == CONN_RAW_UDP) {
		fprintf(stderr, "Sending raw traffic directly to %s\n", client_get_raw_addr());
	}

	fprintf(stderr, "Connection setup complete, transmitting data.\n");

	if (foreground == 0)
		do_detach();

	if (pidfile != NULL)
		do_pidfile(pidfile);

	if (newroot != NULL)
		do_chroot(newroot);

	if (username != NULL) {
#ifndef WINDOWS32
		gid_t gids[1];
		gids[0] = pw->pw_gid;
		if (setgroups(1, gids) < 0 || setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			warnx("Could not switch to user %s!\n", username);
			usage();
			/* NOTREACHED */
		}
#endif
	}

	if (context != NULL)
		do_setcon(context);

	client_tunnel(tun_fd, dns_fd);

cleanup2:
	close_dns(dns_fd);
	close_tun(tun_fd);
cleanup1:

	return retval;
}

