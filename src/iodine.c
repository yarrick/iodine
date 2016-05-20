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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
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
#include "version.h"
#include "tun.h"
#include "client.h"
#include "util.h"

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#endif

#if !defined(BSD) && !defined(__GLIBC__)
static char *__progname;
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
static void usage() __attribute__((noreturn));
#endif

static void
print_usage()
{
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-v] [-h] [-V sec] [-f] [-r] [-u user] [-t chrootdir] [-d device] "
			"[-w downfrags] [-W upfrags] [-i sec -j sec] [-I sec] [-c 0|1] [-C 0|1] [-s ms] "
			"[-P password] [-m maxfragsize] [-M maxlen] [-T type] [-O enc] [-L 0|1] [-R rdomain] "
			"[-z context] [-F pidfile] topdomain [nameserver1 [nameserver2 [...]]]\n", __progname);
}

static void
usage()
{
	print_usage();
	exit(2);
}

static void
help()
{
	fprintf(stderr, "iodine IP over DNS tunneling client\n");
	print_usage();
	fprintf(stderr, "\nOptions to try if connection doesn't work:\n");
	fprintf(stderr, "  -T force dns type: NULL, PRIVATE, TXT, SRV, MX, CNAME, A (default: autodetect)\n");
	fprintf(stderr, "  -O force downstream encoding for -T other than NULL: Base32, Base64, Base64u,\n");
	fprintf(stderr, "     Base128, or (only for TXT:) Raw  (default: autodetect)\n");
	fprintf(stderr, "  -I target interval between sending and receiving requests (default: 4 secs)\n");
	fprintf(stderr, "      or ping interval in immediate mode (default: 1 sec)\n");
	fprintf(stderr, "  -s minimum interval between queries (default: 0ms)\n");
	fprintf(stderr, "  -L 1: use lazy mode for low-latency (default). 0: don't (implies -I1)\n");
	fprintf(stderr, "  -m max size of downstream fragments (default: autodetect)\n");
	fprintf(stderr, "  -M max size of upstream hostnames (~100-255, default: 255)\n");
	fprintf(stderr, "  -r to skip raw UDP mode attempt\n");
	fprintf(stderr, "  -P password used for authentication (max 32 chars will be used)\n\n");

	fprintf(stderr, "Fine-tuning options:\n");
	fprintf(stderr, "  -w downstream fragment window size (default: 8 frags)\n");
	fprintf(stderr, "  -W upstream fragment window size (default: 8 frags)\n");
	fprintf(stderr, "  -i server-side request timeout in lazy mode (default: auto)\n");
	fprintf(stderr, "  -j downstream fragment ACK timeout, implies -i4 (default: 2 sec)\n");
	fprintf(stderr, "  -c 1: use downstream compression (default), 0: disable\n");
	fprintf(stderr, "  -C 1: use upstream compression (default), 0: disable\n\n");

	fprintf(stderr, "Other options:\n");
	fprintf(stderr, "  -v to print version info and exit\n");
	fprintf(stderr, "  -h to print this help and exit\n");
	fprintf(stderr, "  -V sec to print connection statistics at specified intervals\n");
	fprintf(stderr, "  -f to keep running in foreground\n");
	fprintf(stderr, "  -D enable debug mode (add more D's to increase debug level)\n");
	fprintf(stderr, "  -u name to drop privileges and run as user 'name'\n");
	fprintf(stderr, "  -t dir to chroot to directory dir\n");
	fprintf(stderr, "  -d device to set tunnel device name\n");
	fprintf(stderr, "  -z context, to apply specified SELinux context after initialization\n");
	fprintf(stderr, "  -R routing domain (OpenBSD only)\n");
	fprintf(stderr, "  -F pidfile to write pid to a file\n\n");

	fprintf(stderr, "nameserver is the IP/hostname of the relaying nameserver(s).\n");
	fprintf(stderr, "   multiple nameservers can be specified (used in round-robin). \n");
	fprintf(stderr, "   if absent, system default is used\n");
	fprintf(stderr, "topdomain is the FQDN that is delegated to the tunnel endpoint.\n");

	exit(0);
}

static void
version()
{
	fprintf(stderr, "iodine IP over DNS tunneling client\n");
	fprintf(stderr, "Git version: %s; protocol version %08X\n", GITREVISION, PROTOCOL_VERSION);
	exit(0);
}

int
main(int argc, char **argv)
{
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
	int hostname_maxlen;

	int retval;
	int raw_mode;
	int lazymode;
	int target_interval_ms;
	int server_timeout_ms;
	int downstream_timeout_ms;
	int min_interval_ms;
	int autodetect_server_timeout;
	int up_compression;
	int down_compression;

	int up_windowsize;
	int down_windowsize;

#ifdef OPENBSD
	int rtable = 0;
#endif

	char *nameserv_host;
	char **nameserv_hosts;
	int nameserv_hosts_len;
	struct sockaddr_storage nameservaddr;
	struct socket *nameserv_addrs;
	size_t nameserv_addrs_len;
	int nameservaddr_len;
	int nameserv_family;

	/* Set default values */
	nameserv_addrs_len = 0;
	nameservaddr_len = 0;
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
	debug = 0;
	stats = 0;

	autodetect_frag_size = 1;
	max_downstream_frag_size = 3072;
	retval = 0;
	raw_mode = 1;
	lazymode = 1;
	target_interval_ms = 5000;	/* DNS RFC says 5 seconds minimum */
	min_interval_ms = 0;
	server_timeout_ms = 4000;	/* Safe value for RTT <1s */
	downstream_timeout_ms = 2000;
	autodetect_server_timeout = 1;
	hostname_maxlen = 0xFF;
	nameserv_family = AF_UNSPEC;
	up_compression = 1;
	down_compression = 1;

	up_windowsize = 8;
	down_windowsize = 8;

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

	while ((choice = getopt(argc, argv, "46vfDhrs:V:c:C:i:j:u:t:d:R:P:w:W:m:M:F:T:O:L:I:")) != -1) {
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
		case 'V':
			stats = atoi(optarg);
			if (stats < 0)
				stats = 0;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'D':
			debug++;
			break;
		case 'h':
			help();
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
		case 'O':
			client_set_downenc(optarg);
			break;
		case 'L':
			lazymode = atoi(optarg);
			if (lazymode > 1)
				lazymode = 1;
			if (lazymode < 0)
				lazymode = 0;
			break;
		case 'I':
			target_interval_ms = strtod(optarg, NULL) * 1000;
			break;
		case 'i':
			server_timeout_ms = strtod(optarg, NULL) * 1000;
			autodetect_server_timeout = 0;
			break;
		case 'j':
			downstream_timeout_ms = strtod(optarg, NULL) * 1000;
			if (autodetect_server_timeout) {
				autodetect_server_timeout = 0;
				server_timeout_ms = 4000;
			}
			break;
		case 's':
			min_interval_ms = atoi(optarg);
			if (min_interval_ms < 0)
				min_interval_ms = 0;
		case 'w':
			down_windowsize = atoi(optarg);
			break;
		case 'W':
			up_windowsize = atoi(optarg);
			break;
		case 'C':
			up_compression = atoi(optarg) & 1;
			break;
		case 'c':
			down_compression = atoi(optarg) & 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	check_superuser(usage);

	argc -= optind;
	argv += optind;

	if (debug) {
		fprintf(stderr, "Debug level %d enabled, will stay in foreground.\n", debug);
		fprintf(stderr, "Add more -D switches to set higher debug level.\n");
		foreground = 1;
	}

	nameserv_hosts_len = argc - 1;
	if (nameserv_hosts_len <= 0)
		nameserv_hosts_len = 1;

	// Preallocate memory with expected number of hosts
	nameserv_hosts = malloc(sizeof(char *) * nameserv_hosts_len);
	nameserv_addrs = malloc(sizeof(struct socket) * nameserv_hosts_len);

	if (argc == 0) {
		usage();
		/* NOT REACHED */
	} else if (argc == 1) {
		nameserv_hosts[0] = get_resolvconf_addr();
	} else if (argc > 1) {
		for (int h = 0; h < nameserv_hosts_len; h++) {
			nameserv_hosts[h] = strdup(argv[h + 1]);
		}
	}
	topdomain = strdup(argv[0]);

	for (int n = 0; n < nameserv_hosts_len; n++) {
		nameserv_host = nameserv_hosts[n];
		if (!nameserv_host) {
			errx(1, "Error processing nameserver hostnames!\n");
		}
		nameservaddr_len = get_addr(nameserv_host, DNS_PORT, nameserv_family, 0, &nameservaddr);
		if (nameservaddr_len < 0) {
			errx(1, "Cannot lookup nameserver '%s': %s ",
					nameserv_host, gai_strerror(nameservaddr_len));
		}
		nameserv_addrs[n].length = nameservaddr_len;
		memcpy(&nameserv_addrs[n].addr, &nameservaddr, sizeof(struct sockaddr_storage));
		nameserv_addrs_len ++;
		nameserv_host = NULL;
	}

	if (nameserv_addrs_len <= 0 || !nameserv_hosts[0]) {
		warnx("No nameserver found - not connected to any network?\n");
		usage();
	}

	client_set_nameservers(nameserv_addrs, nameserv_addrs_len);

	if (max_downstream_frag_size < 1 || max_downstream_frag_size > 0xffff) {
		warnx("Use a max frag size between 1 and 65535 bytes.\n");
		usage();
		/* NOTREACHED */
	}

	if(check_topdomain(topdomain, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	if (up_windowsize < 1 || down_windowsize < 1) {
		warnx("Windowsize (-w or -W) must be greater than 0!");
		usage();
	}

	if (target_interval_ms < 100) {
		warnx("Target interval must be greater than 0.1 seconds!");
		usage();
	}

	if (server_timeout_ms < 100 || server_timeout_ms >= target_interval_ms) {
		warnx("Server timeout must be greater than 0.1 sec and less than target interval!");
		usage();
	}

	if (downstream_timeout_ms < 100) {
		warnx("Downstream fragment timeout must be more than 0.1 sec to prevent excessive retransmits.");
		usage();
	}

	if (!lazymode && target_interval_ms > 1000) {
		warnx("Warning: Target interval of >1 second in immediate mode will cause high latency.");
		usage();
	}

	client_set_compression(up_compression, down_compression);
	client_set_dnstimeout(target_interval_ms, server_timeout_ms, downstream_timeout_ms, autodetect_server_timeout);
	client_set_interval(target_interval_ms, min_interval_ms);
	client_set_lazymode(lazymode);
	client_set_topdomain(topdomain);
	client_set_hostname_maxlen(hostname_maxlen);
	client_set_windowsize(up_windowsize, down_windowsize);

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

	fprintf(stderr, "Sending DNS queries for %s to ", topdomain);
	for (int a = 0; a < nameserv_addrs_len; a++) {
		fprintf(stderr, "%s%s", format_addr(&nameserv_addrs[a].addr, nameserv_addrs[a].length),
				(a != nameserv_addrs_len-1) ?  ", " : "");
	}
	fprintf(stderr, "\n");

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

