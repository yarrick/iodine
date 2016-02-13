/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015 Frekk van Blagh <frekk@frekkworks.com>
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
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <zlib.h>
#include <getopt.h>

#include "common.h"
#include "version.h"

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <err.h>
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#define _XPG4_2
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <grp.h>
#include <sys/uio.h>
#include <pwd.h>
#include <netdb.h>
#include <syslog.h>
#endif

#include "dns.h"
#include "encoding.h"
#include "base32.h"
#include "base64.h"
#include "base64u.h"
#include "base128.h"
#include "user.h"
#include "login.h"
#include "tun.h"
#include "fw_query.h"
#include "version.h"
#include "server.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;

#define	LOG_EMERG	0
#define	LOG_ALERT	1
#define	LOG_CRIT	2
#define	LOG_ERR		3
#define	LOG_WARNING	4
#define	LOG_NOTICE	5
#define	LOG_INFO	6
#define	LOG_DEBUG	7
static void
syslog(int a, const char *str, ...)
{
	/* TODO: implement (add to event log), move to common.c */
	;
}
#endif

/* Definition of main server instance */
struct server_instance server;

static struct server_instance preset_default = {
	.check_ip = 1,
	.netmask = 27,
	.ns_ip = INADDR_ANY,
	.mtu = 1130,	/* Very many relays give fragsize 1150 or slightly
			   higher for NULL; tun/zlib adds ~17 bytes. */
	.port = 53,
	.addrfamily = AF_UNSPEC,

	/* Mark both file descriptors as unused */
	.dns_fds.v4fd = -1,
	.dns_fds.v6fd = -1
};

/* Ask ipify.org webservice to get external ip */
static int
get_external_ip(struct in_addr *ip)
{
	int sock;
	struct addrinfo *addr;
	int res;
	const char *getstr = "GET / HTTP/1.0\r\n"
		/* HTTP 1.0 to avoid chunked transfer coding */
		"Host: api.ipify.org\r\n\r\n";
	char buf[512];
	char *b;
	int len;

	res = getaddrinfo("api.ipify.org", "80", NULL, &addr);
	if (res < 0) return 1;

	sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (sock < 0) {
		freeaddrinfo(addr);
		return 2;
	}

	res = connect(sock, addr->ai_addr, addr->ai_addrlen);
	freeaddrinfo(addr);
	if (res < 0) return 3;

	res = write(sock, getstr, strlen(getstr));
	if (res != strlen(getstr)) return 4;

	/* Zero buf before receiving, leave at least one zero at the end */
	memset(buf, 0, sizeof(buf));
	res = read(sock, buf, sizeof(buf) - 1);
	if (res < 0) return 5;
	len = res;

	res = close(sock);
	if (res < 0) return 6;

	b = buf;
	while (len > 9) {
		/* Look for split between headers and data */
		if (strncmp("\r\n\r\n", b, 4) == 0) break;
		b++;
		len--;
	}
	if (len < 10) return 7;
	b += 4;

	res = inet_aton(b, ip);
	return (res == 0);
}

static void
sigint(int sig)
{
	server.running = 0;
}

static void
print_usage() {
	extern char *__progname;

	fprintf(stderr, "Usage: %s [options] [-v] [-h] [-4] [-6] [-c] [-s] [-f] [-D] "
		"[-u user] [-d device] [-m mtu] "
		"[-l ipv4 listen address] [-L ipv6 listen address] [-p port] "
		"[-n external ip] [-b dnsport] [-P password] [-F pidfile] "
		"[-i max idle time] tunnel_ip[/netmask] topdomain\n", __progname);
}

static void
usage() {
	print_usage();
	exit(2);
}

static void
help() {
	fprintf(stderr, "iodine IP over DNS tunneling server\n");
	print_usage();
	fprintf(stderr, "  -v, --version  print version info and exit\n");
	fprintf(stderr, "  -h, --help  print this help and exit\n");
	fprintf(stderr, "  -4  listen only on IPv4\n");
	fprintf(stderr, "  -6  listen only on IPv6\n");
	fprintf(stderr, "  -c, --noipcheck  disable check of client IP/port on each request\n");
	fprintf(stderr, "  -s, --notun  skip creating and configuring the tun device, "
		"which then has to be created manually\n");
	fprintf(stderr, "  -f  to keep running in foreground\n");
	fprintf(stderr, "  -D  increase debug level\n");
	fprintf(stderr, "     (using -DD in UTF-8 terminal: \"LC_ALL=C luit iodined -DD ...\")\n");
	fprintf(stderr, "  -u, --user  drop privileges and run as user\n");
	fprintf(stderr, "  --chrootdir  chroot to directory after init\n");
	fprintf(stderr, "  -d  specify tunnel device name\n");
	fprintf(stderr, "  -m, --mtu  specify tunnel device mtu\n");
	fprintf(stderr, "  --context  apply SELinux context after initialization\n");
	fprintf(stderr, "  -l, --listen4  IPv4 address to listen on for incoming dns traffic "
		"(default 0.0.0.0)\n");
	fprintf(stderr, "  -L, --listen6  IPv6 address to listen on for incoming dns traffic "
		"(default ::)\n");
	fprintf(stderr, "  -p  port to listen on for incoming dns traffic (default 53)\n");
	fprintf(stderr, "  -n, --nsip  ip to respond with to NS queries\n");
	fprintf(stderr, "  -b, --forwardto  forward normal DNS queries to a UDP port on localhost\n");
	fprintf(stderr, "  -A, --localforward  allow TCP data pipe to local ports only (default: disabled)\n");
	fprintf(stderr, "  -R, --remoteforward  allow TCP data pipe to remote hosts (default: disabled)\n");
	fprintf(stderr, "  -P  password used for authentication (max 32 chars will be used)\n");
	fprintf(stderr, "  -F, --pidfile  write pid to a file\n");
	fprintf(stderr, "  -i, --idlequit  maximum idle time before shutting down\n");
	fprintf(stderr, "tunnel_ip is the IP number of the local tunnel interface.\n");
	fprintf(stderr, "   /netmask sets the size of the tunnel network.\n");
	fprintf(stderr, "topdomain is the FQDN that is delegated to this server.\n");
	exit(0);
}

static void
version() {
	fprintf(stderr, "iodine IP over DNS tunneling server\n");
	fprintf(stderr, "Git version: %s; protocol version %08X\n", GITREVISION, PROTOCOL_VERSION);
	exit(0);
}

static void
prepare_dns_fd(int fd)
{
#ifndef WINDOWS32
	int flag = 1;

	/* To get destination address from each UDP datagram, see read_dns() */
	setsockopt(fd, IPPROTO_IP, DSTADDR_SOCKOPT, (const void*) &flag, sizeof(flag));
#ifdef IPV6_RECVPKTINFO
	setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void*) &flag, sizeof(flag));
#endif
#ifdef IPV6_PKTINFO
	setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, (const void*) &flag, sizeof(flag));
#endif

#endif
}

int
main(int argc, char **argv)
{
	extern char *__progname;
	char *listen_ip4;
	char *listen_ip6;
	char *errormsg;
#ifndef WINDOWS32
	struct passwd *pw = NULL;
#endif
	int foreground;
	char *username;
	char *newroot;
	char *context;
	char *device;
	char *pidfile;

	int choice;

	int skipipconfig;
	char *netsize;
	int ns_get_externalip;
	int retval;

#ifdef HAVE_SYSTEMD
	int nb_fds;
#endif

	errormsg = NULL;
	username = NULL;
	newroot = NULL;
	context = NULL;
	device = NULL;
	foreground = 0;
	listen_ip4 = NULL;
	listen_ip6 = NULL;

	ns_get_externalip = 0;
	skipipconfig = 0;
	pidfile = NULL;
	srand(time(NULL));

	retval = 0;

#ifdef WINDOWS32
	WSAStartup(req_version, &wsa_data);
#endif

#if !defined(BSD) && !defined(__GLIBC__)
	__progname = strrchr(argv[0], '/');
	if (__progname == NULL)
		__progname = argv[0];
	else
		__progname++;
#endif

	// Load default values from preset
	memcpy(&server, &preset_default, sizeof(struct server_instance));

	/* each option has format:
	   char *name, int has_arg, int *flag, int val */
	static struct option iodined_args[] = {
		{"version", no_argument, 0, 'v'},
		{"noipcheck", no_argument, 0, 'c'},
		{"notun", no_argument, 0, 's'},
		{"user", required_argument, 0, 'u'},
		{"listen4", required_argument, 0, 'l'},
		{"listen6", required_argument, 0, 'L'},
		{"nsip", required_argument, 0, 'n'},
		{"mtu", required_argument, 0, 'm'},
		{"idlequit", required_argument, 0, 'i'},
		{"forwardto", required_argument, 0, 'b'},
		{"localforward", no_argument, 0, 'A'},
		{"remoteforward", no_argument, 0, 'R'},
		{"help", no_argument, 0, 'h'},
		{"context", required_argument, 0, 'z'},
		{"chrootdir", required_argument, 0, 't'},
		{"pidfile", required_argument, 0, 'F'},
		{NULL, 0, 0, 0}
	};

	static char *iodined_args_short = "46vcsfhDARu:t:d:m:l:L:p:n:b:P:z:F:i:";

	server.running = 1;

	while ((choice = getopt_long(argc, argv, iodined_args_short, iodined_args, NULL)) != -1) {
		switch(choice) {
		case '4':
			server.addrfamily = AF_INET;
			break;
		case '6':
			server.addrfamily = AF_INET6;
			break;
		case 'v':
			version();
			break;
		case 'c':
			server.check_ip = 0;
			break;
		case 's':
			skipipconfig = 1;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help();
			break;
		case 'D':
			server.debug++;
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
			server.mtu = atoi(optarg);
			break;
		case 'l':
			listen_ip4 = optarg;
			break;
		case 'L':
			listen_ip6 = optarg;
			break;
		case 'p':
			server.port = atoi(optarg);
			break;
		case 'n':
			if (optarg && strcmp("auto", optarg) == 0) {
				ns_get_externalip = 1;
			} else {
				server.ns_ip = inet_addr(optarg);
			}
			break;
		case 'b':
			server.bind_enable = 1;
			server.bind_port = atoi(optarg);
			break;
		case 'A':
			server.allow_forward_local_port = 1;
			break;
		case 'R':
			server.allow_forward_local_port = 1;
			server.allow_forward_remote = 1;
			break;
		case 'F':
			pidfile = optarg;
			break;
		case 'i':
			server.max_idle_time = atoi(optarg);
			break;
		case 'P':
			strncpy(server.password, optarg, sizeof(server.password));
			server.password[sizeof(server.password)-1] = 0;

			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg));
			break;
		case 'z':
			context = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	check_superuser(usage);

	if (argc != 2)
		usage();

	netsize = strchr(argv[0], '/');
	if (netsize) {
		*netsize = 0;
		netsize++;
		server.netmask = atoi(netsize);
	}

	server.my_ip = inet_addr(argv[0]);

	if (server.my_ip == INADDR_NONE) {
		warnx("Bad IP address to use inside tunnel.");
		usage();
	}

	server.topdomain = strdup(argv[1]);
	if(check_topdomain(server.topdomain, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	if (username != NULL) {
#ifndef WINDOWS32
		if ((pw = getpwnam(username)) == NULL) {
			warnx("User %s does not exist!", username);
			usage();
		}
#endif
	}

	if (server.mtu <= 0) {
		warnx("Bad MTU given.");
		usage();
	}

	if(server.port < 1 || server.port > 65535) {
		warnx("Bad port number given.");
		usage();
	}

	if (server.port != 53) {
		fprintf(stderr, "ALERT! Other dns servers expect you to run on port 53.\n");
		fprintf(stderr, "You must manually forward port 53 to port %d for things to work.\n", server.port);
	}

	if (server.debug) {
		fprintf(stderr, "Debug level %d enabled, will stay in foreground.\n", server.debug);
		fprintf(stderr, "Add more -D switches to set higher debug level.\n");
		foreground = 1;
	}

	if (server.addrfamily == AF_UNSPEC || server.addrfamily == AF_INET) {
		server.dns4addr_len = get_addr(listen_ip4, server.port, AF_INET,
									   AI_PASSIVE | AI_NUMERICHOST, &server.dns4addr);
		if (server.dns4addr_len < 0) {
			warnx("Bad IPv4 address to listen on.");
			usage();
		}
	}
	if (server.addrfamily == AF_UNSPEC || server.addrfamily == AF_INET6) {
		server.dns6addr_len = get_addr(listen_ip6, server.port, AF_INET6,
									   AI_PASSIVE | AI_NUMERICHOST, &server.dns6addr);
		if (server.dns6addr_len < 0) {
			warnx("Bad IPv6 address to listen on.");
			usage();
		}
	}
	if (server.bind_enable) {
		in_addr_t dns_ip = ((struct sockaddr_in *) &server.dns4addr)->sin_addr.s_addr;
		if (server.bind_port < 1 || server.bind_port > 65535) {
			warnx("Bad DNS server port number given.");
			usage();
			/* NOTREACHED */
		}
		/* Avoid forwarding loops */
		if (server.bind_port == server.port && (dns_ip == INADDR_ANY || dns_ip == INADDR_LOOPBACK)) {
			warnx("Forward port is same as listen port (%d), will create a loop!", server.bind_port);
			fprintf(stderr, "Use -l to set listen ip to avoid this.\n");
			usage();
			/* NOTREACHED */
		}
		fprintf(stderr, "Requests for domains outside of %s will be forwarded to port %d\n",
				server.topdomain, server.bind_port);
	}

	if (ns_get_externalip) {
		struct in_addr extip;
		int res = get_external_ip(&extip);
		if (res) {
			fprintf(stderr, "Failed to get external IP via web service.\n");
			exit(3);
		}
		server.ns_ip = extip.s_addr;
		fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(extip));
	}

	if (server.ns_ip == INADDR_NONE) {
		warnx("Bad IP address to return as nameserver.");
		usage();
	}
	if (server.netmask > 30 || server.netmask < 8) {
		warnx("Bad netmask (%d bits). Use 8-30 bits.", server.netmask);
		usage();
	}

	if (strlen(server.password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(server.password, sizeof(server.password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(server.password, sizeof(server.password));
	}

	created_users = init_users(server.my_ip, server.netmask);

	if ((server.tun_fd = open_tun(device)) == -1) {
		/* nothing to clean up, just return */
		return 1;
	}
	if (!skipipconfig) {
		const char *other_ip = users_get_first_ip();
		if (tun_setip(argv[0], other_ip, server.netmask) != 0 || tun_setmtu(server.mtu) != 0) {
			retval = 1;
			free((void*) other_ip);
			goto cleanup;
		}
		free((void*) other_ip);
	}

#ifdef HAVE_SYSTEMD
	nb_fds = sd_listen_fds(0);
	if (nb_fds > 1) {
		retval = 1;
		warnx("Too many file descriptors received!\n");
		goto cleanup;
	} else if (nb_fds == 1) {
		/* XXX: assume we get IPv4 socket */
		server.dns_fds.v4fd = SD_LISTEN_FDS_START;
	} else {
#endif
		if ((server.addrfamily == AF_UNSPEC || server.addrfamily == AF_INET) &&
			(server.dns_fds.v4fd = open_dns(&server.dns4addr, server.dns4addr_len)) < 0) {

			retval = 1;
			goto cleanup;
		}
		if ((server.addrfamily == AF_UNSPEC || server.addrfamily == AF_INET6) &&
			/* Set IPv6 socket to V6ONLY */
			(server.dns_fds.v6fd = open_dns_opt(&server.dns6addr, server.dns6addr_len, 1)) < 0) {

			retval = 1;
			goto cleanup;
		}
#ifdef HAVE_SYSTEMD
	}
#endif

	/* Setup dns file descriptors to get destination IP address */
	if (server.dns_fds.v4fd >= 0)
		prepare_dns_fd(server.dns_fds.v4fd);
	if (server.dns_fds.v6fd >= 0)
		prepare_dns_fd(server.dns_fds.v6fd);

	if (server.bind_enable) {
		if ((server.bind_fd = open_dns_from_host(NULL, 0, AF_INET, 0)) < 0) {
			retval = 1;
			goto cleanup;
		}
	}

	if (created_users < USERS) {
		fprintf(stderr, "Limiting to %d simultaneous users because of netmask /%d\n",
			created_users, server.netmask);
	}
	fprintf(stderr, "Listening to dns for domain %s\n", server.topdomain);

	if (foreground == 0)
		do_detach();

	if (pidfile != NULL)
		do_pidfile(pidfile);

#ifdef FREEBSD
	tzsetwall();
#endif
#ifndef WINDOWS32
	openlog( __progname, LOG_NDELAY, LOG_DAEMON );
#endif

	if (newroot != NULL)
		do_chroot(newroot);

	signal(SIGINT, sigint);
	if (username != NULL) {
#ifndef WINDOWS32
		gid_t gids[1];
		gids[0] = pw->pw_gid;
		if (setgroups(1, gids) < 0 || setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			warnx("Could not switch to user %s!\n", username);
			usage();
		}
#endif
	}

	if (context != NULL)
		do_setcon(context);

	syslog(LOG_INFO, "started, listening on port %d", server.port);

	server_tunnel();

	syslog(LOG_INFO, "stopping");
	close_socket(server.bind_fd);
cleanup:
	close_socket(server.dns_fds.v6fd);
	close_socket(server.dns_fds.v4fd);
	close_socket(server.tun_fd);
#ifdef WINDOWS32
	WSACleanup();
#endif
	/* TODO close user TCP forward sockets */

	return retval;
}
