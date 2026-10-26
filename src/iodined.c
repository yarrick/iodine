/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#ifdef WINDOWS
#include "windows_dns.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser_compat.h>
#endif
#define _XPG4_2
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/uio.h>
#include <netdb.h>
#endif

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#if HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#include "common.h"
#include "compat.h"
#include "dns.h"
#include "encoding.h"
#include "fw_query.h"
#include "login.h"
#include "process.h"
#include "run_as.h"
#include "server.h"
#include "tun.h"
#include "user.h"
#include "version.h"

#define PASSWORD_ENV_VAR "IODINED_PASS"

#if HAVE_PROGNAME
extern char *__progname;
#else
static char *__progname;
#endif

#if HAVE_NORETURN_ATTR
/* mark as no return to help some compilers to avoid warnings
 * about use of uninitialized variables */
static inline void usage(void) __attribute__((noreturn));
static inline void help(FILE * stream) __attribute__((noreturn));
#endif

static char password[33];

/* Ask opendns.com DNS service for external ip */
static int
get_external_ip(struct in_addr *ip)
{
	static const char target[] = "myip.opendns.com";
	struct query query;
	int attempt;
	int res;
	int fd;
	int out_len = 0;
	memset(&query, 0, sizeof(query));

	query.type = T_A;
	if(get_addr("resolver1.opendns.com", 53, AF_INET, 0, &query.destination, &query.dest_len))
		return 1;

	fd = open_dns_from_host(NULL, 0, AF_INET, AI_PASSIVE);
	if (fd < 0) return 2;

	for (attempt = 0; attempt < 3; attempt++) {
		char buf[64*1024];
		int buflen;
		fd_set fds;
		struct timeval tv;

		if (attempt) fprintf(stderr, "Retrying external IP lookup\n");
		{
			uint16_t rid;
			secure_random(&rid, sizeof(rid));
			query.id = rid;
		}
		buflen = sizeof(buf);
		buflen = dns_encode(buf, buflen, &query, QR_QUERY, target, strlen(target));
		if (buflen < 0) continue;

		sendto(fd, buf, buflen, 0, (struct sockaddr*)&query.destination, query.dest_len);

		tv.tv_sec = 1 + attempt;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		res = select(fd + 1, &fds, NULL, NULL, &tv);
		if (res > 0) {
			buflen = sizeof(buf);
			buflen = recv(fd, buf, buflen, 0);
			if (buflen > 0) {
				out_len = dns_decode((char *)ip, sizeof(struct in_addr), &query, QR_ANSWER, buf, buflen);
				if (out_len > 0) break;
			}
		}
	}

	close_dns(fd);
	return (out_len != sizeof(struct in_addr));
}

static void
sigint(int sig)
{
	(void)sig;
	server_stop();
}

static void print_usage(FILE *stream)
{
	fprintf(stream,
		"Usage: %s [-46cDfsv] [-u user] [-t chrootdir] [-d device] [-m mtu]\n"
		"               [-z context] [-l ipv4 listen address] [-L ipv6 listen address]\n"
		"               [-p port] [-n auto|external_ip] [-b dnsport] [-P password]\n"
		"               [-F pidfile] [-i max idle time] tunnel_ip[/netmask] topdomain\n",
		__progname);
}

static void usage(void)
{
	print_usage(stderr);
	exit(2);
}

static void help(FILE *stream)
{
	fprintf(stream, "iodine IP over DNS tunneling server\n\n");
	print_usage(stream);
	fprintf(stream,
		"\nAvailable options:\n"
		"  -v to print version info and exit\n"
		"  -h to print this help and exit\n"
		"  -4 to listen only on IPv4\n"
		"  -6 to listen only on IPv6\n"
		"  -c to disable check of client IP/port on each request\n"
		"  -s to skip creating and configuring the tun device,\n"
		"     which then has to be created manually\n"
		"  -f to keep running in foreground\n"
		"  -D to increase debug level\n"
		"     (using -DD in UTF-8 terminal: \"LC_ALL=C luit iodined -DD ...\")\n"
		"  -u name to drop privileges and run as user 'name'\n"
		"  -t dir to chroot to directory dir\n"
		"  -d device to set tunnel device name\n"
		"  -m mtu to set tunnel device mtu\n"
		"  -z context to apply SELinux context after initialization\n"
		"  -l IPv4 address to listen on for incoming dns traffic "
		"(default 0.0.0.0)\n"
		"     (Use 'external' to listen only on external IP, looked up via a service)\n"
		"  -L IPv6 address to listen on for incoming dns traffic "
		"(default ::)\n"
		"  -p port to listen on for incoming dns traffic (default 53)\n"
		"  -n ip to respond with to NS queries\n"
		"     (Use 'auto' to use the external IP, looked up via a service)\n"
		"  -b port to forward normal DNS queries to (on localhost)\n"
		"  -P password used for authentication (max 32 chars will be used)\n"
		"  -F pidfile to write pid to a file\n"
		"  -i maximum idle time before shutting down\n\n"
		"tunnel_ip is the IP number of the local tunnel interface.\n"
		"   /netmask sets the size of the tunnel network.\n"
		"topdomain is the FQDN that is delegated to this server.\n"
		"   Initial wildcard is allowed (example: *.tun.com)\n");

	exit(0);
}

static void version(void)
{
	fprintf(stderr,
		"iodine IP over DNS tunneling server\n"
		"Version: %s\n", IODINE_VERSION);

	exit(0);
}

static void prepare_dns_fd(int fd)
{
#ifndef WINDOWS
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
	(void)fd;
}

int
main(int argc, char **argv)
{
	struct server_params params;
	char *listen_ip4;
	char *listen_ip6;
	char *errormsg;
	int foreground;
	char *username;
	char *topdomain;
	struct run_as_user *run_as;
	char *newroot;
	char *context;
	char *device;
	char *pidfile;
	int addrfamily;
	struct dnsfd dns_fds;
	int tun_fd;

	/* settings for forwarding normal DNS to
	 * local real DNS server */
	int bind_fd;
	int bind_enable;
	int bind_port;

	int created_users;
	in_addr_t my_ip;
	int choice;
	int port;
	in_addr_t ns_ip;
	int mtu;
	int check_ip;
	int skipipconfig;
	int debug;
	int netmask;
	char *netsize;
	int ns_get_externalip;
	struct in_addr resolved_external_ip;
	int retval;
	int max_idle_time = 0;
	struct sockaddr_storage dns4addr;
	socklen_t dns4addr_len;
	struct sockaddr_storage dns6addr;
	socklen_t dns6addr_len;
#if HAVE_SYSTEMD
	int nb_fds;
#endif

	errormsg = NULL;
	username = NULL;
	topdomain = NULL;
	run_as = NULL;
	newroot = NULL;
	context = NULL;
	device = NULL;
	foreground = 0;
	bind_enable = 0;
	bind_port = 0;
	bind_fd = 0;
	mtu = 1130;	/* Very many relays give fragsize 1150 or slightly
			   higher for NULL; tun/zlib adds ~17 bytes. */
	listen_ip4 = NULL;
	listen_ip6 = NULL;
	port = 53;
	ns_ip = INADDR_ANY;
	ns_get_externalip = 0;
	resolved_external_ip.s_addr = INADDR_ANY;
	addrfamily = AF_UNSPEC;
	check_ip = 1;
	skipipconfig = 0;
	debug = 0;
	netmask = 27;
	pidfile = NULL;
	dns4addr_len = 0;
	dns6addr_len = 0;

	retval = 0;

	network_init();

#if !HAVE_PROGNAME
	__progname = strrchr(argv[0], '/');
	if (__progname == NULL)
		__progname = argv[0];
	else
		__progname++;
#endif

	fw_query_init();

	while ((choice = getopt(argc, argv, "46vcsfhDu:t:d:m:l:L:p:n:b:P:z:F:i:")) != -1) {
		switch(choice) {
		case '4':
			addrfamily = AF_INET;
			break;
		case '6':
			addrfamily = AF_INET6;
			break;
		case 'v':
			version();
			break;
		case 'c':
			check_ip = 0;
			break;
		case 's':
			skipipconfig = 1;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help(stdout);
			break;
		case 'D':
			debug++;
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
			listen_ip4 = optarg;
			break;
		case 'L':
			listen_ip6 = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			if (optarg && strcmp("auto", optarg) == 0) {
				ns_get_externalip = 1;
			} else {
				ns_ip = inet_addr(optarg);
			}
			break;
		case 'b':
			bind_enable = 1;
			bind_port = atoi(optarg);
			break;
		case 'F':
			pidfile = optarg;
			break;
		case 'i':
			max_idle_time = atoi(optarg);
			break;
		case 'P':
			strlcpy(password, optarg, sizeof(password));

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

	if (argc != 2) {
		usage();
		/* NOTREACHED */
	}

	check_privileges(username, port);

	netsize = strchr(argv[0], '/');
	if (netsize) {
		*netsize = 0;
		netsize++;
		netmask = atoi(netsize);
	}

	my_ip = inet_addr(argv[0]);

	if (my_ip == INADDR_NONE) {
		warnx("Bad IP address to use inside tunnel.");
		usage();
	}

	topdomain = strdup(argv[1]);
	if (check_topdomain(topdomain, 1, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	if (username != NULL) {
		if ((run_as = run_as_user_lookup(username)) == NULL) {
			warnx("User %s does not exist!", username);
			usage();
			/* NOTREACHED */
		}
	}

	if (mtu <= 0) {
		warnx("Bad MTU given.");
		usage();
		/* NOTREACHED */
	}

	if (port < 1 || port > 65535) {
		warnx("Bad port number given.");
		usage();
		/* NOTREACHED */
	}

	if (port != 53) {
		fprintf(stderr, "ALERT! Other dns servers expect you to run on port 53.\n");
		fprintf(stderr, "You must manually forward port 53 to port %d for things to work.\n", port);
	}

	if (debug) {
		fprintf(stderr, "Debug level %d enabled, will stay in foreground.\n", debug);
		fprintf(stderr, "Add more -D switches to set higher debug level.\n");
		foreground = 1;
	}
	if (addrfamily == AF_UNSPEC || addrfamily == AF_INET) {
		if (listen_ip4 && strcmp("external", listen_ip4) == 0) {
			int res = get_external_ip(&resolved_external_ip);
			if (res) {
				fprintf(stderr, "Failed to get external IP via DNS query.\n");
				exit(3);
			}
			listen_ip4 = inet_ntoa(resolved_external_ip);
			fprintf(stderr, "Will listen on external IP %s\n", listen_ip4);
		}
		if (get_addr(listen_ip4, port, AF_INET, AI_PASSIVE, &dns4addr, &dns4addr_len)) {
			warnx("Bad IPv4 address to listen on: '%s'", listen_ip4);
			usage();
		}
		// Use dns4addr from here on.
		listen_ip4 = NULL;
	}
	if (addrfamily == AF_UNSPEC || addrfamily == AF_INET6) {
		if (get_addr(listen_ip6, port, AF_INET6, AI_PASSIVE, &dns6addr, &dns6addr_len)) {
			if (listen_ip6 == NULL) {
				if (addrfamily == AF_INET6) {
					fprintf(stderr, "IPv6 not supported");
					exit(3);
				} else {
					warnx("IPv6 not supported, skipping");
					addrfamily = AF_INET;
				}
			} else {
				warnx("Failed to get IPv6 address to listen on: '%s'",
					listen_ip6);
				usage();
				/* NOTREACHED */
			}
		}
		// Use dns6addr from here on.
		listen_ip6 = NULL;
	}

	if (bind_enable) {
		in_addr_t dns_ip = ((struct sockaddr_in *) &dns4addr)->sin_addr.s_addr;
		if (bind_port < 1 || bind_port > 65535) {
			warnx("Bad DNS server port number given.");
			usage();
			/* NOTREACHED */
		}
		/* Avoid forwarding loops */
		if (bind_port == port && (dns_ip == INADDR_ANY || dns_ip == htonl(0x7f000001L))) {
			warnx("Forward port is same as listen port (%d), will create a loop!", bind_port);
			fprintf(stderr, "Use -l to set listen ip to avoid this.\n");
			usage();
			/* NOTREACHED */
		}
		fprintf(stderr, "Requests for domains outside of %s will be forwarded to port %d\n",
			topdomain, bind_port);
	}

	if (ns_get_externalip) {
		if (resolved_external_ip.s_addr == INADDR_ANY) {
			int res = get_external_ip(&resolved_external_ip);
			if (res) {
				fprintf(stderr, "Failed to get external IP via DNS query.\n");
				exit(3);
			}
		}
		ns_ip = resolved_external_ip.s_addr;
		fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(resolved_external_ip));
	}

	if (ns_ip == INADDR_NONE) {
		warnx("Bad IP address to return as nameserver.");
		usage();
	}
	if (netmask > 30 || netmask < 8) {
		warnx("Bad netmask (%d bits). Use 8-30 bits.", netmask);
		usage();
	}

	if (strlen(password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(password, sizeof(password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(password, sizeof(password));
	}

	/* Mark both file descriptors as unused */
	dns_fds.v4fd = -1;
	dns_fds.v6fd = -1;

	created_users = init_users(my_ip, netmask);

	if ((tun_fd = open_tun(device)) == -1) {
		/* nothing to clean up, just return */
		return 1;
	}
	if (!skipipconfig) {
		const char *other_ip = users_get_first_ip();
		if (tun_setip(argv[0], other_ip, netmask) != 0 || tun_setmtu(mtu) != 0) {
			retval = 1;
			free((void*) other_ip);
			goto cleanup;
		}
		free((void*) other_ip);
	}

#if HAVE_SYSTEMD
	nb_fds = sd_listen_fds(0);
	if (nb_fds < 0) {
		warnx("Failed to receive file descriptors from systemd: %s", strerror(-nb_fds));
		retval = 1;
		goto cleanup;
	} else if (nb_fds == 0) {
#endif
		if ((addrfamily == AF_UNSPEC || addrfamily == AF_INET) &&
			(dns_fds.v4fd = open_dns(&dns4addr, dns4addr_len)) < 0) {

			retval = 1;
			goto cleanup;
		}
		if ((addrfamily == AF_UNSPEC || addrfamily == AF_INET6) &&
			/* Set IPv6 socket to V6ONLY */
			(dns_fds.v6fd = open_dns_opt(&dns6addr, dns6addr_len, 1)) < 0) {

			retval = 1;
			goto cleanup;
		}
#if HAVE_SYSTEMD
	} else if (nb_fds <= 2) {
		/* systemd may pass up to two sockets, for ip4 and ip6, try to figure out
			which is which */
		for (int i = 0; i < nb_fds; i++) {
			int fd = SD_LISTEN_FDS_START + i;
			if (sd_is_socket(fd, AF_INET, SOCK_DGRAM, -1)) {
				dns_fds.v4fd = fd;
			} else if (sd_is_socket(fd, AF_INET6, SOCK_DGRAM, -1)) {
				dns_fds.v6fd = fd;
			} else {
				retval = 1;
				warnx("Unknown socket %d passed to iodined!\n", fd);
				goto cleanup;
			}
		}
	} else {
		retval = 1;
		warnx("Too many file descriptors received!\n");
		goto cleanup;
	}
#endif

	/* Setup dns file descriptors to get destination IP address */
	if (dns_fds.v4fd >= 0)
		prepare_dns_fd(dns_fds.v4fd);
	if (dns_fds.v6fd >= 0)
		prepare_dns_fd(dns_fds.v6fd);

	if (bind_enable) {
		if ((bind_fd = open_dns_from_host(NULL, 0, AF_INET, 0)) < 0) {
			retval = 1;
			goto cleanup;
		}
	}

	if (created_users < USERS) {
		fprintf(stderr, "Limiting to %d simultaneous users because of netmask /%d\n",
			created_users, netmask);
	}
	fprintf(stderr, "Listening to dns for domain %s\n", topdomain);

	if (pidfile != NULL)
		do_pidfile(pidfile);

	if (foreground == 0)
		do_detach();

#ifdef FREEBSD
	tzset();
#endif
#if HAVE_SYSLOG
	openlog(__progname, LOG_NDELAY, LOG_DAEMON);
#endif

	if (newroot != NULL)
		do_chroot(newroot);

	signal(SIGINT, sigint);
	if (run_as != NULL) {
		if (run_as_user_switch(run_as)) {
			warnx("Could not switch to user %s!\n", username);
			usage();
			/* NOTREACHED */
		}
	}

	if (context != NULL)
		do_setcon(context);

	syslog(LOG_INFO, "started, listening on port %d", port);

	params.topdomain = topdomain;
	params.password = password;
	params.users = created_users;
	params.check_ip = check_ip;
	params.tunnel_mtu = mtu;
	params.server_ip = my_ip;
	params.netmask = netmask;
	params.nameserver_ip = ns_ip;
	params.bind_port = bind_port;
	params.debug = debug;

	server_init(&params);

	server_tunnel(tun_fd, &dns_fds, bind_fd, max_idle_time);

	syslog(LOG_INFO, "stopping");
	close_dns(bind_fd);
cleanup:
	if (dns_fds.v6fd >= 0)
		close_dns(dns_fds.v6fd);
	if (dns_fds.v4fd >= 0)
		close_dns(dns_fds.v4fd);
	close_tun(tun_fd);

	return retval;
}
