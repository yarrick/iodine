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
#endif

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
	server_stop();
}

static void
print_usage() {
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-v] [-h] [-4] [-6] [-c] [-s] [-f] [-D] "
		"[-u user] [-t chrootdir] [-d device] [-m mtu] [-z context] "
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
	fprintf(stderr, "  -v to print version info and exit\n");
	fprintf(stderr, "  -h to print this help and exit\n");
	fprintf(stderr, "  -4 to listen only on IPv4\n");
	fprintf(stderr, "  -6 to listen only on IPv6\n");
	fprintf(stderr, "  -c to disable check of client IP/port on each request\n");
	fprintf(stderr, "  -s to skip creating and configuring the tun device, "
		"which then has to be created manually\n");
	fprintf(stderr, "  -f to keep running in foreground\n");
	fprintf(stderr, "  -D to increase debug level\n");
	fprintf(stderr, "     (using -DD in UTF-8 terminal: \"LC_ALL=C luit iodined -DD ...\")\n");
	fprintf(stderr, "  -u name to drop privileges and run as user 'name'\n");
	fprintf(stderr, "  -t dir to chroot to directory dir\n");
	fprintf(stderr, "  -d device to set tunnel device name\n");
	fprintf(stderr, "  -m mtu to set tunnel device mtu\n");
	fprintf(stderr, "  -z context to apply SELinux context after initialization\n");
	fprintf(stderr, "  -l IPv4 address to listen on for incoming dns traffic "
		"(default 0.0.0.0)\n");
	fprintf(stderr, "  -L IPv6 address to listen on for incoming dns traffic "
		"(default ::)\n");
	fprintf(stderr, "  -p port to listen on for incoming dns traffic (default 53)\n");
	fprintf(stderr, "  -n ip to respond with to NS queries\n");
	fprintf(stderr, "  -b port to forward normal DNS queries to (on localhost)\n");
	fprintf(stderr, "  -P password used for authentication (max 32 chars will be used)\n");
	fprintf(stderr, "  -F pidfile to write pid to a file\n");
	fprintf(stderr, "  -i maximum idle time before shutting down\n");
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
	struct passwd *pw;
#endif
	int foreground;
	char *username;
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

	int choice;
	int port;
	int mtu;
	int skipipconfig;
	char *netsize;
	int ns_get_externalip;
	int retval;
	int max_idle_time = 0;
	struct sockaddr_storage dns4addr;
	int dns4addr_len;
	struct sockaddr_storage dns6addr;
	int dns6addr_len;
#ifdef HAVE_SYSTEMD
	int nb_fds;
#endif

#ifndef WINDOWS32
	pw = NULL;
#endif
	errormsg = NULL;
	username = NULL;
	newroot = NULL;
	context = NULL;
	device = NULL;
	foreground = 0;
	bind_enable = 0;
	bind_fd = 0;
	mtu = 1130;	/* Very many relays give fragsize 1150 or slightly
			   higher for NULL; tun/zlib adds ~17 bytes. */
	dns4addr_len = 0;
	dns6addr_len = 0;
	listen_ip4 = NULL;
	listen_ip6 = NULL;
	port = 53;
	ns_get_externalip = 0;
	addrfamily = AF_UNSPEC;
	skipipconfig = 0;
	pidfile = NULL;
	srand(time(NULL));

	retval = 0;

	server_init();

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
			help();
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
			strncpy(password, optarg, sizeof(password));
			password[sizeof(password)-1] = 0;

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
		netmask = atoi(netsize);
	}

	my_ip = inet_addr(argv[0]);

	if (my_ip == INADDR_NONE) {
		warnx("Bad IP address to use inside tunnel.");
		usage();
	}

	topdomain = strdup(argv[1]);
	if(check_topdomain(topdomain, &errormsg)) {
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

	if (mtu <= 0) {
		warnx("Bad MTU given.");
		usage();
	}

	if(port < 1 || port > 65535) {
		warnx("Bad port number given.");
		usage();
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
		dns4addr_len = get_addr(listen_ip4, port, AF_INET, AI_PASSIVE | AI_NUMERICHOST, &dns4addr);
		if (dns4addr_len < 0) {
			warnx("Bad IPv4 address to listen on.");
			usage();
		}
	}
	if (addrfamily == AF_UNSPEC || addrfamily == AF_INET6) {
		dns6addr_len = get_addr(listen_ip6, port, AF_INET6, AI_PASSIVE | AI_NUMERICHOST, &dns6addr);
		if (dns6addr_len < 0) {
			warnx("Bad IPv6 address to listen on.");
			usage();
		}
	}
	if(bind_enable) {
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
		struct in_addr extip;
		int res = get_external_ip(&extip);
		if (res) {
			fprintf(stderr, "Failed to get external IP via web service.\n");
			exit(3);
		}
		ns_ip = extip.s_addr;
		fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(extip));
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

#ifdef HAVE_SYSTEMD
	nb_fds = sd_listen_fds(0);
	if (nb_fds > 1) {
		retval = 1;
		warnx("Too many file descriptors received!\n");
		goto cleanup;
	} else if (nb_fds == 1) {
		/* XXX: assume we get IPv4 socket */
		dns_fds.v4fd = SD_LISTEN_FDS_START;
	} else {
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
#ifdef HAVE_SYSTEMD
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

	my_mtu = mtu;

	if (created_users < USERS) {
		fprintf(stderr, "Limiting to %d simultaneous users because of netmask /%d\n",
			created_users, netmask);
	}
	fprintf(stderr, "Listening to dns for domain %s\n", topdomain);

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

	syslog(LOG_INFO, "started, listening on port %d", port);

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
