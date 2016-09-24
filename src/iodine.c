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
#include <getopt.h>
#include <sys/types.h>
#include <sys/param.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include "common.h"
#include "version.h"
#include "tun.h"
#include "client.h"
#include "util.h"
#include "encoding.h"
#include "base32.h"

#ifdef WINDOWS32
#include "windows.h"
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#else
#include <arpa/nameser.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#endif

#if !defined(BSD) && !defined(__GLIBC__)
static char *__progname;
#endif

#define PASSWORD_ENV_VAR "IODINE_PASS"

struct client_instance this;

/* BEGIN PRESET DEFINITIONS */

/* static startup values - should not be changed in presets */
#define PRESET_STATIC_VALUES \
	.conn = CONN_DNS_NULL, \
	.send_ping_soon = 1, \
	.maxfragsize_up = 100, \
	.next_downstream_ack = -1, \
	.num_immediate = 1, \
	.rtt_total_ms = 200, \
	.remote_forward_addr = {.ss_family = AF_UNSPEC}

static struct client_instance preset_default = {
	.raw_mode = 1,
	.lazymode = 1,
	.max_timeout_ms = 5000,
	.send_interval_ms = 0,
	.server_timeout_ms = 4000,
	.downstream_timeout_ms = 2000,
	.autodetect_server_timeout = 1,
	.dataenc = &base32_encoder,
	.autodetect_frag_size = 1,
	.max_downstream_frag_size = MAX_FRAGSIZE,
	.compression_up = 1,
	.compression_down = 1,
	.windowsize_up = 8,
	.windowsize_down = 8,
	.hostname_maxlen = 0xFF,
	.downenc = ' ',
	.do_qtype = T_UNSET,
	PRESET_STATIC_VALUES
};

static struct client_instance preset_original = {
	.raw_mode = 0,
	.lazymode = 1,
	.max_timeout_ms = 4000,
	.send_interval_ms = 0,
	.server_timeout_ms = 3000,
	.autodetect_server_timeout = 1,
	.windowsize_down = 1,
	.windowsize_up = 1,
	.hostname_maxlen = 0xFF,
	.downstream_timeout_ms = 4000,
	.dataenc = &base32_encoder,
	.autodetect_frag_size = 1,
	.max_downstream_frag_size = MAX_FRAGSIZE,
	.compression_down = 1,
	.compression_up = 0,
	.downenc = ' ',
	.do_qtype = T_UNSET,
	PRESET_STATIC_VALUES
};

static struct client_instance preset_fast = {
	.raw_mode = 0,
	.lazymode = 1,
	.max_timeout_ms = 3000,
	.send_interval_ms = 0,
	.server_timeout_ms = 2500,
	.downstream_timeout_ms = 100,
	.autodetect_server_timeout = 1,
	.dataenc = &base32_encoder,
	.autodetect_frag_size = 1,
	.max_downstream_frag_size = 1176,
	.compression_up = 1,
	.compression_down = 1,
	.windowsize_up = 30,
	.windowsize_down = 30,
	.hostname_maxlen = 0xFF,
	.downenc = ' ',
	.do_qtype = T_UNSET,
	PRESET_STATIC_VALUES
};

static struct client_instance preset_fallback = {
	.raw_mode = 1,
	.lazymode = 1,
	.max_timeout_ms = 1000,
	.send_interval_ms = 20,
	.server_timeout_ms = 500,
	.downstream_timeout_ms = 1000,
	.autodetect_server_timeout = 1,
	.dataenc = &base32_encoder,
	.autodetect_frag_size = 1,
	.max_downstream_frag_size = 500,
	.compression_up = 1,
	.compression_down = 1,
	.windowsize_up = 1,
	.windowsize_down = 1,
	.hostname_maxlen = 100,
	.downenc = 'T',
	.do_qtype = T_CNAME,
	PRESET_STATIC_VALUES
};

#define NUM_CLIENT_PRESETS 4

static struct {
	struct client_instance *preset_data;
	char short_name;
	char *desc;
} client_presets[NUM_CLIENT_PRESETS] = {
	{
		.preset_data = &preset_default,
		.short_name = 'D',
		.desc = "Defaults"
	},
	{
		.preset_data = &preset_original,
		.short_name = '7',
		.desc = "Imitate iodine 0.7"
	},
	{
		.preset_data = &preset_fast,
		.short_name = 'F',
		.desc = "Fast and low latency"
	},
	{
		.preset_data = &preset_fallback,
		.short_name = 'M',
		.desc = "Minimal DNS queries and short DNS timeouts"
	}
};

/* END PRESET DEFINITIONS */

static void
sighandler(int sig)
{
	this.running = 0;
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

	fprintf(stderr, "Usage: %s [-v] [-h] [-Y preset] [-V sec] [-X port] [-f] [-r] [-u user] [-t chrootdir] [-d device] "
			"[-w downfrags] [-W upfrags] [-i sec -j sec] [-I sec] [-c 0|1] [-C 0|1] [-s ms] "
			"[-P password] [-m maxfragsize] [-M maxlen] [-T type] [-O enc] [-L 0|1] [-R port[,host] ] "
			"[-z context] [-F pidfile] topdomain [nameserver1 [nameserver2 [...]]]\n", __progname);
}

static void
usage()
{
	print_usage();
	exit(2);
}

static void
print_presets(int spaces)
{
#define INDENT fprintf(stderr, "%*s", spaces, "");
	INDENT fprintf(stderr, "Available presets: (use -Y <preset ID>)\n");
	spaces += 2;
	for (int i = 0; i < NUM_CLIENT_PRESETS; i++) {
		INDENT fprintf(stderr, "'%c': %s\n", client_presets[i].short_name, client_presets[i].desc);
	}
}

static void
help()
{
	fprintf(stderr, "iodine IP over DNS tunneling client\n");
	print_usage();
	fprintf(stderr, "\nOptions to try if connection doesn't work:\n");
	fprintf(stderr, "  -T  use DNS type: NULL, PRIVATE, TXT, SRV, MX, CNAME, A (default: autodetect)\n");
	fprintf(stderr, "  -O  use specific downstream encoding for queries: Base32, Base64, Base64u,\n");
	fprintf(stderr, "        Base128, or (only for TXT:) Raw  (default: autodetect)\n");
	fprintf(stderr, "  -I  target interval between sending and receiving requests (default: 4 secs)\n");
	fprintf(stderr, "        or ping interval in immediate mode (default: 1 sec)\n");
	fprintf(stderr, "  -s  minimum interval between queries (default: 0ms)\n");
	fprintf(stderr, "  -L 1: use lazy mode for low-latency (default). 0: don't (implies -I1)\n");
	fprintf(stderr, "  -m  max size of downstream fragments (default: autodetect)\n");
	fprintf(stderr, "  -M  max size of upstream hostnames (~100-255, default: 255)\n");
	fprintf(stderr, "  -r  skip raw UDP mode attempt\n");
	fprintf(stderr, "  -P  password used for authentication (max 32 chars will be used)\n\n");

	fprintf(stderr, "Fine-tuning options:\n");
	fprintf(stderr, "  -w  downstream fragment window size (default: 8 frags)\n");
	fprintf(stderr, "  -W  upstream fragment window size (default: 8 frags)\n");
	fprintf(stderr, "  -i  server-side request timeout in lazy mode (default: auto)\n");
	fprintf(stderr, "  -j  downstream fragment ACK timeout, implies -i4 (default: 2 sec)\n");
	//fprintf(stderr, "  --nodrop  disable TCP packet-dropping optimisations\n");
	fprintf(stderr, "  -c 1: use downstream compression (default), 0: disable\n");
	fprintf(stderr, "  -C 1: use upstream compression (default), 0: disable\n\n");

	fprintf(stderr, "Other options:\n");
	fprintf(stderr, "  -v, --version  print version info and exit\n");
	fprintf(stderr, "  -h, --help  print this help and exit\n");
	fprintf(stderr, "  -V, --stats  print connection statistics at given intervals (default: 5 sec)\n");
	fprintf(stderr, "  -f  keep running in foreground\n");
	fprintf(stderr, "  -D  enable debug mode (add more D's to increase debug level)\n");
	fprintf(stderr, "  -d  set tunnel device name\n");
	fprintf(stderr, "  -u  drop privileges and run as specified user\n");
	fprintf(stderr, "  -F  write PID to specified file\n");
	fprintf(stderr, "  -Y, --preset  use a set of predefined options for DNS tunnel (can be overridden manually)\n");
	print_presets(6);
	fprintf(stderr, "  -R, --remote [host:]port  skip tun device and forward data to/from\n");
	fprintf(stderr, "        stdin/out, telling iodined to forward data to a remote port\n");
	fprintf(stderr, "        locally or to a specific host (accessed by server). Implies --nodrop.\n");
	fprintf(stderr, "        To specify an IPv6 address, host must be enclosed in square brackets.\n");
	fprintf(stderr, "        Can be used with SSH ProxyCommand option. ('iodine -R 22 ...')\n");
	fprintf(stderr, "  --chroot  chroot to given directory\n");
	fprintf(stderr, "  --context  apply specified SELinux context after initialization\n");
	fprintf(stderr, "  --rdomain  use specified routing domain (OpenBSD only)\n\n");

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

static int
parse_tcp_forward_option(char *optstr)
{
	char *remote_port_str, *remote_host_str;
	int retval;

	if (strrchr(optstr, ':')) {
		remote_port_str = strrchr(optstr, ':') + 1;
		if (optstr[0] == '[') {
			/* IPv6 address enclosed in square brackets */
			remote_host_str = optstr + 1;
			/* replace closing bracket with null terminator */
			*strchr(remote_host_str, ']') = 0;
			this.remote_forward_addr.ss_family = AF_INET6;
			retval = inet_pton(AF_INET6, remote_host_str,
							   &((struct sockaddr_in6 *) &this.remote_forward_addr)->sin6_addr);
		} else {
			remote_host_str = optstr;
			/* replace separator with null terminator */
			*strchr(remote_host_str, ':') = 0;
			this.remote_forward_addr.ss_family = AF_INET;
			retval = inet_aton(remote_host_str,
							   &((struct sockaddr_in *) &this.remote_forward_addr)->sin_addr);
		}
	} else {
		/* no address specified (use server localhost IPv4), optstr is port */
		remote_port_str = optstr;
		this.remote_forward_addr.ss_family = AF_INET;
		((struct sockaddr_in *) &this.remote_forward_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		retval = 1;
	}

	if (!retval) {
		warnx("Invalid remote forward address (-R)! Must be [host:]port,\n"
			"where IPv6 addresses are enclosed in literal square brackets [].");
		usage();
		/* not reached */
	}

	/* parse port */
	int port = atoi(remote_port_str);
	if (port < 1 || port > 65535) {
		fprintf(stderr, "Remote forward (-R) TCP port must be between 1 and 65535.");
		usage();
		/* not reached */
	}

	if (this.remote_forward_addr.ss_family == AF_INET) {
		/* set port as sockaddr_in (IPv4) */
		((struct sockaddr_in *) &this.remote_forward_addr)->sin_port = htons(port);
	} else {
		/* set port in IPv6 sockaddr */
		((struct sockaddr_in6 *) &this.remote_forward_addr)->sin6_port = htons(port);
	}
	return port;
}

int
main(int argc, char **argv)
{
	char *errormsg = NULL;
#ifndef WINDOWS32
	struct passwd *pw = NULL;
#endif
	int choice = -1;
	int retval = 0;

	char *username = NULL;
	char *newroot = NULL;
	char *context = NULL;
	char *device = NULL;
	char *pidfile = NULL;

	int remote_forward_port = 0;

	char *nameserv_host = NULL;
	struct sockaddr_storage nameservaddr;
	int nameservaddr_len = 0;
	int nameserv_family = AF_UNSPEC;

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

#define OPT_RDOMAIN 0x80
#define OPT_NODROP 0x81

	/* each option has format:
	 * char *name, int has_arg, int *flag, int val */
	static struct option iodine_args[] = {
		{"version", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{"stats", optional_argument, 0, 'V'},
		{"context", required_argument, 0, 'z'},
		{"rdomain", required_argument, 0, OPT_RDOMAIN},
		{"chrootdir", required_argument, 0, 't'},
		{"preset", required_argument, 0, 'Y'},
		{"proxycommand", no_argument, 0, 'R'},
//		{"nodrop", no_argument, 0, OPT_NODROP},
		{"remote", required_argument, 0, 'R'},
		{NULL, 0, 0, 0}
	};

	/* Pre-parse command line to get preset
	 * This is so that all options override preset values regardless of order in command line */
	int optind_orig = optind, preset_id = -1;

	static char *iodine_args_short = "46vfDhrY:s:V:c:C:i:j:u:t:d:R:P:w:W:m:M:F:T:O:L:I:";

	while ((choice = getopt_long(argc, argv, iodine_args_short, iodine_args, NULL))) {
		/* Check if preset has been found yet so we don't process any other options */
		if (preset_id < 0) {
			if (choice == -1) {
				/* reached end of command line and no preset specified - use default */
				preset_id = 0;
			} else if (choice == 'Y') {
				/* find index of preset */
				if (optarg) {
					for (int i = 0; i < NUM_CLIENT_PRESETS; i++) {
						if (toupper(optarg[0]) == client_presets[i].short_name) {
							preset_id = i;
							break;
						}
					}
				}
			} else if (choice == '?') {
				usage();
				/* Not reached */
			} else {
				/* skip all other options until we find preset */
				continue;
			}

			if (preset_id < 0) {
				/* invalid preset or none specified */
				fprintf(stderr, "Invalid preset or none specified with -Y or --preset!\n");
				print_presets(2);
				usage();
				/* not reached */
			}

			memcpy(&this, client_presets[preset_id].preset_data, sizeof(struct client_instance));

			/* Reset optind to reparse command line */
			optind = optind_orig;
			continue;
		} else if (choice == -1) {
			break;
		}

		/* Once a preset is used, it is copied into memory. This way other
		 * options can override preset values regardless of order in command line */

		switch (choice) {
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
			this.stats = atoi(optarg);
			if (this.stats < 0)
				this.stats = 0;
			break;
		case 'f':
			this.foreground = 1;
			break;
		case 'D':
			this.debug++;
			break;
		case 'h':
			help();
			/* NOTREACHED */
			break;
		case 'r':
			this.raw_mode = 0;
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
		case OPT_RDOMAIN:
			rtable = atoi(optarg);
			break;
#endif
		case 'R':
			/* Argument format: [host:]port */
			if (!optarg) break;
			this.use_remote_forward = 1;
			remote_forward_port = parse_tcp_forward_option(optarg);
			break;
		case OPT_NODROP:
			// TODO implement TCP-over-tun optimisations
			break;
		case 'P':
			strncpy(this.password, optarg, sizeof(this.password));
			this.password[sizeof(this.password)-1] = 0;

			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg));
			break;
		case 'm':
			this.autodetect_frag_size = 0;
			this.max_downstream_frag_size = atoi(optarg);
			break;
		case 'M':
			this.hostname_maxlen = atoi(optarg);
			if (this.hostname_maxlen > 255)
				this.hostname_maxlen = 255;
			if (this.hostname_maxlen < 10)
				this.hostname_maxlen = 10;
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
			if ((this.downenc = parse_encoding(optarg)) == 0)
				errx(6, "Invalid encoding type '%s'", optarg);
			break;
		case 'L':
			this.lazymode = atoi(optarg);
			if (this.lazymode > 1)
				this.lazymode = 1;
			if (this.lazymode < 0)
				this.lazymode = 0;
			break;
		case 'I':
			this.max_timeout_ms = strtod(optarg, NULL) * 1000;
			if (this.autodetect_server_timeout) {
				this.server_timeout_ms = this.max_timeout_ms / 2;
			}
			break;
		case 'i':
			this.server_timeout_ms = strtod(optarg, NULL) * 1000;
			this.autodetect_server_timeout = 0;
			break;
		case 'j':
			this.downstream_timeout_ms = strtod(optarg, NULL) * 1000;
			if (this.autodetect_server_timeout) {
				this.autodetect_server_timeout = 0;
				this.server_timeout_ms = 4000;
			}
			break;
		case 's':
			this.send_interval_ms = atoi(optarg);
			if (this.send_interval_ms < 0)
				this.send_interval_ms = 0;
		case 'w':
			this.windowsize_down = atoi(optarg);
			break;
		case 'W':
			this.windowsize_up = atoi(optarg);
			break;
		case 'c':
			this.compression_down = atoi(optarg) & 1;
			break;
		case 'C':
			this.compression_up = atoi(optarg) & 1;
			break;
		case 'Y':
			/* Already processed preset: ignore */
			continue;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	srand((unsigned) time(NULL));
	this.rand_seed = (uint16_t) rand();
	this.chunkid = (uint16_t) rand();
	this.running = 1;

	check_superuser(usage);

	argc -= optind;
	argv += optind;

	if (this.debug) {
		fprintf(stderr, "Debug level %d enabled, will stay in foreground.\n", this.debug);
		fprintf(stderr, "Add more -D switches to set higher debug level.\n");
		this.foreground = 1;
	}



	this.nameserv_hosts_len = argc - 1;
	if (this.nameserv_hosts_len <= 0)
		/* if no hosts specified, use resolv.conf */
		this.nameserv_hosts_len = 1;

	// Preallocate memory with expected number of hosts
	this.nameserv_hosts = malloc(sizeof(char *) * this.nameserv_hosts_len);
	this.nameserv_addrs = malloc(sizeof(struct sockaddr_storage) * this.nameserv_hosts_len);

	if (argc == 0) {
		usage();
		/* NOT REACHED */
	} else if (argc == 1) {
		this.nameserv_hosts[0] = get_resolvconf_addr();
	} else if (argc > 1)
		for (int h = 0; h < this.nameserv_hosts_len; h++)
			this.nameserv_hosts[h] = strdup(argv[h + 1]);
	this.topdomain = strdup(argv[0]);

	for (int n = 0; n < this.nameserv_hosts_len; n++) {
		nameserv_host = this.nameserv_hosts[n];
		if (!nameserv_host) {
			errx(1, "Error processing nameserver hostnames!");
		}
		nameservaddr_len = get_addr(nameserv_host, DNS_PORT, nameserv_family, 0, &nameservaddr);
		if (nameservaddr_len < 0) {
			errx(1, "Cannot lookup nameserver '%s': %s ",
					nameserv_host, gai_strerror(nameservaddr_len));
		}
		memcpy(&this.nameserv_addrs[n], &nameservaddr, sizeof(struct sockaddr_storage));
		this.nameserv_addrs_len ++;
		nameserv_host = NULL;
	}

	if (this.nameserv_addrs_len <= 0 || !this.nameserv_hosts[0]) {
		warnx("No nameservers found - not connected to any network?");
		usage();
	}

	if (this.max_downstream_frag_size < 10 || this.max_downstream_frag_size > MAX_FRAGSIZE) {
		warnx("Use a max frag size between 10 and %d bytes.", MAX_FRAGSIZE);
		usage();
		/* NOTREACHED */
	}

	if(check_topdomain(this.topdomain, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	int max_ws = MAX_SEQ_ID / 2;
	if (this.windowsize_up < 1 || this.windowsize_down < 1 ||
		this.windowsize_up > max_ws || this.windowsize_down > max_ws) {
		warnx("Window sizes (-w or -W) must be between 0 and %d!", max_ws);
		usage();
	}

	if (this.max_timeout_ms < 100) {
		warnx("Target interval (-I) must be greater than 0.1 seconds!");
		usage();
	}

	if ((this.server_timeout_ms < 100 || this.server_timeout_ms >= this.max_timeout_ms)
		&& !this.autodetect_server_timeout) {
		warnx("Server timeout (-i) must be greater than 0.1 sec and less than target interval!");
		usage();
	}

	if (this.downstream_timeout_ms < 100) {
		warnx("Downstream fragment timeout must be more than 0.1 sec to prevent excessive retransmits.");
		usage();
	}

	if (!this.lazymode && this.max_timeout_ms > 1000) {
		fprintf(stderr, "Warning: Target interval of >1 second in immediate mode will cause high latency.\n");
	}

	if (username != NULL) {
#ifndef WINDOWS32
		if ((pw = getpwnam(username)) == NULL) {
			warnx("User %s does not exist!", username);
			usage();
			/* NOTREACHED */
		}
#else
		warnx("Warning: Cannot switch user on Windows systems.");
#endif
	}

	if (strlen(this.password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(this.password, sizeof(this.password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(this.password, sizeof(this.password));
	}

	if (!this.use_remote_forward) {
		if ((this.tun_fd = open_tun(device)) == -1) {
			retval = 1;
			goto cleanup;
		}
	}

	if ((this.dns_fd = open_dns_from_host(NULL, 0, nameservaddr.ss_family, AI_PASSIVE)) < 0) {
		retval = 1;
		goto cleanup;
	}
#ifdef OPENBSD
	if (rtable > 0)
		socket_setrtable(dns_fd, rtable);
#endif

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	fprintf(stderr, "Sending DNS queries for %s to ", this.topdomain);
	for (int a = 0; a < this.nameserv_addrs_len; a++)
		fprintf(stderr, "%s%s", format_addr(&this.nameserv_addrs[a], sizeof(struct sockaddr_storage)),
				(a != this.nameserv_addrs_len - 1) ?  ", " : "");
	fprintf(stderr, "\n");

	if (this.remote_forward_addr.ss_family != AF_UNSPEC)
		fprintf(stderr, "Requesting TCP data forwarding from server to %s:%d\n",
				format_addr(&this.remote_forward_addr, sizeof(struct sockaddr_storage)), remote_forward_port);

	if (client_handshake()) {
		retval = 1;
		goto cleanup;
	}

	if (this.conn == CONN_RAW_UDP) {
		fprintf(stderr, "Sending raw UDP traffic directly to %s\n", client_get_raw_addr());
	}

	fprintf(stderr, "Connection setup complete, transmitting data.\n");

	if (this.foreground == 0)
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

	client_tunnel();

cleanup:
	if (this.use_remote_forward)
		close(STDOUT_FILENO);
	close_socket(this.dns_fd);
	close_socket(this.tun_fd);
#ifdef WINDOWS32
	WSACleanup();
#endif

	return retval;
}

