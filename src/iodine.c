/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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
#endif

#define PASSWORD_ENV_VAR "IODINE_PASS"

static void
sighandler(int sig) 
{
	client_stop();
}

static void
usage() {
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-v] [-h] [-f] [-r] [-u user] [-t chrootdir] [-d device] "
			"[-P password] [-m maxfragsize] [-z context] [-F pidfile] "
			"[nameserver] topdomain\n", __progname);
	exit(2);
}

static void
help() {
	extern char *__progname;

	fprintf(stderr, "iodine IP over DNS tunneling client\n");
	fprintf(stderr, "Usage: %s [-v] [-h] [-f] [-r] [-u user] [-t chrootdir] [-d device] "
			"[-P password] [-m maxfragsize] [-z context] [-F pidfile] "
			"[nameserver] topdomain\n", __progname);
	fprintf(stderr, "  -v to print version info and exit\n");
	fprintf(stderr, "  -h to print this help and exit\n");
	fprintf(stderr, "  -f to keep running in foreground\n");
	fprintf(stderr, "  -r to skip raw UDP mode attempt\n");
	fprintf(stderr, "  -u name to drop privileges and run as user 'name'\n");
	fprintf(stderr, "  -t dir to chroot to directory dir\n");
	fprintf(stderr, "  -d device to set tunnel device name\n");
	fprintf(stderr, "  -P password used for authentication (max 32 chars will be used)\n");
	fprintf(stderr, "  -m maxfragsize, to limit size of downstream packets\n");
	fprintf(stderr, "  -z context, to apply specified SELinux context after initialization\n");
	fprintf(stderr, "  -F pidfile to write pid to a file\n");
	fprintf(stderr, "nameserver is the IP number of the relaying nameserver, if absent /etc/resolv.conf is used\n");
	fprintf(stderr, "topdomain is the FQDN that is delegated to the tunnel endpoint.\n");

	exit(0);
}

static void
version() {
	char *svnver;

	svnver = "$Rev$ from $Date$";

	fprintf(stderr, "iodine IP over DNS tunneling client\n");
	fprintf(stderr, "SVN version: %s\n", svnver);

	exit(0);
}

int
main(int argc, char **argv)
{
	char *nameserv_addr;
	char *topdomain;
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

	nameserv_addr = NULL;
	topdomain = NULL;
#ifndef WINDOWS32
	pw = NULL;
#endif
	username = NULL;
	memset(password, 0, 33);
	foreground = 0;
	newroot = NULL;
	context = NULL;
	device = NULL;
	pidfile = NULL;

	autodetect_frag_size = 1;
	max_downstream_frag_size = 3072;
	retval = 0;
	raw_mode = 1;

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

	while ((choice = getopt(argc, argv, "vfhru:t:d:P:m:F:")) != -1) {
		switch(choice) {
		case 'v':
			version();
			/* NOTREACHED */
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help();
			/* NOTREACHED */
			break;
		case 'r':
			raw_mode = 0;
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
			strncpy(password, optarg, sizeof(password));
			password[sizeof(password)-1] = 0;
			
			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg)); 
			break;
		case 'm':
			autodetect_frag_size = 0;
			max_downstream_frag_size = atoi(optarg);
			break;
		case 'z':
			context = optarg;
			break;
		case 'F':
			pidfile = optarg;
			break;    
		default:
			usage();
			/* NOTREACHED */
		}
	}
	
	check_superuser(usage);

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		nameserv_addr = get_resolvconf_addr();
		topdomain = strdup(argv[0]);
		break;
	case 2:
		nameserv_addr = argv[0];
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

	if (nameserv_addr) {
		client_set_nameserver(nameserv_addr);
	} else {
		usage();
		/* NOTREACHED */
	}	

	if (strlen(topdomain) <= 128) {
		if(check_topdomain(topdomain)) {
			warnx("Topdomain contains invalid characters.\n");
			usage();
			/* NOTREACHED */
		}
	} else {
		warnx("Use a topdomain max 128 chars long.\n");
		usage();
		/* NOTREACHED */
	}

	client_set_topdomain(topdomain);
	
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
	if ((dns_fd = open_dns(0, INADDR_ANY)) == -1) {
		retval = 1;
		goto cleanup2;
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	if (client_handshake(dns_fd, raw_mode, autodetect_frag_size, max_downstream_frag_size)) {
		retval = 1;
		goto cleanup2;
	}
	
	if (client_get_conn() == CONN_DNS_NULL) {
		fprintf(stderr, "Sending queries for %s to %s\n", topdomain, nameserv_addr);
	} else {
		fprintf(stderr, "Sending raw traffic directly to %s\n", client_get_raw_addr());
	}

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

