/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 * 2013 Peter Sagerson <psagers.github@ignorare.net>
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>

#include "config.h"
#include "compat.h"

#ifdef DARWIN
#include <ctype.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
/* Inline used parts of if_utun.h to compile without it. */
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2
#include <netinet/ip.h>
#endif

#ifdef HAVE_SYS_SOCKIO
#include <sys/sockio.h>
#endif

#ifndef IFCONFIGPATH
#define IFCONFIGPATH "PATH=/sbin:/bin "
#endif

#ifndef ROUTEPATH
#define ROUTEPATH "PATH=/sbin:/bin "
#endif

#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TUN_MAX_TRY 50

#include "tun.h"
#include "common.h"

static char if_name[250];

#ifdef LINUX

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

int
open_tun(const char *tun_device)
{
	int i;
	int tun_fd;
	struct ifreq ifreq;
#ifdef ANDROID
	char *tunnel = "/dev/tun";
#else
	char *tunnel = "/dev/net/tun";
#endif

	if ((tun_fd = open(tunnel, O_RDWR)) < 0) {
		warn("open_tun: %s", tunnel);
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));

	ifreq.ifr_flags = IFF_TUN;

	if (tun_device != NULL) {
		strlcpy(ifreq.ifr_name, tun_device, IFNAMSIZ);
		strlcpy(if_name, tun_device, sizeof(if_name));

		if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
			fprintf(stderr, "Opened %s\n", ifreq.ifr_name);
			fd_set_close_on_exec(tun_fd);
			return tun_fd;
		}

		if (errno != EBUSY) {
			warn("open_tun: ioctl[TUNSETIFF]");
			return -1;
		}
	} else {
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(ifreq.ifr_name, IFNAMSIZ, "dns%d", i);

			if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
				fprintf(stderr, "Opened %s\n", ifreq.ifr_name);
				snprintf(if_name, sizeof(if_name), "dns%d", i);
				fd_set_close_on_exec(tun_fd);
				return tun_fd;
			}

			if (errno != EBUSY) {
				warn("open_tun: ioctl[TUNSETIFF]");
				return -1;
			}
		}

		warn("open_tun: Couldn't set interface name");
	}
	warn("error when opening tun");
	return -1;
}

#else /* BSD and friends */

#ifdef DARWIN

/* Extract the device number from the name, if given. The value returned will
 * be suitable for sockaddr_ctl.sc_unit, which means 0 for auto-assign, or
 * (n + 1) for manual.
 */
static int
utun_unit(const char *dev)
{
	const char *unit_str = dev;
	int unit = 0;

	if (!dev)
		return -1;

	while (*unit_str != '\0' && !isdigit(*unit_str))
		unit_str++;

	if (isdigit(*unit_str))
		unit = strtol(unit_str, NULL, 10) + 1;

	return unit;
}

static int
open_utun(const char *dev)
{
	struct sockaddr_ctl addr;
	struct ctl_info info;
	char ifname[10];
	socklen_t ifname_len = sizeof(ifname);
	int unit;
	int fd = -1;
	int err = 0;

	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) {
		warn("open_utun: socket(PF_SYSTEM)");
		return -1;
	}

	/* Look up the kernel controller ID for utun devices. */
	bzero(&info, sizeof(info));
	strlcpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

	err = ioctl(fd, CTLIOCGINFO, &info);
	if (err != 0) {
		warn("open_utun: ioctl(CTLIOCGINFO)");
		close(fd);
		return -1;
	}

	/* Connecting to the socket creates the utun device. */
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_id = info.ctl_id;
	unit = utun_unit(dev);
	if (unit < 0) {
		close(fd);
		return -1;
	}
	addr.sc_unit = unit;

	err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		warn("open_utun: connect");
		close(fd);
		return -1;
	}

	/* Retrieve the assigned interface name. */
	err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
	if (err != 0) {
		warn("open_utun: getsockopt(UTUN_OPT_IFNAME)");
		close(fd);
		return -1;
	}

	strlcpy(if_name, ifname, sizeof(if_name));

	fprintf(stderr, "Opened %s\n", ifname);
	fd_set_close_on_exec(fd);

	return fd;
}

#endif

int
open_tun(const char *tun_device)
{
	int i;
	int tun_fd;
	char tun_name[50];

	if (tun_device != NULL) {
#ifdef DARWIN
		if (!strncmp(tun_device, "utun", 4)) {
			tun_fd = open_utun(tun_device);
			if (tun_fd >= 0) {
				return tun_fd;
			}
		}
#endif

		snprintf(tun_name, sizeof(tun_name), "/dev/%s", tun_device);
		strlcpy(if_name, tun_device, sizeof(if_name));
		if_name[sizeof(if_name)-1] = '\0';

		if ((tun_fd = open(tun_name, O_RDWR)) < 0) {
			warn("open_tun: %s", tun_name);
			return -1;
		}

		fprintf(stderr, "Opened %s\n", tun_name);
		fd_set_close_on_exec(tun_fd);
		return tun_fd;
	} else {
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(tun_name, sizeof(tun_name), "/dev/tun%d", i);

			if ((tun_fd = open(tun_name, O_RDWR)) >= 0) {
				fprintf(stderr, "Opened %s\n", tun_name);
				snprintf(if_name, sizeof(if_name), "tun%d", i);
				fd_set_close_on_exec(tun_fd);
				return tun_fd;
			}

			if (errno == ENOENT)
				break;
		}

#ifdef DARWIN
		fprintf(stderr, "No tun devices found, trying utun\n");
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(tun_name, sizeof(tun_name), "utun%d", i);
			tun_fd = open_utun(tun_name);
			if (tun_fd >= 0) {
				return tun_fd;
			}
		}
#endif

		warn("open_tun: Failed to open tunneling device");
	}

	return -1;
}

#endif

void
close_tun(int tun_fd)
{
	if (tun_fd >= 0)
		close(tun_fd);
}

static int
tun_uses_header(void)
{
#if defined (FREEBSD) || defined (NETBSD)
	/* FreeBSD/NetBSD has no header */
	return 0;
#elif defined (DARWIN)
	/* Darwin tun has no header, Darwin utun does */
	return !strncmp(if_name, "utun", 4);
#else  /* LINUX/OPENBSD */
	return 1;
#endif
}

int
write_tun(int tun_fd, char *data, size_t len)
{
	if (!tun_uses_header()) {
		data += 4;
		len -= 4;
	} else {
#ifdef LINUX
		// Linux prefixes with 32 bits ethertype
		// 0x0800 for IPv4, 0x86DD for IPv6
		data[0] = 0x00;
		data[1] = 0x00;
		data[2] = 0x08;
		data[3] = 0x00;
#else /* OPENBSD and DARWIN(utun) */
		// BSDs prefix with 32 bits address family
		// AF_INET for IPv4, AF_INET6 for IPv6
		data[0] = 0x00;
		data[1] = 0x00;
		data[2] = 0x00;
		data[3] = 0x02;
#endif
	}

	if (write(tun_fd, data, len) != len) {
		warn("write_tun");
		return 1;
	}
	return 0;
}

ssize_t
read_tun(int tun_fd, char *buf, size_t len)
{
	if (!tun_uses_header()) {
		int bytes;
		memset(buf, 0, 4);

		bytes = read(tun_fd, buf + 4, len - 4);
		if (bytes < 0) {
			return bytes;
		} else {
			return bytes + 4;
		}
	} else {
		return read(tun_fd, buf, len);
	}
}

int
tun_setip(const char *ip, const char *other_ip, int netbits)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in localaddr, peeraddr, maskaddr;

	memset(&localaddr, 0, sizeof(localaddr));
	memset(&peeraddr, 0, sizeof(peeraddr));
	memset(&maskaddr, 0, sizeof(maskaddr));

	maskaddr.sin_family = AF_INET;
	if (build_netmask(netbits, &maskaddr.sin_addr)) {
		fprintf(stderr, "Invalid netmask: %d!\n", netbits);
		return 1;
	}

	localaddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &localaddr.sin_addr) <= 0) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}

	peeraddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, other_ip, &peeraddr.sin_addr) <= 0) {
		fprintf(stderr, "Invalid peer IP: %s!\n", other_ip);
		return 1;
	}

	fprintf(stderr, "Setting IP of %s to %s\n", if_name, ip);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("tun_setip: socket creation failed");
		return 1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	memcpy(&ifr.ifr_addr, &localaddr, sizeof(localaddr));
	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
		perror("tun_setip: ioctl SIOCSIFADDR failed");
		close(sock);
		return 1;
	}

	memcpy(&ifr.ifr_addr, &peeraddr, sizeof(peeraddr));
	if (ioctl(sock, SIOCSIFDSTADDR, &ifr) < 0) {
		perror("tun_setip: ioctl SIOCSIFDSTADDR failed");
		close(sock);
		return 1;
	}

	memcpy(&ifr.ifr_addr, &maskaddr, sizeof(maskaddr));
	if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
		perror("tun_setip: ioctl SIOCSIFNETMASK failed");
		close(sock);
		return 1;
	}

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		perror("tun_setip: ioctl SIOCGIFFLAGS failed");
		close(sock);
		return 1;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_POINTOPOINT | IFF_RUNNING);
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		perror("tun_setip: ioctl SIOCSIFFLAGS failed");
		close(sock);
		return 1;
	}

	close(sock);

#ifndef LINUX
	char cmdline[512];
	int r;
	struct in_addr netip;
	netip.s_addr = inet_addr(ip);
	netip.s_addr = netip.s_addr & netmask.s_addr;
	r = system(cmdline);
	if (r != 0) {
		return r;
	} else {

		snprintf(cmdline, sizeof(cmdline),
				ROUTEPATH "route add %s/%d %s",
				inet_ntoa(netip), netbits, ip);
	}
	fprintf(stderr, "Adding route %s/%d to %s\n", inet_ntoa(netip), netbits, ip);
	return system(cmdline);
#endif
	return 0;
}

int
tun_setmtu(const unsigned mtu)
{
	char cmdline[512];

	if (mtu > 200 && mtu <= 1500) {
		snprintf(cmdline, sizeof(cmdline),
				IFCONFIGPATH "ifconfig %s mtu %u",
				if_name,
				mtu);

		fprintf(stderr, "Setting MTU of %s to %u\n", if_name, mtu);
		return system(cmdline);
	} else {
		warn("MTU out of range: %u\n", mtu);
	}

	return 1;
}

