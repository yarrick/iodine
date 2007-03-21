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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "tun.h"

#define TUN_MAX_TRY 50

char if_name[50];

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
	char *tunnel = "/dev/net/tun";

	if ((tun_fd = open(tunnel, O_RDWR)) < 0) {
		warn("open_tun: %s: %s", tunnel, strerror(errno));
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));

	ifreq.ifr_flags = IFF_TUN; 

	if (tun_device != NULL) {
		strncpy(ifreq.ifr_name, tun_device, IFNAMSIZ);
		strncpy(if_name, tun_device, sizeof(if_name));

		if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
			printf("Opened %s\n", ifreq.ifr_name);
			return tun_fd;
		}

		if (errno != EBUSY) {
			warn("open_tun: ioctl[TUNSETIFF]: %s", strerror(errno));
			return -1;
		}
	} else {
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(ifreq.ifr_name, IFNAMSIZ, "dns%d", i);

			if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
				printf("Opened %s\n", ifreq.ifr_name);
				snprintf(if_name, sizeof(if_name), "dns%d", i);
				return tun_fd;
			}

			if (errno != EBUSY) {
				warn("open_tun: ioctl[TUNSETIFF]: %s", strerror(errno));
				return -1;
			}
		}

		warn("open_tun: Couldn't set interface name");
	}
	return -1;
}

#else /* BSD */

int 
open_tun(const char *tun_device) 
{
	int i;
	int tun_fd;
	char tun_name[50];

	if (tun_device != NULL) {
		snprintf(tun_name, sizeof(tun_name), "/dev/%s", tun_device);
		strncpy(if_name, tun_device, sizeof(if_name));

		if ((tun_fd = open(tun_name, O_RDWR)) < 0) {
			warn("open_tun: %s: %s", tun_name, strerror(errno));
			return -1;
		}

		printf("Opened %s\n", tun_name);
		return tun_fd;
	} else {
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(tun_name, sizeof(tun_name), "/dev/tun%d", i);

			if ((tun_fd = open(tun_name, O_RDWR)) >= 0) {
				printf("Opened %s\n", tun_name);
				snprintf(if_name, sizeof(if_name), "tun%d", i);
				return tun_fd;
			}

			if (errno == ENOENT)
				break;
		}

		warn("open_tun: Failed to open tunneling device");
	}

	return -1;
}

#endif /* !LINUX */

void 
close_tun(int tun_fd) 
{
	if (tun_fd >= 0)
		close(tun_fd);
}

int 
write_tun(int tun_fd, char *data, int len) 
{
#if defined (FREEBSD) || defined (DARWIN) || defined(NETBSD)
	data += 4;
	len -= 4;
#else /* !FREEBSD/DARWIN */
#ifdef LINUX
	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x08;
	data[3] = 0x00;
#else /* OPENBSD */
	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x02;
#endif /* !LINUX */
#endif /* FREEBSD */

	if (write(tun_fd, data, len) != len) {
		warn("write_tun");
		return 1;
	}
	return 0;
}

int 
read_tun(int tun_fd, char *buf, int len) 
{
#if defined (FREEBSD) || defined (DARWIN) || defined(NETBSD)
	/* FreeBSD/Darwin/NetBSD has no header */
	return read(tun_fd, buf + 4, len - 4) + 4;
#else /* !FREEBSD */
	return read(tun_fd, buf, len);
#endif /* !FREEBSD */
}

int
tun_setip(const char *ip)
{
	char cmdline[512];

	if (inet_addr(ip) != INADDR_NONE) {
		snprintf(cmdline, sizeof(cmdline), 
				"/sbin/ifconfig %s %s %s netmask 255.255.255.0",
				if_name,
				ip,
				ip);
		
		printf("Setting IP of %s to %s\n", if_name, ip);
#ifndef LINUX
		int r;

		r = system(cmdline);
		if(r != 0) {
			return r;
		} else {
			snprintf(cmdline, sizeof(cmdline),
					"/sbin/route add %s/24 %s",
					ip, ip);
		}
		printf("Adding route %s/24 to %s\n", ip, ip);
#endif
		return system(cmdline);
	} else {
		printf("Invalid IP: %s!\n", ip);
	}

	return 1;
}

int 
tun_setmtu(const int mtu)
{
	char cmdline[512];

	if (mtu > 200 && mtu < 1500) {
		snprintf(cmdline, sizeof(cmdline), 
				"/sbin/ifconfig %s mtu %d",
				if_name,
				mtu);
		
		printf("Setting MTU of %s to %d\n", if_name, mtu);
		return system(cmdline);
	} else {
		warn("MTU out of range: %d\n", mtu);
	}

	return 1;
}

