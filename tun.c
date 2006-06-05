/*
 * Copyright (c) 2006 
 * Bjorn Andersson <flex@kryo.se>,
 * Erik Ekman <yarrick@kryo.se>
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include "tun.h"

#define TUN_MAX_TRY 50

int tun_fd = -1;
char *tun_device = NULL;

#ifdef LINUX

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

int 
open_tun() 
{
	struct ifreq ifreq;
	int i;

	if (tun_device == NULL)
		tun_device = "/dev/net/tun";

	if ((tun_fd = open(tun_device, O_RDWR)) < 0) 
		err(1, "open_tun: %s: %s", tun_device, strerror(errno));

	bzero(&ifreq, sizeof(ifreq));

	ifreq.ifr_flags = IFF_TUN; 

	for (i = 0; i < TUN_MAX_TRY; i++) {
		snprintf(ifreq.ifr_name, IFNAMSIZ, "tun%d", i);

		if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
			printf("opened %s\n", ifreq.ifr_name);
			return 0;
		}

		if (errno != EBUSY) 
			err(1, "open_tun: ioctl[TUNSETIFF]: %s", strerror(errno));
	}

	err(1, "open_tun: Couldn't set interface name.\n");

	return 1;
}

#else /* BSD */

int 
open_tun() 
{
	if (tun_device != NULL) {
		if ((tun_fd = open(tun_device, O_RDWR)) < 0) 
			err(1, "open_tun: %s: %s", tun_device, strerror(errno));
	} else {
		char tun_name[50];
		int i;

		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(tun_name, sizeof(tun_name), "/dev/tun%d", i);

			if ((tun_fd = open(tun_name, O_RDWR)) >= 0)
				return 0;

			if (errno == ENOENT)
				break;
		}

		err(1, "open_tun: Failed to open tunneling device.");
	}

	return 0;
}

#endif /* LINUX */

void 
close_tun() 
{
	if (tun_fd >= 0)
		close(tun_fd);
}

int 
write_tun(uint8_t *buf, int len) 
{
	if (write(tun_fd, buf, len) != len) 
		err(1, "write_tun: %s", strerror(errno));

	return 0;
}

int 
read_tun(uint8_t *buf, int len) 
{
	return read(tun_fd, buf, len);
}

