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
#include "common.h"
#include "util.h"

char *get_resolvconf_addr(void)
{
	static char addr[16];
	char *rv = NULL;
#ifndef WINDOWS32
	char buf[80];
	FILE *fp;
#ifdef ANDROID
	fp = popen("getprop net.dns1", "r");
	if (fp == NULL)
		err(1, "getprop net.dns1 failed");
	if (fgets(buf, sizeof(buf), fp) == NULL)
		err(1, "read getprop net.dns1 failed");
	if (sscanf(buf, "%15s", addr) == 1)
		rv = addr;
	pclose(fp);
#else
	if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
		err(1, "/etc/resolv.conf");

	while (feof(fp) == 0) {
		fgets(buf, sizeof(buf), fp);

		if (sscanf(buf, "nameserver %15s", addr) == 1) {
			rv = addr;
			break;
		}
	}

	fclose(fp);
#endif
#else /* !WINDOWS32 */
	FIXED_INFO  *fixed_info;
	ULONG       buflen;
	DWORD       ret;

	fixed_info = malloc(sizeof(FIXED_INFO));
	buflen = sizeof(FIXED_INFO);

	if (GetNetworkParams(fixed_info, &buflen) == ERROR_BUFFER_OVERFLOW) {
		/* official ugly api workaround */
		free(fixed_info);
		fixed_info = malloc(buflen);
	}

	ret = GetNetworkParams(fixed_info, &buflen);
	if (ret == NO_ERROR) {
		strncpy(addr, fixed_info->DnsServerList.IpAddress.String, sizeof(addr));
		addr[15] = 0;
		rv = addr;
	}
	free(fixed_info);
#endif
	return rv;
}

#ifdef OPENBSD
void
socket_setrtable(int fd, int rtable)
{
#ifdef SO_RTABLE
	if (setsockopt (fd, IPPROTO_IP, SO_RTABLE, &rtable, sizeof(rtable)) == -1)
		err(1, "Failed to set routing table %d", rtable);
#else
	fprintf(stderr, "Routing domain support was not available at compile time.\n");
#endif
}
#endif
