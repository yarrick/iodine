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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WINDOWS32
#include <winsock2.h>
#include <winioctl.h>
#include "windows.h"

HANDLE dev_handle;
struct tun_data data;

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_CONFIG_TUN       TAP_CONTROL_CODE(10, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_DEVICE_SPACE "\\\\.\\Global\\"
#define TAP_VERSION_ID_0801 "tap0801"
#define TAP_VERSION_ID_0901 "tap0901"
#define KEY_COMPONENT_ID "ComponentId"
#define NET_CFG_INST_ID "NetCfgInstanceId"
#else
#include <err.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define TUN_MAX_TRY 50
#endif

#include "tun.h"
#include "common.h"

char if_name[50];

#ifndef WINDOWS32
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
		ifreq.ifr_name[IFNAMSIZ-1] = '\0';
		strncpy(if_name, tun_device, sizeof(if_name));
		if_name[sizeof(if_name)-1] = '\0';

		if (ioctl(tun_fd, TUNSETIFF, (void *) &ifreq) != -1) {
			fprintf(stderr, "Opened %s\n", ifreq.ifr_name);
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
				fprintf(stderr, "Opened %s\n", ifreq.ifr_name);
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
		if_name[sizeof(if_name)-1] = '\0';

		if ((tun_fd = open(tun_name, O_RDWR)) < 0) {
			warn("open_tun: %s: %s", tun_name, strerror(errno));
			return -1;
		}

		fprintf(stderr, "Opened %s\n", tun_name);
		return tun_fd;
	} else {
		for (i = 0; i < TUN_MAX_TRY; i++) {
			snprintf(tun_name, sizeof(tun_name), "/dev/tun%d", i);

			if ((tun_fd = open(tun_name, O_RDWR)) >= 0) {
				fprintf(stderr, "Opened %s\n", tun_name);
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
#else /* WINDOWS32 */
static void
get_device(char *device, int device_len)
{
	LONG status;
	HKEY adapter_key;
	int index;

	index = 0;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TAP_ADAPTER_KEY, 0, KEY_READ, &adapter_key);

	if (status != ERROR_SUCCESS) {
		warnx("Error opening registry key " TAP_ADAPTER_KEY );
		return;
	}
	
	while (TRUE) {
		char name[256];
		char unit[256];
		char component[256];

		char cid_string[256] = KEY_COMPONENT_ID;
		HKEY device_key;
		DWORD datatype;
		DWORD len;

		/* Iterate through all adapter of this kind */
		len = sizeof(name);
		status = RegEnumKeyEx(adapter_key, index, name, &len, NULL, NULL, NULL, NULL);
		if (status == ERROR_NO_MORE_ITEMS) {
			break;
		} else if (status != ERROR_SUCCESS) {
			warnx("Error enumerating subkeys of registry key " TAP_ADAPTER_KEY );
			break;
		}

		snprintf(unit, sizeof(unit), TAP_ADAPTER_KEY "\\%s", name);
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit, 0, KEY_READ, &device_key);
		if (status != ERROR_SUCCESS) {
			warnx("Error opening registry key %s", unit);
			goto next;
		}

		/* Check component id */
		len = sizeof(component);
		status = RegQueryValueEx(device_key, cid_string, NULL, &datatype, (LPBYTE)component, &len);
		if (status != ERROR_SUCCESS || datatype != REG_SZ) {
			goto next;
		}
		if (strncmp(TAP_VERSION_ID_0801, component, strlen(TAP_VERSION_ID_0801)) == 0 ||
			strncmp(TAP_VERSION_ID_0901, component, strlen(TAP_VERSION_ID_0901)) == 0) {
			/* We found a TAP32 device, get its NetCfgInstanceId */
			char iid_string[256] = NET_CFG_INST_ID;
			
			status = RegQueryValueEx(device_key, iid_string, NULL, &datatype, (LPBYTE) device, (DWORD *) &device_len);
			if (status != ERROR_SUCCESS || datatype != REG_SZ) {
				warnx("Error reading registry key %s\\%s on TAP device", unit, iid_string);
			} else {
				/* Done getting name of TAP device */
				RegCloseKey(device_key);
				return;
			}
		}
next:
		RegCloseKey(device_key);
		index++;
	}
	RegCloseKey(adapter_key);
}

DWORD WINAPI tun_reader(LPVOID arg)
{
	struct tun_data *tun = arg;
	char buf[64*1024];
	int len;
	int res;
	OVERLAPPED olpd;
	int sock;

	sock = open_dns(0, INADDR_ANY);

	olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	while(TRUE) {
		olpd.Offset = 0;
		olpd.OffsetHigh = 0;
		res = ReadFile(tun->tun, buf, sizeof(buf), (LPDWORD) &len, &olpd);
		if (!res) {
			WaitForSingleObject(olpd.hEvent, INFINITE);
			res = GetOverlappedResult(dev_handle, &olpd, (LPDWORD) &len, FALSE);
			res = sendto(sock, buf, len, 0, (struct sockaddr*) &(tun->addr), 
				sizeof(struct sockaddr_in));
		}
	}

	return 0;
}

int 
open_tun(const char *tun_device) 
{
	char adapter[256];
	char tapfile[512];
	int tunfd;
	in_addr_t local;

	memset(adapter, 0, sizeof(adapter));
	get_device(adapter, sizeof(adapter));

	if (strlen(adapter) == 0) {
		warnx("No TAP adapters found. See README-win32.txt for help.\n");
		return -1;
	}
	
	snprintf(tapfile, sizeof(tapfile), "%s%s.tap", TAP_DEVICE_SPACE, adapter);
	fprintf(stderr, "Opening device %s\n", tapfile);
	dev_handle = CreateFile(tapfile, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
	if (dev_handle == INVALID_HANDLE_VALUE) {
		return -1;
	}

	/* TODO get name of interface */
	strncpy(if_name, "dns", MIN(4, sizeof(if_name)));

	/* Use a UDP connection to forward packets from tun,
	 * so we can still use select() in main code.
	 * A thread does blocking reads on tun device and 
	 * sends data as udp to this socket */
	
	local = htonl(0x7f000001); /* 127.0.0.1 */
	tunfd = open_dns(55353, local);

	data.tun = dev_handle;
	memset(&(data.addr), 0, sizeof(data.addr));
	data.addr.sin_family = AF_INET;
	data.addr.sin_port = htons(55353);
	data.addr.sin_addr.s_addr = local;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tun_reader, &data, 0, NULL);
	
	return tunfd;
}
#endif 

void 
close_tun(int tun_fd) 
{
	if (tun_fd >= 0)
		close(tun_fd);
}

int 
write_tun(int tun_fd, char *data, size_t len) 
{
#if defined (FREEBSD) || defined (DARWIN) || defined(NETBSD) || defined(WINDOWS32)
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

#ifndef WINDOWS32
	if (write(tun_fd, data, len) != len) {
		warn("write_tun");
		return 1;
	}
#else /* WINDOWS32 */
	{
		DWORD written;
		DWORD res;
		OVERLAPPED olpd;

		olpd.Offset = 0;
		olpd.OffsetHigh = 0;
		olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		res = WriteFile(dev_handle, data, len, &written, &olpd);
		if (!res && GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(olpd.hEvent, INFINITE);
			res = GetOverlappedResult(dev_handle, &olpd, &written, FALSE);
			if (written != len) {
				return -1;
			}
		}
	}
#endif
	return 0;
}

ssize_t
read_tun(int tun_fd, char *buf, size_t len) 
{
#if defined (FREEBSD) || defined (DARWIN) || defined(NETBSD) || defined(WINDOWS32)
	/* FreeBSD/Darwin/NetBSD has no header */
	int bytes;
	bytes = recv(tun_fd, buf + 4, len, 0);
	if (bytes < 0) {
		return bytes;
	} else {
		return bytes + 4;
	}
#else /* !FREEBSD */
	return read(tun_fd, buf, len);
#endif /* !FREEBSD */
}

int
tun_setip(const char *ip, int netbits)
{
	char cmdline[512];
	int netmask;
	struct in_addr net;
	int i;
#ifndef LINUX
	int r;
#endif
#ifdef WINDOWS32
	DWORD status;
	DWORD ipdata[3];
	struct in_addr addr;
	DWORD len;
#endif

	netmask = 0;
	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	net.s_addr = htonl(netmask);

	if (inet_addr(ip) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}
#ifndef WINDOWS32
	snprintf(cmdline, sizeof(cmdline), 
			"/sbin/ifconfig %s %s %s netmask %s",
			if_name,
			ip,
			ip,
			inet_ntoa(net));
	
	fprintf(stderr, "Setting IP of %s to %s\n", if_name, ip);
#ifndef LINUX
	r = system(cmdline);
	if(r != 0) {
		return r;
	} else {
		snprintf(cmdline, sizeof(cmdline),
				"/sbin/route add %s/%d %s",
				ip, netbits, ip);
	}
	fprintf(stderr, "Adding route %s/%d to %s\n", ip, netbits, ip);
#endif
	return system(cmdline);
#else /* WINDOWS32 */

	/* Set device as connected */
	fprintf(stderr, "Enabling interface '%s'\n", if_name);
	status = 1;
	r = DeviceIoControl(dev_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, 
		sizeof(status), &status, sizeof(status), &len, NULL);
	if (!r) {
		fprintf(stderr, "Failed to enable interface\n");
		return -1;
	}
	
	if (inet_aton(ip, &addr)) {
		ipdata[0] = (DWORD) addr.s_addr;   /* local ip addr */
		ipdata[1] = net.s_addr & ipdata[0]; /* network addr */
		ipdata[2] = (DWORD) net.s_addr;    /* netmask */
	} else {
		return -1;
	}

	/* Tell ip/networkaddr/netmask to device for arp use */
	r = DeviceIoControl(dev_handle, TAP_IOCTL_CONFIG_TUN, &ipdata, 
		sizeof(ipdata), &ipdata, sizeof(ipdata), &len, NULL);
	if (!r) {
		fprintf(stderr, "Failed to set interface in TUN mode\n");
		return -1;
	}

	/* use netsh to set ip address */
	fprintf(stderr, "Setting IP of interface '%s' to %s (can take a few seconds)...\n", if_name, ip);
	snprintf(cmdline, sizeof(cmdline), "netsh interface ip set address \"%s\" static %s %s",
		if_name, ip, inet_ntoa(net));
	return system(cmdline);
#endif
}

int 
tun_setmtu(const unsigned mtu)
{
#ifndef WINDOWS32
	char cmdline[512];

	if (mtu > 200 && mtu <= 1500) {
		snprintf(cmdline, sizeof(cmdline), 
				"/sbin/ifconfig %s mtu %u",
				if_name,
				mtu);
		
		fprintf(stderr, "Setting MTU of %s to %u\n", if_name, mtu);
		return system(cmdline);
	} else {
		warn("MTU out of range: %u\n", mtu);
	}

	return 1;
#else /* WINDOWS32 */

	return 0;
#endif
}

