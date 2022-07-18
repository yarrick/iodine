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
#include <fcntl.h>

#ifdef DARWIN
#include <ctype.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#endif

#ifndef IFCONFIGPATH
#define IFCONFIGPATH "PATH=/sbin:/bin "
#endif

#ifndef ROUTEPATH
#define ROUTEPATH "PATH=/sbin:/bin "
#endif

#ifdef WINDOWS32
#include "windows.h"
#include <winioctl.h>

static HANDLE dev_handle;
static struct tun_data data;

static void get_name(char *ifname, int namelen, char *dev_name);

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_CONFIG_TUN       TAP_CONTROL_CODE(10, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define TAP_ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_DEVICE_SPACE "\\\\.\\Global\\"
#define TAP_VERSION_ID_0801 "tap0801"
#define TAP_VERSION_ID_0901 "tap0901"
#define TAP_VERSION_ID_0901_ROOT "root\\tap0901"
#define KEY_COMPONENT_ID "ComponentId"
#define NET_CFG_INST_ID "NetCfgInstanceId"
#else
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TUN_MAX_TRY 50
#endif

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
		strncpy(ifreq.ifr_name, tun_device, IFNAMSIZ);
		ifreq.ifr_name[IFNAMSIZ-1] = '\0';
		strncpy(if_name, tun_device, sizeof(if_name));
		if_name[sizeof(if_name)-1] = '\0';

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

#elif WINDOWS32

static void
get_device(char *device, int device_len, const char *wanted_dev)
{
	LONG status;
	HKEY adapter_key;
	int index;

	index = 0;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TAP_ADAPTER_KEY, 0, KEY_READ, &adapter_key);

	if (status != ERROR_SUCCESS) {
		warnx("Error opening registry key " TAP_ADAPTER_KEY);
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
			warnx("Error enumerating subkeys of registry key " TAP_ADAPTER_KEY);
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
			strncmp(TAP_VERSION_ID_0901, component, strlen(TAP_VERSION_ID_0901)) == 0 ||
			strncmp(TAP_VERSION_ID_0901_ROOT, component, strlen(TAP_VERSION_ID_0901_ROOT)) == 0) {
			/* We found a TAP32 device, get its NetCfgInstanceId */
			char iid_string[256] = NET_CFG_INST_ID;

			status = RegQueryValueEx(device_key, iid_string, NULL, &datatype, (LPBYTE) device, (DWORD *) &device_len);
			if (status != ERROR_SUCCESS || datatype != REG_SZ) {
				warnx("Error reading registry key %s\\%s on TAP device", unit, iid_string);
			} else {
				/* Done getting GUID of TAP device,
				 * now check if the name is the requested one */
				if (wanted_dev) {
					char name[250];
					get_name(name, sizeof(name), device);
					if (strncmp(name, wanted_dev, strlen(wanted_dev))) {
						/* Skip if name mismatch */
						goto next;
					}
				}
				/* Get the if name */
				get_name(if_name, sizeof(if_name), device);
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

static void
get_name(char *ifname, int namelen, char *dev_name)
{
	char path[256];
	char name_str[256] = "Name";
	LONG status;
	HKEY conn_key;
	DWORD len;
	DWORD datatype;

	memset(ifname, 0, namelen);

	snprintf(path, sizeof(path), NETWORK_KEY "\\%s\\Connection", dev_name);
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &conn_key);
	if (status != ERROR_SUCCESS) {
		fprintf(stderr, "Could not look up name of interface %s: error opening key\n", dev_name);
		RegCloseKey(conn_key);
		return;
	}
	len = namelen;
	status = RegQueryValueEx(conn_key, name_str, NULL, &datatype, (LPBYTE)ifname, &len);
	if (status != ERROR_SUCCESS || datatype != REG_SZ) {
		fprintf(stderr, "Could not look up name of interface %s: error reading value\n", dev_name);
		RegCloseKey(conn_key);
		return;
	}
	RegCloseKey(conn_key);
}

DWORD WINAPI tun_reader(LPVOID arg)
{
	struct tun_data *tun = arg;
	char buf[64*1024];
	int len;
	int res;
	OVERLAPPED olpd;
	int sock;

	sock = open_dns_from_host("127.0.0.1", 0, AF_INET, 0);

	olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	while(TRUE) {
		olpd.Offset = 0;
		olpd.OffsetHigh = 0;
		res = ReadFile(tun->tun, buf, sizeof(buf), (LPDWORD) &len, &olpd);
		if (!res) {
			WaitForSingleObject(olpd.hEvent, INFINITE);
			res = GetOverlappedResult(dev_handle, &olpd, (LPDWORD) &len, FALSE);
			res = sendto(sock, buf, len, 0, (struct sockaddr*) &(tun->addr),
				tun->addrlen);
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
	struct sockaddr_storage localsock;
	int localsock_len;

	memset(adapter, 0, sizeof(adapter));
	memset(if_name, 0, sizeof(if_name));
	get_device(adapter, sizeof(adapter), tun_device);

	if (strlen(adapter) == 0 || strlen(if_name) == 0) {
		if (tun_device) {
			warnx("No TAP adapters found. Try without -d.");
		} else {
			warnx("No TAP adapters found. Version 0801 and 0901 are supported.");
		}
		return -1;
	}

	fprintf(stderr, "Opening device %s\n", if_name);
	snprintf(tapfile, sizeof(tapfile), "%s%s.tap", TAP_DEVICE_SPACE, adapter);
	dev_handle = CreateFile(tapfile, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
	if (dev_handle == INVALID_HANDLE_VALUE) {
		warnx("Could not open device!");
		return -1;
	}

	/* Use a UDP connection to forward packets from tun,
	 * so we can still use select() in main code.
	 * A thread does blocking reads on tun device and
	 * sends data as udp to this socket */

	localsock_len = get_addr("127.0.0.1", 55353, AF_INET, 0, &localsock);
	tunfd = open_dns(&localsock, localsock_len);

	data.tun = dev_handle;
	memcpy(&(data.addr), &localsock, localsock_len);
	data.addrlen = localsock_len;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tun_reader, &data, 0, NULL);

	return tunfd;
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
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

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

	strncpy(if_name, ifname, sizeof(if_name));

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
		strncpy(if_name, tun_device, sizeof(if_name));
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

#ifdef WINDOWS32
int
write_tun(int tun_fd, char *data, size_t len)
{
	DWORD written;
	DWORD res;
	OVERLAPPED olpd;

	data += 4;
	len -= 4;

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
	return 0;
}

ssize_t
read_tun(int tun_fd, char *buf, size_t len)
{
	int bytes;
	memset(buf, 0, 4);

	bytes = recv(tun_fd, buf + 4, len - 4, 0);
	if (bytes < 0) {
		return bytes;
	} else {
		return bytes + 4;
	}
}
#else
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
#endif

int
tun_setip(const char *ip, const char *other_ip, int netbits)
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
#else
	const char *display_ip;
#ifndef LINUX
	struct in_addr netip;
#endif
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
# ifdef FREEBSD
	display_ip = other_ip; /* FreeBSD wants other IP as second IP */
# else
	display_ip = ip;
# endif
	snprintf(cmdline, sizeof(cmdline),
			IFCONFIGPATH "ifconfig %s %s %s netmask %s",
			if_name,
			ip,
			display_ip,
			inet_ntoa(net));

	fprintf(stderr, "Setting IP of %s to %s\n", if_name, ip);
#ifndef LINUX
	netip.s_addr = inet_addr(ip);
	netip.s_addr = netip.s_addr & net.s_addr;
	r = system(cmdline);
	if (r != 0) {
		return r;
	} else {

		snprintf(cmdline, sizeof(cmdline),
				ROUTEPATH "route add %s/%d %s",
				inet_ntoa(netip), netbits, ip);
	}
	fprintf(stderr, "Adding route %s/%d to %s\n", inet_ntoa(netip), netbits, ip);
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
				IFCONFIGPATH "ifconfig %s mtu %u",
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

