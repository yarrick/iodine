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

#include "config.h"
#include "compat.h"
#include "run_as.h"

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>

DWORD WINAPI tun_reader(LPVOID arg);
struct tun_data {
	HANDLE tun;
	int sock;
	struct sockaddr_storage addr;
	int addrlen;
};

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

#include "tun.h"
#include "common.h"

static char if_name[250];
static NET_LUID luid;

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
    run_thread_as_restricted_privilege_user();

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
	wchar_t wname[256];
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

	MultiByteToWideChar(CP_ACP, 0, if_name, -1, wname, ARRAYSIZE(wname));
	ConvertInterfaceAliasToLuid(wname, &luid);

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

void
close_tun(int tun_fd)
{
	if (tun_fd >= 0)
		close(tun_fd);
}

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

int
tun_setip(const char *ip, const char *other_ip, int netbits)
{
	struct in_addr netmask;
	int r;
	DWORD status;
	DWORD ipdata[3];
	struct in_addr addr;
	DWORD len;
	MIB_UNICASTIPADDRESS_ROW ip_row;

	if (build_netmask(netbits, &netmask)) {
		fprintf(stderr, "Invalid netmask: %d!\n", netbits);
		return 1;
	}

	if (inet_addr(ip) == INADDR_NONE) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}

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
		ipdata[0] = (DWORD) addr.s_addr;        /* local ip addr */
		ipdata[1] = netmask.s_addr & ipdata[0]; /* network addr */
		ipdata[2] = (DWORD) netmask.s_addr;     /* netmask */
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

	fprintf(stderr, "Setting IP of interface '%s' to %s\n", if_name, ip);
	InitializeUnicastIpAddressEntry(&ip_row);
	ip_row.InterfaceLuid = luid;
	ip_row.OnLinkPrefixLength = netbits;
	ip_row.Address.Ipv4.sin_family = AF_INET;
	ip_row.Address.Ipv4.sin_addr = addr;
	status = CreateUnicastIpAddressEntry(&ip_row);
	if (status == ERROR_OBJECT_ALREADY_EXISTS) {
		status = SetUnicastIpAddressEntry(&ip_row);
		if (status != NO_ERROR) {
			warnx("tun_setmtu: SetUnicastIpAddressEntry failed: status %d", status);
			return 1;
		}
	} else if (status != NO_ERROR) {
		warnx("tun_setmtu: CreateUnicastIpAddressEntry failed: status %d", status);
		return 1;
	}
	return 0;
}

int
tun_setmtu(const unsigned mtu)
{
	MIB_IPINTERFACE_ROW row;
	NETIO_STATUS res;

	if (mtu <= 200 || mtu > 1500) {
		warn("MTU out of range: %u\n", mtu);
		return 1;
	}

	InitializeIpInterfaceEntry(&row);
	row.Family = AF_INET;
	row.InterfaceLuid = luid;
	row.NlMtu = mtu;
	fprintf(stderr, "Setting MTU of %s to %u\n", if_name, mtu);
	res = SetIpInterfaceEntry(&row);
	if (res != NO_ERROR) {
		warnx("tun_setmtu: SetIpInterfaceEntry failed: status %d", res);
		return 1;
	}
	return 0;
}

