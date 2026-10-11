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
#include "common.h"
#include "compat.h"
#include "tun.h"
#include "wintun.h"

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>

DWORD WINAPI tun_reader(LPVOID arg);
struct tun_data {
	WINTUN_SESSION_HANDLE session;
	int sock;
	struct sockaddr_storage addr;
	int addrlen;
};

static struct tun_data data;
static char if_name[250];
static NET_LUID luid;

#define WINTUN_RING_CAPACITY 0x400000 /* 4 MiB ring buffer */

static HMODULE wintun_module = NULL;
static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static WINTUN_ADAPTER_HANDLE adapter_handle = NULL;
static WINTUN_SESSION_HANDLE session_handle = NULL;

static int
wintun_init(void)
{
	if (wintun_module)
		return 0;
	wintun_module = LoadLibraryExW(L"wintun.dll", NULL,
		LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!wintun_module)
		return -1;

#define RESOLVE_FUNC(Name) \
	((Name = (__typeof__(Name))(uintptr_t)GetProcAddress(wintun_module, #Name)) == NULL)
	if (RESOLVE_FUNC(WintunCreateAdapter) ||
	    RESOLVE_FUNC(WintunOpenAdapter) ||
	    RESOLVE_FUNC(WintunCloseAdapter) ||
	    RESOLVE_FUNC(WintunStartSession) ||
	    RESOLVE_FUNC(WintunEndSession) ||
	    RESOLVE_FUNC(WintunGetReadWaitEvent) ||
	    RESOLVE_FUNC(WintunReceivePacket) ||
	    RESOLVE_FUNC(WintunReleaseReceivePacket) ||
	    RESOLVE_FUNC(WintunAllocateSendPacket) ||
	    RESOLVE_FUNC(WintunSendPacket)) {
		FreeLibrary(wintun_module);
		wintun_module = NULL;
		return -1;
	}
#undef RESOLVE_FUNC
	return 0;
}

DWORD WINAPI tun_reader(LPVOID arg)
{
	struct tun_data *tun = arg;
	int sock = open_dns_from_host("127.0.0.1", 0, AF_INET, 0);
	HANDLE read_event = WintunGetReadWaitEvent(tun->session);

	while(TRUE) {
		DWORD packet_size;
		BYTE *packet = WintunReceivePacket(tun->session, &packet_size);
		if (packet) {
			sendto(sock, (const char*)packet, packet_size, 0,
				(struct sockaddr*) &(tun->addr), tun->addrlen);
			WintunReleaseReceivePacket(tun->session, packet);
		} else {
			if (GetLastError() == ERROR_NO_MORE_ITEMS) {
				WaitForSingleObject(read_event, INFINITE);
			} else {
				break;
			}
		}
	}

	return 0;
}

int
open_tun(const char *tun_device)
{
	wchar_t wname[250];
	int tunfd;
	struct sockaddr_storage localsock;
	socklen_t localsock_len;

	if(wintun_init()) {
		warnx("Could not load wintun.dll");
		return -1;
	}

	if (tun_device) {
		MultiByteToWideChar(CP_UTF8, 0, tun_device, -1, wname, ARRAYSIZE(wname));
		snprintf(if_name, sizeof(if_name), "%s", tun_device);
	} else {
		wcscpy_s(wname, ARRAYSIZE(wname), L"DNS Tunnel");
		snprintf(if_name, sizeof(if_name), "DNS Tunnel");
	}
	fprintf(stderr, "Opening Wintun interface '%s'...\n", if_name);

	adapter_handle = WintunOpenAdapter(wname);
	if (!adapter_handle) {
		adapter_handle = WintunCreateAdapter(wname, L"iodine", NULL);
	}
	if (!adapter_handle) {
		warnx("open_tun: Could not create or open Wintun adapter '%s'.", if_name);
		return -1;
	}
	ConvertInterfaceAliasToLuid(wname, &luid);
	session_handle = WintunStartSession(adapter_handle, WINTUN_RING_CAPACITY);
	if (!session_handle) {
		warnx("Failed to start Wintun session");
		WintunCloseAdapter(adapter_handle);
		adapter_handle = NULL;
		return -1;
	}

	/* Use a UDP connection to forward packets from tun,
	 * so we can still use select() in main code.
	 * A thread does blocking reads on the tun device and
	 * sends data as udp to this socket */
	if (get_addr("127.0.0.1", 55353, AF_INET, 0, &localsock, &localsock_len))
        return -1;
	tunfd = open_dns(&localsock, localsock_len);

	data.session = session_handle;
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
	(void)tun_fd;
	if (len < 4)
		return -1;

	/* Supplied packet has space for header, which is not needed */
	data += 4;
	len -= 4;

	BYTE* packet = WintunAllocateSendPacket(session_handle, len);
	if (!packet) {
		return -1;
	}
	memcpy(packet, data, len);
	WintunSendPacket(session_handle, packet);
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
	in_addr_t localaddr;
	DWORD status;
	MIB_UNICASTIPADDRESS_ROW ip_row;
	PMIB_UNICASTIPADDRESS_TABLE table = NULL;
	(void)other_ip;

	if (build_netmask(netbits, &netmask)) {
		fprintf(stderr, "Invalid netmask: %d!\n", netbits);
		return 1;
	}

	localaddr = inet_addr(ip);
	if (localaddr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP: %s!\n", ip);
		return 1;
	}

	/* Remove earlier IP addresses on interface */
	if (GetUnicastIpAddressTable(AF_INET, &table) == NO_ERROR) {
		for (DWORD i = 0; i < table->NumEntries; i++) {
			if (table->Table[i].InterfaceLuid.Value == luid.Value) {
				DeleteUnicastIpAddressEntry(&table->Table[i]);
			}
		}
		FreeMibTable(table);
	}

	fprintf(stderr, "Setting IP of interface '%s' to %s\n", if_name, ip);
	InitializeUnicastIpAddressEntry(&ip_row);
	ip_row.InterfaceLuid = luid;
	ip_row.OnLinkPrefixLength = netbits;
	ip_row.Address.Ipv4.sin_family = AF_INET;
	ip_row.Address.Ipv4.sin_addr.s_addr = localaddr;
	status = CreateUnicastIpAddressEntry(&ip_row);
	if (status != NO_ERROR) {
		warnx("tun_setmtu: CreateUnicastIpAddressEntry failed: status %lu", status);
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
	fprintf(stderr, "Setting MTU of '%s' to %u\n", if_name, mtu);
	res = SetIpInterfaceEntry(&row);
	if (res != NO_ERROR) {
		warnx("tun_setmtu: SetIpInterfaceEntry failed: status %d", res);
		return 1;
	}
	return 0;
}

