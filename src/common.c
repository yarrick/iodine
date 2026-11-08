/* Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 * Copyright (c) 2007 Albert Lee <trisk@acm.jhu.edu>.
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

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>

#include "config.h"

#ifdef WINDOWS
#include <winsock2.h>
#include <windows.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "common.h"
#include "compat.h"

/* The raw header used when not using DNS protocol */
const unsigned char raw_header[RAW_HDR_LEN] = { 0x10, 0xd1, 0x9e, 0x00 };

char *
format_inaddr(struct in_addr *addr)
{
	static char dst[INET_ADDRSTRLEN + 1];
	memset(dst, 0, sizeof(dst));
	if (inet_ntop(AF_INET, addr, dst, sizeof(dst)) == NULL) {
		dst[0] = '?';
	}
	return dst;
}

char *
format_addr(struct sockaddr_storage *sockaddr, socklen_t sockaddr_len)
{
	static char dst[INET6_ADDRSTRLEN + 1];
#ifdef WINDOWS
	int wsa_error = WSAGetLastError();
#endif

	memset(dst, 0, sizeof(dst));
	if (sockaddr->ss_family == AF_INET &&
	    (size_t) sockaddr_len >= sizeof(struct sockaddr_in)) {
		getnameinfo((struct sockaddr *)sockaddr, sockaddr_len,
			    dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
	} else if (sockaddr->ss_family == AF_INET6 &&
		   (size_t) sockaddr_len >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sockaddr;
		if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
			struct in_addr ia;
			/* Get mapped v4 addr from last 32bit field */
			memcpy(&ia.s_addr, &addr->sin6_addr.s6_addr[12], sizeof(ia));
			return format_inaddr(&ia);
		} else {
			getnameinfo((struct sockaddr *)sockaddr, sockaddr_len,
				    dst, sizeof(dst) - 1, NULL, 0, NI_NUMERICHOST);
		}
	} else {
		dst[0] = '?';
	}
#ifdef WINDOWS
	if (WSAGetLastError() == 0) {
		WSASetLastError(wsa_error);
	}
#endif
	return dst;
}

int
get_addr(char *host, int port, int addr_family, int flags,
	 struct sockaddr_storage *out, socklen_t *outlen)
{
	struct addrinfo hints, *addr;
	int res;
	char portnum[8];

	if (out == NULL) {
		return -1;
	}

	memset(portnum, 0, sizeof(portnum));
	snprintf(portnum, sizeof(portnum) - 1, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = addr_family;
#if defined(WINDOWS) || defined(HAIKU) || defined(OPENBSD)
	/* AI_ADDRCONFIG misbehaves on windows/haiku, and does not exist in OpenBSD */
	hints.ai_flags = flags;
#else
	hints.ai_flags = AI_ADDRCONFIG | flags;
#endif
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	res = getaddrinfo(host, portnum, &hints, &addr);
	if (res != 0) {
		return -1;
	}

	/* Grab first result */
	memcpy(out, addr->ai_addr, addr->ai_addrlen);
	if (outlen) *outlen = addr->ai_addrlen;
	freeaddrinfo(addr);
	return 0;
}

int
build_netmask(int netbits, struct in_addr *addr)
{
	uint32_t netmask;
	int i;
	/* netbits is the CIDR prefix length (1..32). Out-of-range values
	   would make "netmask <<= (32 - netbits)" below undefined
	   behavior; reject them. Callers normally validate already, but
	   the netmask can come from untrusted input (client handshake
	   reply). */
	if (netbits < 1 || netbits > 32) {
		return 1;
	}

	netmask = 0;
	for (i = 0; i < netbits; i++) {
		netmask = (netmask << 1) | 1;
	}
	netmask <<= (32 - netbits);
	addr->s_addr = htonl(netmask);
	return 0;
}

int
check_topdomain(char *str, int allow_wildcard, char **errormsg)
{
	unsigned int i;
	int dots = 0;
	int chunklen = 0;

	if (strlen(str) < 3) {
		if (errormsg) *errormsg = "Too short (< 3)";
		return 1;
	}
	if (strlen(str) > 128) {
		if (errormsg) *errormsg = "Too long (> 128)";
		return 1;
	}

	if (str[0] == '.') {
		if (errormsg) *errormsg = "Starts with a dot";
		return 1;
	}

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '.') {
			dots++;
			if (chunklen == 0) {
				if (errormsg) *errormsg = "Consecutive dots";
				return 1;
			}
			if (chunklen > 63) {
				if (errormsg) *errormsg = "Too long domain part (> 63)";
				return 1;
			}
			chunklen = 0;
		} else {
			chunklen++;
		}
		if ((str[i] >= 'a' && str[i] <= 'z') || (str[i] >= 'A' && str[i] <= 'Z') ||
				isdigit(str[i]) || str[i] == '-' || str[i] == '.') {
			continue;
		} else if (allow_wildcard && str[i] == '*') {
			/* First char allowed to be wildcard, if followed by dot */
			if (i == 0) {
				if (str[i+1] == '.') {
					continue;
				}
				if (errormsg) *errormsg = "Wildcard (*) must be followed by dot";
				return 1;
			} else {
				if (errormsg) *errormsg = "Wildcard (*) only allowed as first char";
				return 1;
			}
		} else {
			if (errormsg) *errormsg = "Contains illegal character (allowed: [a-zA-Z0-9-.])";
			return 1;
		}
	}

	if (dots == 0) {
		if (errormsg) *errormsg = "No dots";
		return 1;
	}
	if (chunklen == 0) {
		if (errormsg) *errormsg = "Ends with a dot";
		return 1;
	}
	if (chunklen > 63) {
		if (errormsg) *errormsg = "Too long domain part (> 63)";
		return 1;
	}

	return 0;
}

int
query_datalen(const char *qname, const char *topdomain)
{
	/* Return number of data bytes embedded in DNS query name,
	 * or -1 if domains do not match.
	 */
	int qpos = strlen(qname);
	int tpos = strlen(topdomain);
	if (tpos < 3 || qpos < tpos) {
		/* Domain or query name too short */
		return -1;
	}
	/* Backward string compare */
	qpos--;
	tpos--;
	while (qpos >= 0) {
		if (topdomain[tpos] == '*') {
			/* Wild match, is first in topdomain */
			if (qname[qpos] == '*') {
				/* Don't match against stars in query name */
				return -1;
			} else if (qpos == 0 || qname[qpos-1] == '.') {
				/* Reached start of query name or chunk separator */
				return qpos;
			}
			qpos--;
		} else if (ascii_tolower(qname[qpos]) == ascii_tolower(topdomain[tpos])) {
			/* Matching char, exclude wildcard in query name */
			if (tpos == 0) {
				/* Fully matched domain */
				if (qpos == 0 || qname[qpos-1] == '.') {
					/* Start of name or has dot before matching topdomain */
					return qpos;
				}
				/* Query name has longer chunk than topdomain */
				return -1;
			}
			tpos--;
			qpos--;
		} else {
			return -1;
		}
	}
	return -1;
}

int
recent_seqno(int ourseqno, int gotseqno)
/* Return 1 if we've seen gotseqno recently (current or up to 3 back).
   Return 0 if gotseqno is new (or very old).
*/
{
	int i;
	for (i = 0; i < 4; i++, ourseqno--) {
		if (ourseqno < 0)
			ourseqno = 7;
		if (gotseqno == ourseqno)
			return 1;
	}
	return 0;
}

/* Set FD_CLOEXEC flag on file descriptor.
 * This stops it from being inherited by system() calls.
 */
void
fd_set_close_on_exec(int fd)
{
#if HAVE_FD_CLOEXEC
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		err(4, "Failed to get fd flags");
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		err(4, "Failed to set fd flags");
#endif
	(void)fd;
}

unsigned char
ascii_tolower(unsigned char c) {
	if (c >= 'A' && c <= 'Z') {
		return c | 0x20;
	}
	return c;
}
