/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <time.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "dns.h"

static int host2dns(const char *, char *, int);

struct sockaddr_in peer;
char topdomain[256];

// Current IP packet
int packetlen;
char activepacket[4096];

int outid;
int outbuflen;
char outbuf[64*1024];

static int
readname(char *packet, char *dst, char *src)
{
	char l;
	int len;
	int offset;

	len = 0;

	while(*src) {
		l = *src++;
		len++;

		if(l & 0x80 && l & 0x40) {
			offset = ((src[-1] & 0x3f) << 8) | src[0];		
			readname(packet, dst, packet + offset);
			dst += strlen(dst);
			break;
		}

		while(l) {
			*dst++ = *src++;
			l--;
			len++;
		}

		*dst++ = '.';
	}

	*dst = '\0';
	src++;
	len++;

	return len;
}

#define READNAME(packet, dst, src) (src) += readname((packet), (dst), (src));

#define READSHORT(dst, src) \
	(dst) = ntohs(*(short*)(src)); (src)+=2; 

#define READLONG(dst, src) \
	(dst) = ntohl(*(long*)(src)); (src)+=4; 

#define READDATA(dst, src, len) \
	memcpy((dst), (src), (len)); (src)+=(len);

int 
open_dnsd(const char *domain) 
{
	int fd;
	int flag;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		warn("socket");
		return 0;
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		warn("bind");
		return 0;
	}

	printf("Opened UDP socket\n");
	
	// Save top domain used
	strncpy(topdomain, domain, sizeof(topdomain) - 2);
	topdomain[sizeof(topdomain) - 1] = 0;

	packetlen = 0;

	return fd;
}

void
close_dnsd(int fd)
{
	close(fd);
}

static int
host2dns(const char *host, char *buffer, int size)
{
	char *h;
	char *p;
	char *word;

	h = strdup(host);
	memset(buffer, 0, size);
	p = buffer;
	
	word = strtok(h, ".");
	while(word) {
		*p++ = (char)strlen(word);
		memcpy(p, word, strlen(word));
		p += strlen(word);

		word = strtok(NULL, ".");
	}

	*p++ = 0;

	free(h);

	return p - buffer;
}

int
dnsd_haspacket()
{
	return (outbuflen > 0);
}

void
dnsd_queuepacket(const char *buf, const int buflen)
{
	memcpy(outbuf, buf, buflen);	

	outbuflen = buflen;
	outid++;
}

static void
dnsd_respond(int fd, char *name, short type, short id, struct sockaddr_in from)
{
	int len;
	char *p;
	char buf[1024];
	HEADER *header;

	memset(buf, 0, sizeof(buf));

	len = 0;
	header = (HEADER*)buf;	

	header->id = htons(id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	header->qdcount = htons(1);
	header->ancount = htons(1);

	p = buf + sizeof(HEADER);
	
	p += host2dns(name, p, strlen(name));
	PUTSHORT(type, p);
	PUTSHORT(C_IN, p);
	
	p += host2dns(name, p, strlen(name));	
	PUTSHORT(type, p);
	PUTSHORT(C_IN, p);
	PUTLONG(0, p);

	if(outbuflen > 0) {
		printf("%d\n", outid);
		PUTSHORT(outbuflen, p);
		memcpy(p, outbuf, outbuflen);
		p += outbuflen;
	} else {
		PUTSHORT(0, p);
	}

	len = p - buf;
	printf("Responding with %d\n", len);
	sendto(fd, buf, len, 0, (struct sockaddr*)&from, sizeof(from));

	outbuflen = 0;
}

int
dnsd_read(int fd, char *buf, int buflen)
{
	int r;
	short id;
	short type;
	short class;
	short qdcount;
	char *data;
	char name[255];
	HEADER *header;
	socklen_t addrlen;
	char packet[64*1024];
	struct sockaddr_in from;

	char lastblock;
	char *np;
	char *domainstart;
	int namelen;
	char *packetp;
	int datalen;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

	printf("Read %d bytes DNS query from %s\n", r, inet_ntoa(from.sin_addr));

	if(r == -1) {
		perror("recvfrom");
	} else {
		header = (HEADER*)packet;
		
		id = ntohs(header->id);

		data = packet + sizeof(HEADER);

		if(!header->qr) {
			qdcount = ntohs(header->qdcount);		

			if(qdcount == 1) {
				bzero(name, sizeof(name));
				READNAME(packet, name, data);
				READSHORT(type, data);
				READSHORT(class, data);
				
				dnsd_respond(fd, name, type, id, from);
				
				lastblock = name[0] - '0';
				np = name;
				np++; // skip first byte, it has only fragmentation info
				domainstart = strstr(np, topdomain);
				if (!domainstart) {
					fprintf(stderr, "Resolved domain does not end with %s! Ignoring packet\n", topdomain);
					return 0;
				}
				namelen = (int) domainstart - (int) np;
				*domainstart = '\0';
				packetp = activepacket;
				packetp += packetlen;
				while (np < domainstart && packetlen < sizeof(activepacket)) {
					if (*np == '.') {
						np++;
					} 
					sscanf(np, "%02X", &r);
					*packetp = r & 0xFF;
					np += 2;
					packetp++;
					packetlen++;
				}
				if (lastblock && packetlen < 2) {
					// Skipping ping packet
					packetlen = 0;
					return 0;
				}
				if (lastblock) {
					datalen = MIN(packetlen, buflen);
					memcpy(buf, activepacket, datalen);
					packetlen = 0;
					printf("Got full packet, returning %d bytes!\n", datalen);
					return datalen;
				} else {
					return 0;
				}
			}
		}
	}

	return 0;
}
