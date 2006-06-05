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
char activepacket[4096];
int lastlen;
int packetpos;
int packetlen;
uint16_t chunkid;

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
open_dns(const char *host, const char *domain) 
{
	int fd;
	int flag;
	struct sockaddr_in addr;
	struct hostent *h;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
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

	// Init dns target struct
	h = gethostbyname(host);
	if (!h) {
		perror("gethostbyname");
	}
	bzero(&peer, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(53);
	peer.sin_addr = *((struct in_addr *) h->h_addr);

	// Save top domain used
	strncpy(topdomain, domain, sizeof(topdomain) - 2);
	topdomain[sizeof(topdomain) - 1] = 0;

	// Init chunk id
	chunkid = 0;

	return fd;
}

void
close_dns(int fd)
{
	close(fd);
}

int
dns_sending()
{
	return (packetlen != 0);
}

static void
dns_send_chunk(int fd)
{
	int avail;
	char *p;

	p = activepacket;
	p += packetpos;
	avail = packetlen - packetpos;
	lastlen = dns_write(fd, ++chunkid, p, avail);
	printf("Sent %d bytes of %d remaining\n", lastlen, avail);
}

void
dns_handle_tun(int fd, char *data, int len)
{
	memcpy(activepacket, data, MIN(len, sizeof(activepacket)));
	lastlen = 0;
	packetpos = 0;
	packetlen = len;

	dns_send_chunk(fd);
}

static int
dns_handle_reply(int fd, char *data, int len)
{
	uint16_t id;
	char *p;

	p = data;
	READSHORT(id, p);

	// Handle ACKing
	if (dns_sending() && id == chunkid) {
		// Got ACK on sent packet
		packetpos += lastlen;
		if (packetpos == packetlen) {
			// Packet completed
			printf("IP packet size %d sent successfully!\n", packetlen);
			packetpos = 0;
			packetlen = 0;
			lastlen = 0;
		} else {
			// More to send
			dns_send_chunk(fd);
		}
	}

	// Detect if any data is attached
	// TODO
	
	return 0;
}

void
dns_ping(int dns_fd)
{
	if (dns_sending()) {
		// Resend latest chunk
		printf("No reply on chunk, resending\n");
		dns_send_chunk(dns_fd);
	} else {
		dns_write(dns_fd, dns_fd, "\0", 1);
	}
}

void 
dns_query(int fd, int id, char *host, int type)
{
	char *p;
	int len;
	int peerlen;
	char buf[1024];
	HEADER *header;
	
	len = 0;
	memset(buf, 0, sizeof(buf));

	header = (HEADER*)buf;	
	
	header->id = id;
	header->qr = 0;
	header->opcode = 0;
	header->aa = 0;
	header->tc = 0;
	header->rd = 1;
	header->ra = 0;

	header->qdcount = htons(1);

	p = buf + sizeof(HEADER);
	p += host2dns(host, p, strlen(host));	

	PUTSHORT(type, p);
	PUTSHORT(C_IN, p);

	peerlen = sizeof(peer);

	len = p - buf;
	sendto(fd, buf, len, 0, (struct sockaddr*)&peer, peerlen);
}

int
dns_write(int fd, int id, char *buf, int len)
{
	int avail;
	int i;
	int parts;
	int p;
	char data[257];
	char *d;

#define CHUNK 31
// 31 bytes expands to 62 chars in domain
// We just use hex as encoding right now

	avail = 0xFF - strlen(topdomain) - 2;

	avail /= 2; // use two chars per byte in encoding
	avail -= (avail/CHUNK); // make space for parts

	avail = MIN(avail, len); // do not use more bytes than is available;
	d = data;

	parts = avail / CHUNK;
	for (p = 0; p < parts; p++) {
		for (i = 0; i < CHUNK; i++) {
			snprintf(d, 3, "%02X", buf[p*CHUNK + i]);
			d += 2;
		}
		*d++ = '.';
	}
	parts = avail % CHUNK;
	for (i = 0; i < parts; i++) {
		snprintf(d, 3, "%02X", buf[p*CHUNK + i]);
		d += 2;
	}
	*d++ = '.';
	strncpy(d, topdomain, strlen(topdomain)+1);
	
	printf("Resolving %s\n", data);
	dns_query(fd, id, data, T_A);
	return avail;
}

int
dns_read(int fd, char *buf, int buflen)
{
	int i;
	int r;
	long ttl;
	short rlen;
	short type;
	short class;
	short port;
	short ancount;
	char *data;
	char name[255];
	char host[255];
	char rdata[256];
	HEADER *header;
	char packet[64*1024];

	r = recv(fd, packet, sizeof(packet), 0);

	printf("Read %d bytes DNS reply\n", r);

	if(r == -1) {
		perror("recv");
	} else {
		header = (HEADER*)packet;
		
		data = packet + sizeof(HEADER);

		if(header->qr) { /* qr=1 => response */
			ancount = ntohs(header->ancount);

			for(i=0;i<ancount;i++) {
				READNAME(packet, name, data);
				READSHORT(type, data);
				READSHORT(class, data);
				READLONG(ttl, data);
				READSHORT(rlen, data);
				READDATA(rdata, data, rlen);

				if(type == T_SRV && rlen > 6) {
					char *r;
					short priority;
					short weight;

					r = rdata;

					READSHORT(priority, r);
					READSHORT(weight, r);
					READSHORT(port, r);
					READNAME(packet, host, r);
				}
			//	printf("%s\n", name);
			}
			// Is any data attached?
			return dns_handle_reply(fd, packet, r);
		}
	}

	return 0;
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
