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
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif
#include <netdb.h>
#include <time.h>
#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "structs.h"
#include "dns.h"
#include "encoding.h"
#include "read.h"

// For FreeBSD
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif


static int dns_write(int, int, char *, int, char);
static void dns_query(int, int, char *, int);

struct sockaddr_in peer;
char topdomain[256];

// Current IP packet
char activepacket[4096];
int lastlen;
int packetpos;
int packetlen;
uint16_t chunkid;

uint16_t pingid;


int 
open_dns(const char *domain, int localport, in_addr_t listen_ip) 
{
	int fd;
	int flag;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(localport);
	/* listen_ip already in network byte order from inet_addr, or 0 */
	addr.sin_addr.s_addr = listen_ip; 

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(fd < 0) {
		warn("socket");
		return -1;
	}

	flag = 1;
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
#endif
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		warn("bind");
		return -1;
	}

	// Save top domain used
	strncpy(topdomain, domain, sizeof(topdomain) - 1);
	topdomain[sizeof(topdomain) - 1] = '\0';

	printf("Opened UDP socket\n");

	return fd;
}

int 
dns_settarget(const char *host) 
{
	struct hostent *h;

	// Init dns target struct
	h = gethostbyname(host);
	if (!h) {
		printf("Could not resolve name %s, exiting\n", host);
		return -1;
	}

	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(53);
	peer.sin_addr = *((struct in_addr *) h->h_addr);

	// Init chunk id
	chunkid = 0;
	pingid = 0;

	return 0;
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
	lastlen = dns_write(fd, ++chunkid, p, avail, 0);
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

void
dns_ping(int dns_fd)
{
	char data[2];
	if (dns_sending()) {
		lastlen = 0;
		packetpos = 0;
		packetlen = 0;
	}
	data[0] = (pingid & 0xFF00) >> 8;
	data[1] = (pingid & 0xFF);
	dns_write(dns_fd, ++pingid, data, 2, 'P');
}

void 
dns_handshake(int dns_fd)
{
	char data[2];
	data[0] = (pingid & 0xFF00) >> 8;
	data[1] = (pingid & 0xFF);
	dns_write(dns_fd, ++pingid, data, 2, 'H');
}

static void 
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
	
	header->id = htons(id);
	header->qr = 0;
	header->opcode = 0;
	header->aa = 0;
	header->tc = 0;
	header->rd = 1;
	header->ra = 0;

	header->qdcount = htons(1);
	header->arcount = htons(1);

	p = buf + sizeof(HEADER);
	p += dns_encode_hostname(host, p, strlen(host));	

	putshort(&p, type);
	putshort(&p, C_IN);

	// EDNS0
	putbyte(&p, 0x00); //Root
	putshort(&p, 0x0029); // OPT
	putshort(&p, 0x1000); // Payload size: 4096
	putshort(&p, 0x0000); // Higher bits/edns version
	putshort(&p, 0x8000); // Z
	putshort(&p, 0x0000); // Data length

	peerlen = sizeof(peer);

	len = p - buf;
	sendto(fd, buf, len, 0, (struct sockaddr*)&peer, peerlen);
}

static int
dns_write(int fd, int id, char *buf, int len, char flag)
{
	int avail;
	int written;
	int encoded;
	char data[257];
	char *d;

	avail = 0xFF - strlen(topdomain) - 2;
	memset(data, 0, sizeof(data));
	d = data;
	written = encode_data(buf, len, avail, d, flag);
	encoded = strlen(data);
	d += encoded;
	if (*d != '.') {
		*d++ = '.';
	}
	strncpy(d, topdomain, strlen(topdomain)+1);
	
	dns_query(fd, id, data, T_NULL);
	return written;
}

int
dns_read(int fd, char *buf, int buflen)
{
	int r;
	socklen_t addrlen;
	char packet[64*1024];
	struct sockaddr_in from;
	HEADER *header;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);
	if(r == -1) {
		perror("recvfrom");
		return 0;
	}

	header = (HEADER*)packet;
	if (dns_sending() && chunkid == ntohs(header->id)) {
		/* Got ACK on sent packet */
		packetpos += lastlen;
		if (packetpos == packetlen) {
			/* Packet completed */
			packetpos = 0;
			packetlen = 0;
			lastlen = 0;
		} else {
			/* More to send */
			dns_send_chunk(fd);
		}
	}
	return dns_parse_reply(buf, buflen, packet, r);
}

int
dns_parse_reply(char *outbuf, int buflen, char *packet, int packetlen)
{
	int rv;
	uint32_t ttl;
	short rlen;
	short type;
	short class;
	short qdcount;
	short ancount;
	char *data;
	char name[255];
	char rdata[4*1024];
	HEADER *header;

	rv = 0;
	header = (HEADER*)packet;
	
	data = packet + sizeof(HEADER);

	if(header->qr) { /* qr=1 => response */
		qdcount = ntohs(header->qdcount);
		ancount = ntohs(header->ancount);

		rlen = 0;

		if(qdcount == 1) {
			readname(packet, packetlen, &data, name, sizeof(name));
			readshort(packet, &data, &type);
			readshort(packet, &data, &class);
		}
		if(ancount == 1) {
			readname(packet, packetlen, &data, name, sizeof(name));
			readshort(packet, &data, &type);
			readshort(packet, &data, &class);
			readlong(packet, &data, &ttl);
			readshort(packet, &data, &rlen);
			rv = MIN(rlen, sizeof(rdata));
			readdata(packet, &data, rdata, rv);
		}

		if(type == T_NULL && rv > 2) {
			rv = MIN(rv, buflen);
			memcpy(outbuf, rdata, rv);
		}
	}

	return rv;
}

int
dns_encode_hostname(const char *host, char *buffer, int size)
{
	char *h;
	char *p;
	char *word;
	int left;

	h = strdup(host);
	memset(buffer, 0, size);
	p = buffer;
	left = size;
	
	word = strtok(h, ".");
	while(word) {
		if (strlen(word) > 63 || strlen(word) > left) {
			return -1;
		}
		left -= (strlen(word) + 1);
		*p++ = (char)strlen(word);
		memcpy(p, word, strlen(word));
		p += strlen(word);

		word = strtok(NULL, ".");
	}

	*p++ = 0;

	free(h);

	return p - buffer;
}

void
dnsd_send(int fd, struct query *q, char *data, int datalen)
{
	int len;
	char *p;
	char buf[64*1024];
	short name;
	HEADER *header;

	memset(buf, 0, sizeof(buf));

	len = 0;
	header = (HEADER*)buf;	

	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	header->qdcount = htons(1);
	header->ancount = htons(1);

	p = buf + sizeof(HEADER);
	
	name = 0xc000 | ((p - buf) & 0x3fff);
	p += dns_encode_hostname(q->name, p, strlen(q->name));
	putshort(&p, q->type);
	putshort(&p, C_IN);

	putshort(&p, name);	
	putshort(&p, q->type);
	putshort(&p, C_IN);
	putlong(&p, 0);

	q->id = 0;

	putshort(&p, datalen);
	putdata(&p, data, datalen);

	len = p - buf;
	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

static int
decodepacket(const char *name, char *buf, int buflen)
{
	int len;
	char *domain;

	domain = strstr(name, topdomain);

	len = decode_data(buf, buflen, name, domain);
	if (len == buflen)
		return -1; 
	return len;
}

int
dnsd_read(int fd, struct query *q, char *buf, int buflen)
{
	int r;
	int rv;
	short id;
	short type;
	short class;
	short qdcount;
	char *data;
	char name[257];
	HEADER *header;
	socklen_t addrlen;
	char packet[64*1024];
	struct sockaddr_in from;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

	if (r >= sizeof(HEADER)) {
		header = (HEADER*)packet;

		id = ntohs(header->id);

		data = packet + sizeof(HEADER);

		if(!header->qr) {
			qdcount = ntohs(header->qdcount);

			if(qdcount == 1) {
				readname(packet, r, &data, name, sizeof(name) -1);
				name[256] = 0;
				readshort(packet, &data, &type);
				readshort(packet, &data, &class);

				strncpy(q->name, name, 257);
				q->type = type;
				q->id = id;
				q->fromlen = addrlen;
				memcpy((struct sockaddr*)&q->from, (struct sockaddr*)&from, addrlen);

				rv = decodepacket(name, buf, buflen);
			}
		}
	} else if (r < 0) { 	// Error
		perror("recvfrom");
		rv = 0;
	} else {		// Packet too small to be dns protocol
		rv = 0;
	}

	return rv;
}
