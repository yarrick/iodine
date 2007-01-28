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
static int decodepacket(const char*, char*, int);

static struct sockaddr_in peer;
static char topdomain[256];

// Current IP packet
static char activepacket[4096];
static int lastlen;
static int packetpos;
static int packetlen;
static uint16_t chunkid;

static uint16_t pingid;


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
dns_login(int dns_fd, char *login, int len)
{
	char data[18];
	memcpy(data, login, MIN(len, 16));
	data[16] = (pingid & 0xFF00) >> 8;
	data[17] = (pingid & 0xFF);
	dns_write(dns_fd, ++pingid, data, 18, 'L');
}

void 
dns_send_version(int dns_fd, int version)
{
	char data[6];
	int v;

	v = htonl(version);
	memcpy(data, &v, 4);
	data[4] = (pingid & 0xFF00) >> 8;
	data[5] = (pingid & 0xFF);
	dns_write(dns_fd, ++pingid, data, 6, 'V');
}

int
dns_encode(char *buf, size_t buflen, struct query *q, int qr, char *data, size_t datalen)
{
	HEADER *header;
	short name;
	char *p;
	int len;

	memset(buf, 0, buflen);
	
	header = (HEADER*)buf;
	
	header->id = htons(q->id);
	header->qr = qr;
	header->opcode = 0;
	header->aa = (qr == QR_ANSWER);
	header->tc = 0;
	header->rd = (qr == QR_QUERY);
	header->ra = 0;

	p = buf + sizeof(HEADER);

	switch (qr) {
	case QR_ANSWER:
		header->ancount = htons(1);
		header->qdcount = htons(1);
	
		name = 0xc000 | ((p - buf) & 0x3fff);
		p += dns_encode_hostname(q->name, p, strlen(q->name));
		putshort(&p, q->type);
		putshort(&p, C_IN);

		putshort(&p, name);	
		putshort(&p, q->type);
		putshort(&p, C_IN);
		putlong(&p, 0);

		/* 
		 * XXX: This is jidder! This is used to detect if there's packets to be sent. 
		 */
		q->id = 0;

		putshort(&p, datalen);
		putdata(&p, data, datalen);
		break;
	case QR_QUERY:
		header->qdcount = htons(1);
		header->arcount = htons(1);
	
		p += dns_encode_hostname(data, p, datalen);	

		putshort(&p, q->type);
		putshort(&p, C_IN);

		// EDNS0
		putbyte(&p, 0x00); //Root
		putshort(&p, 0x0029); // OPT
		putshort(&p, 0x1000); // Payload size: 4096
		putshort(&p, 0x0000); // Higher bits/edns version
		putshort(&p, 0x8000); // Z
		putshort(&p, 0x0000); // Data length
		break;
	default:
		errx(1, "dns_encode: qr is wrong!!!");
		/* NOTREACHED */
	}
	
	len = p - buf;

	return len;
}

int
dns_decode(char *buf, size_t buflen, struct query *q, int qr, char *packet, size_t packetlen)
{
	char rdata[4*1024];
	HEADER *header;
	short qdcount;
	short ancount;
	char name[255];
	uint32_t ttl;
	short class;
	short type;
	char *data;
	short rlen;
	int id; 
	int rv;

	rv = 0;
	header = (HEADER*)packet;
	
	if (header->qr != qr) {
		warnx("header->qr does not match the requested qr");
		return -1;
	}
	
	data = packet + sizeof(HEADER);
	qdcount = ntohs(header->qdcount);
	ancount = ntohs(header->ancount);
	
	id = ntohs(header->id);
		
	rlen = 0;

	switch (qr) {
	case QR_ANSWER:
		if(qdcount != 1 || ancount != 1) {
			warnx("no query or answer in answer");
			return -1;
		}

		readname(packet, packetlen, &data, name, sizeof(name));
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		
		readname(packet, packetlen, &data, name, sizeof(name));
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		readlong(packet, &data, &ttl);
		readshort(packet, &data, &rlen);
		rv = MIN(rlen, sizeof(rdata));
		readdata(packet, &data, rdata, rv);

		if(type == T_NULL && rv > 2) {
			rv = MIN(rv, buflen);
			memcpy(buf, rdata, rv);
		}
		break;
	case QR_QUERY:
		if (qdcount != 1) {
			warnx("no query on query");
			return -1;
		}

		readname(packet, packetlen, &data, name, sizeof(name) -1);
		name[256] = 0;
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);

		strncpy(q->name, name, 257);
		q->type = type;
		q->id = id;

		rv = decodepacket(name, buf, buflen);
		break;
	}

	return rv;
}

static void 
dns_query(int fd, int id, char *host, int type)
{
	char buf[1024];
	struct query q;
	int peerlen;
	int len;

	q.id = id;
	q.type = type;
	
	len = dns_encode(buf, sizeof(buf), &q, QR_QUERY, host, strlen(host));

	peerlen = sizeof(peer);
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
	return dns_decode(buf, buflen, NULL, QR_ANSWER, packet, r);
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
			free(h);
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
	char buf[64*1024];
	int len;

	len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, data, datalen);
	
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
	struct sockaddr_in from;
	char packet[64*1024];
	socklen_t addrlen;
	int len;
	int rv;
	int r;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

	if (r >= sizeof(HEADER)) {
		len = dns_decode(buf, buflen, q, QR_QUERY, packet, r);

		q->fromlen = addrlen;
		memcpy((struct sockaddr*)&q->from, (struct sockaddr*)&from, addrlen);
		rv = len;
	} else if (r < 0) { 	// Error
		perror("recvfrom");
		rv = 0;
	} else {		// Packet too small to be dns protocol
		rv = 0;
	}

	return rv;
}

