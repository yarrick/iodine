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
#include "read.h"

static int host2dns(const char *, char *, int);
static int dns_write(int, int, char *, int, char);

struct sockaddr_in peer;
char topdomain[256];

// Current IP packet
char activepacket[4096];
int lastlen;
int packetpos;
int packetlen;
uint16_t chunkid;

uint16_t pingid;

int outid;
int outbuflen;
char outbuf[64*1024];
char delayed_q_name[256];
short delayed_q_type;
short delayed_q_id;
struct sockaddr_in delayed_q_from;
int delayed_q_fromlen;

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

	printf("Opened UDP socket\n");
	printf("Sending queries for %s to %s\n", domain, host);

	// Init dns target struct
	h = gethostbyname(host);
	if (!h) {
		printf("Could not resolve name %s, exiting\n", host);
		return -1;
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
	pingid = 0;

	return fd;
}

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

	printf("Opened UDP socket\n");
	printf("Listening to dns for domain %s\n", domain);
	
	// Save top domain used
	strncpy(topdomain, domain, sizeof(topdomain) - 2);
	topdomain[sizeof(topdomain) - 1] = 0;

	packetlen = 0;
	delayed_q_type = 0;
	delayed_q_id = 0;
	delayed_q_fromlen = 0;

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
	lastlen = dns_write(fd, ++chunkid, p, avail, 0);
	//printf("Sent %d bytes of %d remaining\n", lastlen, avail);
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
	//	printf("No reply on chunk, discarding\n");
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
	p += host2dns(host, p, strlen(host));	

	PUTSHORT(type, p);
	PUTSHORT(C_IN, p);

	// EDNS0
	*p++ = 0x00; //Root
	PUTSHORT(0x0029, p); // OPT
	PUTSHORT(0x1000, p); // Payload size: 4096
	PUTSHORT(0x0000, p); // Higher bits/ edns version
	PUTSHORT(0x8000, p); // Z
	PUTSHORT(0x0000, p); // Data length

	peerlen = sizeof(peer);

	len = p - buf;
	sendto(fd, buf, len, 0, (struct sockaddr*)&peer, peerlen);
}

static void
put_hex(char *p, char h)
{
	int t;
	static const char to_hex[] = "0123456789ABCDEF";

	t = (h & 0xF0) >> 4;
	p[0] = to_hex[t];
	t = h & 0x0F;
	p[1] = to_hex[t];
}

static int
dns_write(int fd, int id, char *buf, int len, char flag)
{
	int avail;
	int i;
	int final;
	char data[257];
	char *d;

#define CHUNK 31
// 31 bytes expands to 62 chars in domain
// We just use hex as encoding right now

	avail = 0xFF - strlen(topdomain) - 2;

	avail /= 2; // use two chars per byte in encoding
	avail -= (avail/CHUNK); // make space for parts

	avail = MIN(avail, len); // do not use more bytes than is available;
	final = (avail == len);	// is this the last block?
	bzero(data, sizeof(data));
	d = data;

	if (flag != 0) {
		*d = flag;
	} else {
		// First byte is 0 for middle packet and 1 for last packet
		*d = '0' + final;
	}
	d++;

	if (len > 0) {
		for (i = 0; i < avail; i++) {
			if (i > 0 && i % 31 == 0) {
				*d = '.';
				d++;
			}
			put_hex(d, buf[i]);
			d += 2;
		}
	}
	if (*d != '.') {
		*d++ = '.';
	}
	strncpy(d, topdomain, strlen(topdomain)+1);
	
	//printf("Resolving %s\n", data);
	dns_query(fd, id, data, T_NULL);
	return avail;
}

int
dns_read(int fd, char *buf, int buflen)
{
	int r;
	long ttl;
	short rlen;
	short type;
	short class;
	short qdcount;
	short ancount;
	char *data;
	char name[255];
	char rdata[4*1024];
	HEADER *header;
	socklen_t addrlen;
	char packet[64*1024];
	struct sockaddr_in from;

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

	if(r == -1) {
		perror("recvfrom");
	} else {
		header = (HEADER*)packet;
		
		data = packet + sizeof(HEADER);

		if(header->qr) { /* qr=1 => response */
			qdcount = ntohs(header->qdcount);
			ancount = ntohs(header->ancount);

			rlen = 0;

			if(qdcount == 1) {
				READNAME(packet, name, data);
				READSHORT(type, data);
				READSHORT(class, data);
			}
			if(ancount == 1) {
				READNAME(packet, name, data);
				READSHORT(type, data);
				READSHORT(class, data);
				READLONG(ttl, data);
				READSHORT(rlen, data);
				READDATA(rdata, data, rlen);
			}
			if (dns_sending() && chunkid == ntohs(header->id)) {
				// Got ACK on sent packet
				packetpos += lastlen;
				if (packetpos == packetlen) {
					// Packet completed
					// printf("IP packet size %d sent successfully!\n", packetlen);
					packetpos = 0;
					packetlen = 0;
					lastlen = 0;
				} else {
					// More to send
					dns_send_chunk(fd);
				}
			}

			if(type == T_NULL && rlen > 2) {
				memcpy(buf, rdata, rlen);
				return rlen;
			} else {
				return 0;
			}
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

int
dnsd_haspacket()
{
	return (outbuflen > 0);
}

int
dnsd_hasack()
{
	return (delayed_q_id != 0);
}

void
dnsd_queuepacket(const char *buf, const int buflen)
{
	memcpy(outbuf, buf, buflen);	

	outbuflen = buflen;
	outid++;
}

static void
dnsd_send(int fd, char *name, short type, short id, struct sockaddr_in from)
{
	int len;
	char *p;
	char buf[64*1024];
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
		PUTSHORT(outbuflen, p);
		memcpy(p, outbuf, outbuflen);
		p += outbuflen;
	} else {
		PUTSHORT(0, p);
	}

	len = p - buf;
//	printf("Responding with %d\n", len);
	sendto(fd, buf, len, 0, (struct sockaddr*)&from, sizeof(from));

	outbuflen = 0;
}

void
dnsd_forceack(int fd)
{
	dnsd_send(fd, delayed_q_name, delayed_q_type, delayed_q_id, delayed_q_from);
	delayed_q_id = 0;
}

struct packet 
{
	int len;
	int offset;
	char data[64*1024];
};

static int
decodepacket(const char *name, struct packet *packet)
{
	int r;
	int len;
	int last;
	int ping;
	char *dp;
	char *domain;
	const char *np;

	len = 0;
	last = (name[0] == '1');
	ping = (name[0] == 'p' || name[0] == 'P');

	domain = strstr(name, topdomain);

	if (!ping && domain) {
		np = name + 1;
		dp = packet->data + packet->offset;

		while(np < domain) {
			if(*np == '.') {
				np++;
				continue;
			}

			sscanf(np, "%02X", &r);
			*dp++ = (char)r;
			np+=2;	
			len++;
		}

		packet->len += len;
		packet->offset += len;
	} 

	if(last) {
		len = packet->len;
		packet->len = packet->offset = 0;
	} else {
		len = 0;
	}

	return len;
}

void
close_dnsd(int fd)
{
	close(fd);
}

struct packet packetbuf;

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

	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);

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
				
				if (dnsd_haspacket()) {
					dnsd_send(fd, name, type, id, from);
				} else {
					// Store needed info about delayed response
					strncpy(delayed_q_name, name, 256);
					delayed_q_type = type;
					delayed_q_id = id;
					delayed_q_fromlen = addrlen;
					memcpy((struct sockaddr*)&delayed_q_from, (struct sockaddr*)&from, addrlen);
				}

				r = decodepacket(name, &packetbuf);

				memcpy(buf, packetbuf.data, r);
				
				return r;
			}
		}
	}

	return 0;
}
