/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>
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
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "mdns.h"

#define MAX_PACKET_LEN 1024

struct servicetree services = RB_INITIALIZER(&services);

int
servicecmp(struct mdns_service *a, struct mdns_service *b)
{
	    return strcmp(a->net, b->net);
}

RB_GENERATE(servicetree, mdns_service, entry, servicecmp);

extern void peer_event(int, struct mdns_peer*);

void
mdns_register_service(struct mdns_service *service)
{
	RB_INSERT(servicetree, &services, service);
}

void
mdns_unregister_service(struct mdns_service *service)
{
	if(service) {
		RB_REMOVE(servicetree, &services, service);
	}
}

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
mdns_open()
{
	int fd;
    int ttl;
    int flag;
    struct sockaddr_in addr;
    struct ip_mreq mc;

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        perror("socket");
        exit(1);
    }

    flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    mc.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mc.imr_interface.s_addr = inet_addr("192.168.7.208"); //htonl(INADDR_ANY); 
    if(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc)) < 0) {
		perror("ip_add_membership");
		exit(1);
	}
    
    ttl = 255;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	
	return fd;
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

static void
mdns_respond(int fd, struct mdns_service *service) 
{
	int len;
	int size;
	HEADER *header;
	char *p;
	int addrlen;
	char buf[1024];
	char host[256];
	struct sockaddr_in addr;

	snprintf(host, sizeof(host), "%s.%s", service->name, service->net);

	memset(buf, 0, sizeof(buf));

	len = 0;
	header = (HEADER*)buf;	

	header->id = 0;
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	header->ancount = htons(2);

	p = buf + sizeof(HEADER);
	
	p += host2dns(service->net, p, strlen(service->net));	
	PUTSHORT(T_PTR, p);
	PUTSHORT(C_IN, p);
	PUTLONG(htons(3600), p);

	size = host2dns(host, p+2, strlen(host));
	PUTSHORT(size, p);
	p += size;

	p += host2dns(host, p, strlen(host));
	PUTSHORT(T_SRV, p);
	PUTSHORT(0x8001, p);
	PUTLONG(service->ttl, p);
	
	size = host2dns(service->host, p+8, strlen(service->host));
	size += 6;
	PUTSHORT(size, p);
	PUTSHORT(0, p);
	PUTSHORT(0, p);
	PUTSHORT(service->port, p);
	p+= size;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("224.0.0.251");
	addr.sin_port = htons(5353);
	addrlen = sizeof(addr);

	len = p - buf;
	sendto(fd, buf, len + 1, 0, (struct sockaddr*)&addr, addrlen);
}

void
mdns_handle(int fd)
{
	int i;
	int ssize;
	long ttl;
	short rlen;
	short type;
	short class;
	short ancount;
	short qdcount;
	char *data;
	char name[255];
	char rdata[256];
	HEADER *header;
	struct mdns_peer *peer;
	struct sockaddr_in from;
	char buf[MAX_PACKET_LEN];

	i = recvfrom(fd, buf, MAX_PACKET_LEN, 0, (struct sockaddr*)&from, &ssize);

	if(i == -1) {
		perror("recvfrom");
	} else {
		header = (HEADER*)buf;
		
		data = buf + sizeof(HEADER);

		if(header->qr) { /* qr=1 => response */
			peer = malloc(sizeof(struct mdns_peer));
			ancount = ntohs(header->ancount);

			for(i=0;i<ancount;i++) {
				READNAME(buf, name, data);
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

					peer->name = strdup(name);
					peer->host = malloc(rlen);
					peer->ttl = ttl;
					
					READSHORT(priority, r);
					READSHORT(weight, r);
					READSHORT(peer->port, r);
					READNAME(buf, peer->host, r);
					peer->host[strlen(peer->host)-1] = '\0';
				
					peer_event(1, peer);
				}
			}
		} else { /* qr=0 => query */
			qdcount = ntohs(header->qdcount);		

			for(i=0;i<qdcount;i++) {
				READNAME(buf, name, data);
				READSHORT(type, data);
				READSHORT(class, data);

				if(type == T_PTR) {
					struct mdns_service needle;
					struct mdns_service *service;

					needle.net = name;

					service = RB_FIND(servicetree, &services, &needle);

					if(service && strcmp(service->net, name) == 0) {
						mdns_respond(fd, service);
					}
				}
			}
		}
	}
}

void 
mdns_query(int fd, char *host, int type)
{
	char *p;
	int len;
	int addrlen;
	char buf[1024];
	HEADER *header;
	struct sockaddr_in addr;
	
	len = 0;
	memset(buf, 0, sizeof(buf));

	header = (HEADER*)buf;	
	
	header->id = 0;
	header->qr = 0;
	header->opcode = 0;
	header->aa = 0;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	header->qdcount = htons(1);

	p = buf + sizeof(HEADER);
	p += host2dns(host, p, strlen(host));	

	PUTSHORT(type, p);
	PUTSHORT(01, p);

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("224.0.0.251");
	addr.sin_port = htons(5353);
	addrlen = sizeof(addr);

	len = p - buf;
	sendto(fd, buf, len+1, 0, (struct sockaddr*)&addr, addrlen);
}

