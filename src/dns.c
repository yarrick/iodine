/*
 * Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>, Erik Ekman <yarrick@kryo.se>
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

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#include <arpa/nameser8_compat.h>
#endif
#include <arpa/inet.h>
#include <err.h>
#endif


#include "dns.h"
#include "encoding.h"
#include "read.h"

int
dns_encode(char *buf, size_t buflen, struct query *q, qr_t qr, char *data, size_t datalen)
{
	HEADER *header;
	short name;
	char *p;
	int len;

	memset(buf, 0, buflen);
	
	header = (HEADER*)buf;
	
	header->id = htons(q->id);
	header->qr = (qr == QR_ANSWER);
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

		putname(&p, sizeof(q->name), q->name);

		putshort(&p, q->type);
		putshort(&p, C_IN);

		putshort(&p, name);	
		putshort(&p, q->type);
		putshort(&p, C_IN);
		putlong(&p, 0);

		putshort(&p, datalen);
		putdata(&p, data, datalen);
		break;
	case QR_QUERY:
		header->qdcount = htons(1);
		header->arcount = htons(1);
	
		putname(&p, datalen, data);

		putshort(&p, q->type);
		putshort(&p, C_IN);

		/* EDNS0 */
		putbyte(&p, 0x00);    /* Root */
		putshort(&p, 0x0029); /* OPT */
		putshort(&p, 0x1000); /* Payload size: 4096 */
		putshort(&p, 0x0000); /* Higher bits/edns version */
		putshort(&p, 0x8000); /* Z */
		putshort(&p, 0x0000); /* Data length */
		break;
	}
	
	len = p - buf;

	return len;
}

int
dns_encode_ns_response(char *buf, size_t buflen, struct query *q, char *topdomain)
{
	HEADER *header;
	int len;
	short name;
	short topname;
	short nsname;
	char *domain;
	int domain_len;
	char *p;

	memset(buf, 0, buflen);
	
	header = (HEADER*)buf;
	
	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	p = buf + sizeof(HEADER);

	header->qdcount = htons(1);
	header->ancount = htons(1);
	header->arcount = htons(1);

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	domain = strstr(q->name, topdomain);
	if (domain) {
		domain_len = (int) (domain - q->name); 
	} else {
		return -1;
	}
	/* pointer to start of topdomain */
	topname = 0xc000 | ((p - buf + domain_len) & 0x3fff);

	/* Query section */
	putname(&p, sizeof(q->name), q->name);	/* Name */
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	putshort(&p, name);			/* Name */
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 0x3ea7d011);		/* TTL */
	putshort(&p, 5);			/* Data length */

	/* pointer to ns.topdomain */
	nsname = 0xc000 | ((p - buf) & 0x3fff);
	putbyte(&p, 2);
	putbyte(&p, 'n');
	putbyte(&p, 's');
	putshort(&p, topname);			/* Name Server */

	/* Additional data (A-record of NS server) */
	putshort(&p, nsname);			/* Name Server */
	putshort(&p, T_A);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 0x3ea7d011);		/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	domain = (char *) &q->destination;
	putbyte(&p, *domain++);
	putbyte(&p, *domain++);
	putbyte(&p, *domain++);
	putbyte(&p, *domain);

	len = p - buf;
	return len;
}

unsigned short
dns_get_id(char *packet, size_t packetlen)
{
	HEADER *header;
	header = (HEADER*)packet;

	if (packetlen < sizeof(HEADER))
		return 0;

	return ntohs(header->id);
}

int
dns_decode(char *buf, size_t buflen, struct query *q, qr_t qr, char *packet, size_t packetlen)
{
	char name[QUERY_NAME_SIZE];
	char rdata[4*1024];
	HEADER *header;
	short qdcount;
	short ancount;
	uint32_t ttl;
	short class;
	short type;
	char *data;
	short rlen;
	int id; 
	int rv;

	rv = 0;
	header = (HEADER*)packet;

	/* Reject short packets */
	if (packetlen < sizeof(HEADER)) 
		return 0;
	
	if (header->qr != qr) {
		warnx("header->qr does not match the requested qr");
		return -1;
	}

	data = packet + sizeof(HEADER);
	qdcount = ntohs(header->qdcount);
	ancount = ntohs(header->ancount);
	
	id = ntohs(header->id);
	id = id & 0xFFFF; /* Kill any sign extension */
		
	rlen = 0;

	switch (qr) {
	case QR_ANSWER:
		if(qdcount != 1 || ancount != 1) {
			switch (header->rcode) {
			case REFUSED:
				warnx("Got REFUSED as reply");
				break;

			case NOTIMP:
				warnx("Got NOTIMP as reply");
				break;

			case NXDOMAIN:
				warnx("Got NXDOMAIN as reply");
				break;

			case SERVFAIL:
				warnx("Got SERVFAIL as reply");
				break;

			case NOERROR:
			default:
				warnx("no query or answer in reply packet");
				break;
			}
			return -1;
		}

		if (q != NULL) 
			q->id = id;

		readname(packet, packetlen, &data, name, sizeof(name));
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		
		readname(packet, packetlen, &data, name, sizeof(name));
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		readlong(packet, &data, &ttl);
		readshort(packet, &data, &rlen);
		rv = MIN(rlen, sizeof(rdata));
		rv = readdata(packet, &data, rdata, rv);

		if(type == T_NULL && rv >= 2 && buf) {
			rv = MIN(rv, buflen);
			memcpy(buf, rdata, rv);
		}
		break;
	case QR_QUERY:
		if (qdcount != 1) {
			warnx("no question section in name query");
			return -1;
		}

		readname(packet, packetlen, &data, name, sizeof(name) - 1);
		name[sizeof(name)-1] = '\0';
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);

		strncpy(q->name, name, sizeof(q->name));
		q->name[sizeof(q->name) - 1] = '\0';
		q->type = type;
		q->id = id;

		rv = strlen(q->name);
		break;
	}

	return rv;
}

