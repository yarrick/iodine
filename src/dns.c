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
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <arpa/inet.h>
#include <err.h>
#endif


#include "dns.h"
#include "encoding.h"
#include "read.h"

#define CHECKLEN(x) if (buflen - (p-buf) < (x))  return 0

int
dns_encode(char *buf, size_t buflen, struct query *q, qr_t qr, char *data, size_t datalen)
{
	HEADER *header;
	short name;
	char *p;
	int len;

	if (buflen < sizeof(HEADER))
		return 0;

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

		/* Question section */
		putname(&p, buflen - (p - buf), q->name);

		CHECKLEN(4);
		putshort(&p, q->type);
		putshort(&p, C_IN);

		/* Answer section */
		CHECKLEN(10);
		putshort(&p, name);	
		if (q->type == T_A)
			putshort(&p, T_CNAME);	/* answer CNAME to A question */
		else
			putshort(&p, q->type);
		putshort(&p, C_IN);
		putlong(&p, 0);		/* TTL */

		if (q->type == T_CNAME || q->type == T_A || q->type == T_MX) {
			/* data is expected to be like "Hblabla.host.name.com\0" */

			char *startp = p;
			int namelen;

			p += 2;			/* skip 2 bytes length */
			CHECKLEN(2);
			if (q->type == T_MX)
				putshort(&p, 10);	/* preference */
			putname(&p, buflen - (p - buf), data);
			CHECKLEN(0);
			namelen = p - startp;
			namelen -= 2;
			putshort(&startp, namelen);
		} else if (q->type == T_TXT) {
			/* TXT has binary or base-X data */
			char *startp = p;
			int txtlen;

			p += 2;			/* skip 2 bytes length */
			puttxtbin(&p, buflen - (p - buf), data, datalen);
			CHECKLEN(0);
			txtlen = p - startp;
			txtlen -= 2;
			putshort(&startp, txtlen);
		} else {
			/* NULL has raw binary data */
			datalen = MIN(datalen, buflen - (p - buf));
			CHECKLEN(2);
			putshort(&p, datalen);
			CHECKLEN(datalen);
			putdata(&p, data, datalen);
			CHECKLEN(0);
		}
		break;
	case QR_QUERY:
		/* Note that iodined also uses this for forward queries */

		header->qdcount = htons(1);
		header->arcount = htons(1);
	
		datalen = MIN(datalen, buflen - (p - buf));
		putname(&p, datalen, data);

		CHECKLEN(4);
		putshort(&p, q->type);
		putshort(&p, C_IN);

		/* EDNS0 to advertise maximum response length
		   (even CNAME/A/MX, 255+255+header would be >512) */
		CHECKLEN(11);
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
/* Only used when iodined gets an NS type query */
{
	HEADER *header;
	int len;
	short name;
	short topname;
	short nsname;
	char *domain;
	int domain_len;
	char *p;

	if (buflen < sizeof(HEADER))
		return 0;

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
	putname(&p, buflen - (p - buf), q->name);	/* Name */
	CHECKLEN(4);
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);			/* Name */
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 5);			/* Data length */

	/* pointer to ns.topdomain */
	nsname = 0xc000 | ((p - buf) & 0x3fff);
	CHECKLEN(5);
	putbyte(&p, 2);
	putbyte(&p, 'n');
	putbyte(&p, 's');
	putshort(&p, topname);			/* Name Server */

	/* Additional data (A-record of NS server) */
	CHECKLEN(12);
	putshort(&p, nsname);			/* Name Server */
	putshort(&p, T_A);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	domain = (char *) &q->destination;
	CHECKLEN(4);
	putbyte(&p, *domain++);
	putbyte(&p, *domain++);
	putbyte(&p, *domain++);
	putbyte(&p, *domain);

	len = p - buf;
	return len;
}

#undef CHECKLEN

unsigned short
dns_get_id(char *packet, size_t packetlen)
{
	HEADER *header;
	header = (HEADER*)packet;

	if (packetlen < sizeof(HEADER))
		return 0;

	return ntohs(header->id);
}

#define CHECKLEN(x) if (packetlen - (data-packet) < (x))  return 0

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

	if (q != NULL) 
		q->rcode = header->rcode;

	switch (qr) {
	case QR_ANSWER:
		if(qdcount < 1 || ancount < 1) {
			/* We may get both CNAME and A, then ancount=2 */
			return -1;
		}

		if (q != NULL) 
			q->id = id;

		readname(packet, packetlen, &data, name, sizeof(name));
		CHECKLEN(4);
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		
		/* if CHECKLEN okay, then we're sure to have a proper name */
		if (q != NULL) {
			/* We only need the first char to check it */
			q->name[0] = name[0];
			q->name[1] = '\0';
		}

		/* Assume that first answer is NULL/CNAME that we wanted */
		readname(packet, packetlen, &data, name, sizeof(name));
		CHECKLEN(10);
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);
		readlong(packet, &data, &ttl);
		readshort(packet, &data, &rlen);

		if (type == T_NULL) {
			rv = MIN(rlen, sizeof(rdata));
			rv = readdata(packet, &data, rdata, rv);
			if (rv >= 2 && buf) {
				rv = MIN(rv, buflen);
				memcpy(buf, rdata, rv);
			} else {
				rv = 0;
			}
		}
		if ((type == T_CNAME || type == T_MX) && buf) {
			if (type == T_MX)
				data += 2;	/* skip preference */
			memset(name, 0, sizeof(name));
			readname(packet, packetlen, &data, name, sizeof(name) - 1);
			name[sizeof(name)-1] = '\0';
			strncpy(buf, name, buflen);
			buf[buflen - 1] = '\0';
			rv = strlen(buf);
		}
		if (type == T_TXT && buf) {
			rv = readtxtbin(packet, &data, rlen, rdata, sizeof(rdata));
			if (rv >= 1) {
				rv = MIN(rv, buflen);
				memcpy(buf, rdata, rv);
			} else {
				rv = 0;
			}
		}
		if (q != NULL)
			q->type = type;
		break;
	case QR_QUERY:
		if (qdcount < 1) {
			warnx("no question section in name query");
			return -1;
		}

		memset(name, 0, sizeof(name));
		readname(packet, packetlen, &data, name, sizeof(name) - 1);
		name[sizeof(name)-1] = '\0';
		CHECKLEN(4);
		readshort(packet, &data, &type);
		readshort(packet, &data, &class);

		if (q == NULL) {
			rv = 0;
			break;
		}

		strncpy(q->name, name, sizeof(q->name));
		q->name[sizeof(q->name) - 1] = '\0';
		q->type = type;
		q->id = id;

		rv = strlen(q->name);
		break;
	}

	return rv;
}

