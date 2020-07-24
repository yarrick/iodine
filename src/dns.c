/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
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
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#endif


#include "dns.h"
#include "encoding.h"
#include "read.h"

int dnsc_use_edns0 = 1;

#define CHECKLEN(x) if (buflen < (x) + (unsigned)(p-buf))  return 0

int dns_encode(char *buf, size_t buflen, struct query *q, qr_t qr,
	       const char *data, size_t datalen)
{
	HEADER *header;
	short name;
	char *p;
	int len;
	int ancnt;

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
		header->qdcount = htons(1);

		name = 0xc000 | ((p - buf) & 0x3fff);

		/* Question section */
		putname(&p, buflen - (p - buf), q->name);

		CHECKLEN(4);
		putshort(&p, q->type);
		putshort(&p, C_IN);

		/* Answer section */

		if (q->type == T_CNAME || q->type == T_A) {
			/* data is expected to be like
			 * "Hblabla.host.name.com\0" */

			char *startp;
			int namelen;

			CHECKLEN(10);
			putshort(&p, name);
			if (q->type == T_A)
				/* answer CNAME to A question */
				putshort(&p, T_CNAME);
			else
				putshort(&p, q->type);
			putshort(&p, C_IN);
			putlong(&p, 0);		/* TTL */

			startp = p;
			p += 2;			/* skip 2 bytes length */
			putname(&p, buflen - (p - buf), data);
			CHECKLEN(0);
			namelen = p - startp;
			namelen -= 2;
			putshort(&startp, namelen);
			ancnt = 1;
		} else if (q->type == T_MX || q->type == T_SRV) {
			/* Data is expected to be like
			   "Hblabla.host.name.com\0Hanother.com\0\0"
			   For SRV, see RFC2782.
			 */

			const char *mxdata = data;
			char *startp;
			int namelen;

			ancnt = 1;
			while (1) {
				CHECKLEN(10);
				putshort(&p, name);
				putshort(&p, q->type);
				putshort(&p, C_IN);
				putlong(&p, 0);	/* TTL */

				startp = p;
				p += 2; /* skip 2 bytes length */
				CHECKLEN(2);
				putshort(&p, 10 * ancnt); /* preference */

				if (q->type == T_SRV) {
					/* weight, port (5060 = SIP) */
					CHECKLEN(4);
					putshort(&p, 10);
					putshort(&p, 5060);
				}

				putname(&p, buflen - (p - buf), mxdata);
				CHECKLEN(0);
				namelen = p - startp;
				namelen -= 2;
				putshort(&startp, namelen);

				mxdata = mxdata + strlen(mxdata) + 1;
				if (*mxdata == '\0')
					break;

				ancnt++;
			}
		} else if (q->type == T_TXT) {
			/* TXT has binary or base-X data */
			char *startp;
			int txtlen;

			CHECKLEN(10);
			putshort(&p, name);
			putshort(&p, q->type);
			putshort(&p, C_IN);
			putlong(&p, 0); /* TTL */

			startp = p;
			p += 2; /* skip 2 bytes length */
			puttxtbin(&p, buflen - (p - buf), data, datalen);
			CHECKLEN(0);
			txtlen = p - startp;
			txtlen -= 2;
			putshort(&startp, txtlen);
			ancnt = 1;
		} else {
			/* NULL has raw binary data */
			CHECKLEN(10);
			putshort(&p, name);
			putshort(&p, q->type);
			putshort(&p, C_IN);
			putlong(&p, 0);	/* TTL */

			datalen = MIN(datalen, buflen - (p - buf));
			CHECKLEN(2);
			putshort(&p, datalen);
			CHECKLEN(datalen);
			putdata(&p, data, datalen);
			CHECKLEN(0);
			ancnt = 1;
		}
		header->ancount = htons(ancnt);
		break;
	case QR_QUERY:
		/* Note that iodined also uses this for forward queries */

		header->qdcount = htons(1);

		datalen = MIN(datalen, buflen - (p - buf));
		putname(&p, datalen, data);

		CHECKLEN(4);
		putshort(&p, q->type);
		putshort(&p, C_IN);

		/* EDNS0 to advertise maximum response length
		   (even CNAME/A/MX, 255+255+header would be >512) */
		if (dnsc_use_edns0) {
			header->arcount = htons(1);
			CHECKLEN(11);
			putbyte(&p, 0x00);    /* Root */
			putshort(&p, 0x0029); /* OPT */
			putshort(&p, 0x1000); /* Payload size: 4096 */
			putshort(&p, 0x0000); /* Higher bits/edns version */
			putshort(&p, 0x8000); /* Z */
			putshort(&p, 0x0000); /* Data length */
		}

		break;
	}

	len = p - buf;

	return len;
}

/* Only used when iodined gets an NS type query */
/* Mostly same as dns_encode_a_response() below */
int dns_encode_ns_response(char *buf, size_t buflen, struct query *q,
			   char *topdomain)
{
	HEADER *header;
	int len;
	short name;
	short topname;
	short nsname;
	char *ipp;
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

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	domain_len = strlen(q->name) - strlen(topdomain);
	if (domain_len < 0 || domain_len == 1)
		return -1;
	if (strcasecmp(q->name + domain_len, topdomain))
		return -1;
	if (domain_len >= 1 && q->name[domain_len - 1] != '.')
		return -1;

	/* pointer to start of topdomain; instead of dots at the end
	   we have length-bytes in front, so total length is the same */
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

	/* Do we have an IPv4 address to send? */
	if (q->destination.ss_family == AF_INET) {
		struct sockaddr_in *dest = (struct sockaddr_in *) &q->destination;

		/* One additional record coming */
		header->arcount = htons(1);

		/* Additional data (A-record of NS server) */
		CHECKLEN(12);
		putshort(&p, nsname);		/* Name Server */
		putshort(&p, T_A);		/* Type */
		putshort(&p, C_IN);		/* Class */
		putlong(&p, 3600);		/* TTL */
		putshort(&p, 4);		/* Data length */

		/* ugly hack to output IP address */
		ipp = (char *) &dest->sin_addr.s_addr;
		CHECKLEN(4);
		putbyte(&p, *(ipp++));
		putbyte(&p, *(ipp++));
		putbyte(&p, *(ipp++));
		putbyte(&p, *ipp);
	}

	len = p - buf;
	return len;
}

/* Only used when iodined gets an A type query for ns.topdomain or
 * www.topdomain . Mostly same as dns_encode_ns_response() above */
int dns_encode_a_response(char *buf, size_t buflen, struct query *q)
{
	struct sockaddr_in *dest = (struct sockaddr_in *) &q->destination;
	HEADER *header;
	int len;
	short name;
	char *ipp;
	char *p;

	/* Check if we have an IPv4 address to send */
	if (q->destination.ss_family != AF_INET)
		return -1;

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

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	/* Query section */
	putname(&p, buflen - (p - buf), q->name); /* Name */
	CHECKLEN(4);
	putshort(&p, q->type);	/* Type */
	putshort(&p, C_IN);	/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);	/* Name */
	putshort(&p, q->type);	/* Type */
	putshort(&p, C_IN);	/* Class */
	putlong(&p, 3600);	/* TTL */
	putshort(&p, 4);	/* Data length */

	/* ugly hack to output IP address */
	ipp = (char *) &dest->sin_addr.s_addr;
	CHECKLEN(4);
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *ipp);

	len = p - buf;
	return len;
}

#undef CHECKLEN

unsigned short dns_get_id(char *packet, size_t packetlen)
{
	HEADER *header;
	header = (HEADER*)packet;

	if (packetlen < sizeof(HEADER))
		return 0;

	return ntohs(header->id);
}

#define CHECKLEN(x) if (packetlen < (x) + (unsigned)(data-packet))  return 0

int dns_decode(char *buf, size_t buflen, struct query *q, qr_t qr, char *packet,
	       size_t packetlen)
{
	char name[QUERY_NAME_SIZE];
	char rdata[4*1024];
	HEADER *header;
	short qdcount;
	short ancount;
	uint32_t ttl;
	unsigned short class;
	unsigned short type;
	char *data;
	unsigned short rlen;
	int id;
	int rv;

	q->id2 = 0;
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
		if (qdcount < 1) {
			/* We need a question */
			return -1;
		}

		if (q != NULL)
			q->id = id;

		/* Read name even if no answer, to give better error message */
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

		if (ancount < 1) {
			/* DNS errors like NXDOMAIN have ancount=0 and
			   stop here. CNAME may also have A; MX/SRV may have
			   multiple results. */
			return -1;
		}

		/* Here type is still the question type */
		if (type == T_NULL || type == T_PRIVATE) {
			/* Assume that first answer is what we wanted */
			readname(packet, packetlen, &data, name, sizeof(name));
			CHECKLEN(10);
			readshort(packet, &data, &type);
			readshort(packet, &data, &class);
			readlong(packet, &data, &ttl);
			readshort(packet, &data, &rlen);

			rv = MIN(rlen, sizeof(rdata));
			rv = readdata(packet, &data, rdata, rv);
			if (rv >= 2 && buf) {
				rv = MIN(rv, buflen);
				memcpy(buf, rdata, rv);
			} else {
				rv = 0;
			}
		}
		else if ((type == T_A || type == T_CNAME) && buf) {
			/* Assume that first answer is what we wanted */
			readname(packet, packetlen, &data, name, sizeof(name));
			CHECKLEN(10);
			readshort(packet, &data, &type);
			readshort(packet, &data, &class);
			readlong(packet, &data, &ttl);
			readshort(packet, &data, &rlen);

			if (type == T_CNAME) {
				/* For tunnels, query type A has CNAME type answer */
				memset(name, 0, sizeof(name));
				readname(packet, packetlen, &data, name, sizeof(name) - 1);
				name[sizeof(name)-1] = '\0';
				strncpy(buf, name, buflen);
				buf[buflen - 1] = '\0';
				rv = strlen(buf);
			}
			if (type == T_A) {
				/* Answer type A includes only 4 bytes.
				   Not used for tunneling. */
				rv = MIN(rlen, sizeof(rdata));
				rv = readdata(packet, &data, rdata, rv);
				if (rv >= 2 && buf) {
					rv = MIN(rv, buflen);
					memcpy(buf, rdata, rv);
				} else {
					rv = 0;
				}
			}
		}
		else if ((type == T_MX || type == T_SRV) && buf) {
			/* We support 250 records, 250*(255+header) ~= 64kB.
			   Only exact 10-multiples are accepted, and gaps in
			   numbering are not jumped over (->truncated).
			   Hopefully DNS servers won't mess around too much.
			 */
			char names[250][QUERY_NAME_SIZE];
			char *rdatastart;
			unsigned short pref;
			int i;
			int offset;

			memset(names, 0, sizeof(names));

			for (i = 0; i < ancount; i++) {
				readname(packet, packetlen, &data, name, sizeof(name));
				CHECKLEN(12);
				readshort(packet, &data, &type);
				readshort(packet, &data, &class);
				readlong(packet, &data, &ttl);
				readshort(packet, &data, &rlen);
				rdatastart = data;
				readshort(packet, &data, &pref);

				if (type == T_SRV) {
					/* skip weight, port */
					data += 4;
					CHECKLEN(0);
				}

				if (pref % 10 == 0 && pref >= 10 &&
				    pref < 2500) {
					readname(packet, packetlen, &data,
						 names[pref / 10 - 1],
						 QUERY_NAME_SIZE - 1);
					names[pref / 10 - 1]
						[QUERY_NAME_SIZE-1] = '\0';
				}

				/* always trust rlen, not name encoding */
				data = rdatastart + rlen;
				CHECKLEN(0);
			}

			/* output is like Hname10.com\0Hname20.com\0\0 */
			offset = 0;
			i = 0;
			while (names[i][0] != '\0') {
				int l = MIN(strlen(names[i]), buflen-offset-2);
				if (l <= 0)
					break;
				memcpy(buf + offset, names[i], l);
				offset += l;
				*(buf + offset) = '\0';
				offset++;
				i++;
			}
			*(buf + offset) = '\0';
			rv = offset;
		}
		else if (type == T_TXT && buf) {
			/* Assume that first answer is what we wanted */
			readname(packet, packetlen, &data, name, sizeof(name));
			CHECKLEN(10);
			readshort(packet, &data, &type);
			readshort(packet, &data, &class);
			readlong(packet, &data, &ttl);
			readshort(packet, &data, &rlen);

			rv = readtxtbin(packet, &data, rlen, rdata,
				        sizeof(rdata));
			if (rv >= 1) {
				rv = MIN(rv, buflen);
				memcpy(buf, rdata, rv);
			} else {
				rv = 0;
			}
		}

		/* Here type is the answer type (note A->CNAME) */
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

