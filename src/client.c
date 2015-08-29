/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015 Frekk van Blagh <frekk@frekkworks.com>
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

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <zlib.h>
#include <time.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#endif

#include "common.h"
#include "encoding.h"
#include "base32.h"
#include "base64.h"
#include "base64u.h"
#include "base128.h"
#include "dns.h"
#include "login.h"
#include "tun.h"
#include "version.h"
#include "window.h"
#include "client.h"

static void handshake_lazyoff(int dns_fd);

int debug;

static int running;
static const char *password;

/* Nameserver/domain info */
static struct sockaddr_storage *nameserv_addrs;
static int nameserv_addrs_len;
static int current_nameserver;
static struct sockaddr_storage raw_serv;
static int raw_serv_len;
static const char *topdomain;

static uint16_t rand_seed;

/* Current up/downstream window data */
static struct frag_buffer *outbuf;
static struct frag_buffer *inbuf;
/* Next downstream seqID to be ACK'd (-1 if none pending) */
static int next_downstream_ack;

/* My userid at the server */
static char userid;
static char userid_char;		/* used when sending (lowercase) */
static char userid_char2;		/* also accepted when receiving (uppercase) */

static uint16_t chunkid;

/* Base32 encoder used for non-data packets and replies */
static struct encoder *b32;
/* Base64 etc encoders for replies */
static struct encoder *b64;
static struct encoder *b64u;
static struct encoder *b128;

/* The encoder used for data packets
 * Defaults to Base32, can be changed after handshake */
static struct encoder *dataenc;

/* The encoder to use for downstream data */
static char downenc = ' ';

/* set query type to send */
static unsigned short do_qtype = T_UNSET;

/* My connection mode */
static enum connection conn;

static int selecttimeout;		/* RFC says timeout minimum 5sec */
static int lazymode;
static long send_ping_soon;
static time_t lastdownstreamtime;
static long send_query_sendcnt = -1;
static long send_query_recvcnt = 0;
static size_t hostname_maxlen = 0xFF;

void
client_init()
{
	running = 1;
	b32 = get_base32_encoder();
	b64 = get_base64_encoder();
	b64u = get_base64u_encoder();
	b128 = get_base128_encoder();
	dataenc = get_base32_encoder();
	rand_seed = ((unsigned int) rand()) & 0xFFFF;
	send_ping_soon = 1;	/* send ping immediately after startup */
	conn = CONN_DNS_NULL;

	chunkid = ((unsigned int) rand()) & 0xFFFF;

	// TODO: user-set window size (command line option)
	outbuf = window_buffer_init(100, 10, hostname_maxlen, WINDOW_SENDING);
	/* Incoming buffer max fragsize doesn't matter */
	inbuf = window_buffer_init(128, 10, MAX_FRAGSIZE, WINDOW_RECVING);

	next_downstream_ack = -1;
	current_nameserver = 0;
}

void
client_stop()
{
	running = 0;
}

enum connection
client_get_conn()
{
	return conn;
}

void
client_set_nameservers(struct sockaddr_storage *addr, int addrslen)
{
	nameserv_addrs = addr;
	nameserv_addrs_len = addrslen;
}

void
client_set_topdomain(const char *cp)
{
	topdomain = cp;
}

void
client_set_password(const char *cp)
{
	password = cp;
}

int
client_set_qtype(char *qtype)
{
	if (!strcasecmp(qtype, "NULL"))
      		do_qtype = T_NULL;
	else if (!strcasecmp(qtype, "PRIVATE"))
		do_qtype = T_PRIVATE;
	else if (!strcasecmp(qtype, "CNAME"))
		do_qtype = T_CNAME;
	else if (!strcasecmp(qtype, "A"))
		do_qtype = T_A;
	else if (!strcasecmp(qtype, "MX"))
		do_qtype = T_MX;
	else if (!strcasecmp(qtype, "SRV"))
		do_qtype = T_SRV;
	else if (!strcasecmp(qtype, "TXT"))
		do_qtype = T_TXT;
	return (do_qtype == T_UNSET);
}

char *
client_get_qtype()
{
	char *c = "UNDEFINED";

	if (do_qtype == T_NULL)		c = "NULL";
	else if (do_qtype == T_PRIVATE)	c = "PRIVATE";
	else if (do_qtype == T_CNAME)	c = "CNAME";
	else if (do_qtype == T_A)	c = "A";
	else if (do_qtype == T_MX)	c = "MX";
	else if (do_qtype == T_SRV)	c = "SRV";
	else if (do_qtype == T_TXT)	c = "TXT";

	return c;
}

void
client_set_downenc(char *encoding)
{
	if (!strcasecmp(encoding, "base32"))
		downenc = 'T';
	else if (!strcasecmp(encoding, "base64"))
		downenc = 'S';
	else if (!strcasecmp(encoding, "base64u"))
		downenc = 'U';
	else if (!strcasecmp(encoding, "base128"))
		downenc = 'V';
	else if (!strcasecmp(encoding, "raw"))
		downenc = 'R';
}

void
client_set_selecttimeout(int select_timeout)
{
	selecttimeout = select_timeout;
}

void
client_set_lazymode(int lazy_mode)
{
	lazymode = lazy_mode;
}

void
client_set_hostname_maxlen(size_t i)
{
	if (i <= 0xFF && i != hostname_maxlen) {
		hostname_maxlen = i;
		outbuf->maxfraglen = get_raw_length_from_dns(hostname_maxlen - UPSTREAM_HDR, dataenc, topdomain);
	}
}

const char *
client_get_raw_addr()
{
	return format_addr(&raw_serv, raw_serv_len);
}

void
client_rotate_nameserver()
{
	current_nameserver ++;
	if (current_nameserver >= nameserv_addrs_len)
		current_nameserver = 0;
}

static void
send_query(int fd, uint8_t *hostname)
{
	uint8_t packet[4096];
	struct query q;
	size_t len;

	if (debug >= 2)
		fprintf(stderr, "TX: pkt len %lu: hostname '%s'\n", strlen((char *)hostname), hostname);

	chunkid += 7727;
	if (chunkid == 0)
		/* 0 is used as "no-query" in iodined.c */
		chunkid = 7727;

	q.id = chunkid;
	q.type = do_qtype;

	len = dns_encode((char *)packet, sizeof(packet), &q, QR_QUERY, (char *)hostname, strlen((char *)hostname));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	if (debug >= 3)
		fprintf(stderr, "  Sendquery: id %5d name[0] '%c'\n", q.id, hostname[0]);

	sendto(fd, packet, len, 0, (struct sockaddr*) &nameserv_addrs[current_nameserver],
			sizeof(struct sockaddr_storage));

	client_rotate_nameserver();

	/* There are DNS relays that time out quickly but don't send anything
	   back on timeout.
	   And there are relays where, in lazy mode, our new query apparently
	   _replaces_ our previous query, and we get no answers at all in
	   lazy mode while legacy immediate-ping-pong works just fine.
	   Here we detect and fix these situations.
	   (Can't very well do this anywhere else; this is the only place
	   we'll reliably get to in such situations.)
	 */

	if (send_query_sendcnt >= 0 && send_query_sendcnt < 100 && lazymode) {
		send_query_sendcnt++;

		if ((send_query_sendcnt > 6 && send_query_recvcnt <= 0) ||
		    (send_query_sendcnt > 10 &&
		     4 * send_query_recvcnt < send_query_sendcnt)) {
			if (selecttimeout > 1) {
				warnx("Receiving too few answers. Setting interval to 1 (-I1)");
				selecttimeout = 1;
				/* restart counting */
				send_query_sendcnt = 0;
				send_query_recvcnt = 0;
			} else if (lazymode) {
				warnx("Receiving too few answers. Will try to switch lazy mode off, but that may not always work any more. Start with -L0 next time on this network.");
				lazymode = 0;
				selecttimeout = 1;
				handshake_lazyoff(fd);
			}
		}
	}
}

static void
send_raw(int fd, char *buf, int buflen, int user, int cmd)
{
	char packet[4096];
	int len;

	len = MIN(sizeof(packet) - RAW_HDR_LEN, buflen);

	memcpy(packet, raw_header, RAW_HDR_LEN);
	if (len) {
		memcpy(&packet[RAW_HDR_LEN], buf, len);
	}

	len += RAW_HDR_LEN;
	packet[RAW_HDR_CMD] = cmd | (user & 0x0F);

	sendto(fd, packet, len, 0, (struct sockaddr*)&raw_serv, sizeof(raw_serv));
}

static void
send_raw_data(int dns_fd) // TODO: fix send_raw
{
	errx(1, "send_raw_data NEEDS FIXING!");
	/*send_raw(dns_fd, outpkt.data, outpkt.len, userid, RAW_HDR_CMD_DATA);
	outpkt.len = 0;*/
}


static void
send_packet(int fd, char cmd, const uint8_t *data, const size_t datalen)
/* Base32 encodes data and sends as single DNS query */
{
	uint8_t buf[4096];

	buf[0] = cmd;

	build_hostname(buf, sizeof(buf), data, datalen, topdomain, b32, hostname_maxlen, 1);

	send_query(fd, buf);
}

static inline int
is_sending()
{
	return (outbuf->numitems > 0);
}

static inline int
is_recving()
{
	return inbuf->numitems > 0;
}

static void
send_ping(int fd, int ping_response, int ack) // TODO: setup window sync stuff in ping
{
	if (conn == CONN_DNS_NULL) {
		uint8_t data[9];

		data[0] = userid;
		data[1] = ack & 0xFF;
		data[2] = outbuf->windowsize & 0xff;
		data[3] = inbuf->windowsize & 0xff;
		data[4] = inbuf->start_seq_id & 0xff;  /* Downstream window start */
		data[5] = outbuf->start_seq_id & 0xff; /* Upstream window start */
		data[6] = ((ack < 0 ? 0 : 1) << 2) | (ping_response & 1);
		data[7] = (rand_seed >> 8) & 0xff;
		data[8] = (rand_seed >> 0) & 0xff;
		rand_seed += 263;

		send_packet(fd, 'p', data, sizeof(data));
	} else {
		send_raw(fd, NULL, 0, userid, RAW_HDR_CMD_PING);
	}
}

static void
send_next_frag(int fd)
/* Sends next available fragment of data from the outgoing window buffer */
{
	static uint8_t buf[MAX_FRAGSIZE], hdr[5];
	int code;
	static int datacmc = 0;
	static char *datacmcchars = "abcdefghijklmnopqrstuvwxyz0123456789";
	fragment *f;
	size_t buflen, len;

	/* Get next fragment to send */
	f = window_get_next_sending_fragment(outbuf, &next_downstream_ack);
	if (!f) {
		if (is_sending()) {
			/* There is stuff to send but we're out of sync, so send a ping
			 * to get things back in order and keep the packets flowing */
			send_ping(fd, 1, next_downstream_ack);
			next_downstream_ack = -1;
			window_tick(outbuf);
		}
		return; /* nothing to send - why was this called? */
	}

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */
	buf[0] = userid_char;		/* First byte is hex userid */

	buf[1] = datacmcchars[datacmc]; /* Second byte is data-CMC */

	/* Next 3 bytes is seq ID, downstream ACK and flags */
	code = ((f->ack_other < 0 ? 0 : 1) << 3) | (f->is_nack << 2)
			| (f->start << 1) | f->end;

	hdr[0] = f->seqID & 0xFF;
	hdr[1] = f->ack_other & 0xFF;
	hdr[2] = code << 4; /* Flags are in upper 4 bits - lower 4 unused */

	buflen = sizeof(buf) - 1;
	/* Encode 3 bytes data into 2 bytes after buf */
	len = b32->encode(buf + 2, &buflen, hdr, 3);
	if (len != 5)
		warnx("mismatch in encoded upstream header length! expected 5, got %lu", len);

	/* Encode data into buf after header (6 = user + CMC + 4 bytes header) */
	build_hostname(buf, sizeof(buf), f->data, f->len, topdomain,
				   dataenc, hostname_maxlen, 6);

	datacmc++;
	if (datacmc >= 36)
		datacmc = 0;

	send_query(fd, buf);

	window_tick(outbuf);
}

static void
write_dns_error(struct query *q, int ignore_some_errors)
/* This is called from:
   1. handshake_waitdns() when already checked that reply fits to our
      latest query.
   2. tunnel_dns() when already checked that reply is for our ping or data
      packet, but not necessarily the most recent (SERVFAIL mostly comes
      after long delay).
   So ignorable errors are never printed.
*/
{
	if (!q) return;

	switch (q->rcode) {
	case NOERROR:	/* 0 */
		if (!ignore_some_errors)
			warnx("Got reply without error, but also without question and/or answer");
		break;
	case FORMERR:	/* 1 */
		warnx("Got FORMERR as reply: server does not understand our request");
		break;
	case SERVFAIL:	/* 2 */
		if (!ignore_some_errors)
			warnx("Got SERVFAIL as reply: server failed or recursion timeout");
		break;
	case NXDOMAIN:	/* 3 */
		warnx("Got NXDOMAIN as reply: domain does not exist");
		break;
	case NOTIMP:	/* 4 */
		warnx("Got NOTIMP as reply: server does not support our request");
		break;
	case REFUSED:	/* 5 */
		warnx("Got REFUSED as reply");
		break;
	default:
		warnx("Got RCODE %u as reply", q->rcode);
		break;
	}
}

static size_t
dns_namedec(uint8_t *outdata, size_t outdatalen, uint8_t *buf, size_t buflen)
/* Decodes *buf to *outdata.
 * *buf WILL be changed by undotify.
 * Note: buflen must be _exactly_ strlen(buf) before undotifying.
 * (undotify of reduced-len won't copy \0, base-X decode will decode too much.)
 * Returns #bytes usefully filled in outdata.
 */
{
	size_t outdatalenu = outdatalen;

	switch (buf[0]) {
	case 'h': /* Hostname with base32 */
	case 'H':
		/* Need 1 byte H, 3 bytes ".xy", >=1 byte data */
		if (buflen < 5)
			return 0;

		/* this also does undotify */
		return unpack_data(outdata, outdatalen, buf + 1, buflen - 4, b32);

	case 'i': /* Hostname++ with base64 */
	case 'I':
		/* Need 1 byte I, 3 bytes ".xy", >=1 byte data */
		if (buflen < 5)
			return 0;

		/* this also does undotify */
		return unpack_data(outdata, outdatalen, buf + 1, buflen - 4, b64);

	case 'j': /* Hostname++ with base64u */
	case 'J':
		/* Need 1 byte J, 3 bytes ".xy", >=1 byte data */
		if (buflen < 5)
			return 0;

		/* this also does undotify */
		return unpack_data(outdata, outdatalen, buf + 1, buflen - 4, b64u);

	case 'k': /* Hostname++ with base128 */
	case 'K':
		/* Need 1 byte J, 3 bytes ".xy", >=1 byte data */
		if (buflen < 5)
			return 0;

		/* this also does undotify */
		return unpack_data(outdata, outdatalen, buf + 1, buflen - 4, b128);

	case 't': /* plain base32(Thirty-two) from TXT */
	case 'T':
		if (buflen < 2)
			return 0;

		return b32->decode(outdata, &outdatalenu, buf + 1, buflen - 1);

	case 's': /* plain base64(Sixty-four) from TXT */
	case 'S':
		if (buflen < 2)
			return 0;

		return b64->decode(outdata, &outdatalenu, buf + 1, buflen - 1);

	case 'u': /* plain base64u (Underscore) from TXT */
	case 'U':
		if (buflen < 2)
			return 0;

		return b64u->decode(outdata, &outdatalenu, buf + 1, buflen - 1);

	case 'v': /* plain base128 from TXT */
	case 'V':
		if (buflen < 2)
			return 0;

		return b128->decode(outdata, &outdatalenu, buf + 1, buflen - 1);

	case 'r': /* Raw binary from TXT */
	case 'R':
		/* buflen>=1 already checked */
		buflen--;
		buflen = MIN(buflen, outdatalen);
		memcpy(outdata, buf + 1, buflen);
		return buflen;

	default:
		warnx("Received unsupported encoding");
		return 0;
	}

	/* notreached */
	return 0;
}

static int
read_dns_withq(int dns_fd, int tun_fd, uint8_t *buf, size_t buflen, struct query *q)
/* Returns -1 on receive error or decode error, including DNS error replies.
   Returns 0 on replies that could be correct but are useless, and are not
   DNS error replies.
   Returns >0 on correct replies; value is #valid bytes in *buf.
*/
{
	struct sockaddr_storage from;
	uint8_t data[64*1024];
	socklen_t addrlen;
	int r;

	addrlen = sizeof(from);
	if ((r = recvfrom(dns_fd, data, sizeof(data), 0,
			  (struct sockaddr*)&from, &addrlen)) < 0) {
		warn("recvfrom");
		return -1;
	}

	if (conn == CONN_DNS_NULL) {
		int rv;
		if (r <= 0)
			/* useless packet */
			return 0;

		rv = dns_decode((char *)buf, buflen, q, QR_ANSWER, (char *)data, r);
		if (rv <= 0)
			return rv;

		if (q->type == T_CNAME || q->type == T_TXT)
		/* CNAME can also be returned from an A question */
		{
			/*
			 * buf is a hostname or txt stream that we still need to
			 * decode to binary
			 *
			 * also update rv with the number of valid bytes
			 *
			 * data is unused here, and will certainly hold the smaller binary
			 */

			rv = dns_namedec(data, sizeof(data), buf, rv);

			rv = MIN(rv, buflen);
			if (rv > 0)
				memcpy(buf, data, rv);

		} else if (q->type == T_MX || q->type == T_SRV) {
			/* buf is like "Hname.com\0Hanother.com\0\0" */
			int buftotal = rv;	/* idx of last \0 */
			int bufoffset = 0;
			int dataoffset = 0;
			int thispartlen, dataspace, datanew;

			while (1) {
				thispartlen = strlen((char *)buf);
				thispartlen = MIN(thispartlen, buftotal-bufoffset);
				dataspace = sizeof(data) - dataoffset;
				if (thispartlen <= 0 || dataspace <= 0)
					break;

				datanew = dns_namedec(data + dataoffset, dataspace,
						      buf + bufoffset, thispartlen);
				if (datanew <= 0)
					break;

				bufoffset += thispartlen + 1;
				dataoffset += datanew;
			}
			rv = dataoffset;
			rv = MIN(rv, buflen);
			if (rv > 0)
				memcpy(buf, data, rv);
		}

		return rv;
	} else { /* CONN_RAW_UDP */
		unsigned long datalen;
		char buf[64*1024];

		/* minimum length */
		if (r < RAW_HDR_LEN) return 0;
		/* should start with header */
		if (memcmp(data, raw_header, RAW_HDR_IDENT_LEN)) return 0;
		/* should be my user id */
		if (RAW_HDR_GET_USR(data) != userid) return 0;

		if (RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_DATA ||
		    RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_PING)
			lastdownstreamtime = time(NULL);

		/* should be data packet */
		if (RAW_HDR_GET_CMD(data) != RAW_HDR_CMD_DATA) return 0;

		r -= RAW_HDR_LEN;
		datalen = sizeof(buf);
		if (uncompress((uint8_t*)buf, &datalen, (uint8_t*) &data[RAW_HDR_LEN], r) == Z_OK) {
			write_tun(tun_fd, (uint8_t*)buf, datalen);
		}

		/* don't process any further */
		return 0;
	}
}

static int
handshake_waitdns(int dns_fd, char *buf, size_t buflen, char c1, char c2, int timeout)
/* Wait for DNS reply fitting to our latest query and returns it.
   Returns length of reply = #bytes used in buf.
   Returns 0 if fitting reply happens to be useless.
   Returns -2 on (at least) DNS error that fits to our latest query,
   error message already printed.
   Returns -3 on timeout (given in seconds).
   Returns -1 on other errors.

   Timeout is restarted when "wrong" (previous/delayed) replies are received,
   so effective timeout may be longer than specified.
*/
{
	struct query q;
	int r, rv;
	fd_set fds;
	struct timeval tv;

	while (1) {
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);
		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if (r < 0)
			return -1;	/* select error */
		if (r == 0)
			return -3;	/* select timeout */

		q.id = 0;
		q.name[0] = '\0';
		rv = read_dns_withq(dns_fd, 0, (uint8_t *)buf, buflen, &q);

		if (q.id != chunkid || (q.name[0] != c1 && q.name[0] != c2)) {
			if (debug >= 1)
				fprintf(stderr, "Ignoring unfitting reply id %d starting with '%c'\n", q.id, q.name[0]);
			continue;
		}

		/* if still here: reply matches our latest query */

		/* Non-recursive DNS servers (such as [a-m].root-servers.net)
		   return no answer, but only additional and authority records.
		   Can't explicitly test for that here, just assume that
		   NOERROR is such situation. Only trigger on the very first
		   requests (Y or V, depending if -T given).
		 */
		if (rv < 0 && q.rcode == NOERROR &&
		    (q.name[0] == 'Y' || q.name[0] == 'y' ||
		     q.name[0] == 'V' || q.name[0] == 'v')) {
			fprintf(stderr, "Got empty reply. This nameserver may not be resolving recursively, use another.\n");
			fprintf(stderr, "Try \"iodine [options] ns.%s %s\" first, it might just work.\n",
				topdomain, topdomain);
			return -2;
		}

		/* If we get an immediate SERVFAIL on the handshake query
		   we're waiting for, wait a while before sending the next.
		   SERVFAIL reliably happens during fragsize autoprobe, but
		   mostly long after we've moved along to some other queries.
		   However, some DNS relays, once they throw a SERVFAIL, will
		   for several seconds apply it immediately to _any_ new query
		   for the same topdomain. When this happens, waiting a while
		   is the only option that works.
		 */
		if (rv < 0 && q.rcode == SERVFAIL)
			sleep(1);

		if (rv < 0) {
			write_dns_error(&q, 1);
			return -2;
		}
		/* rv either 0 or >0, return it as is. */
		return rv;
	}

	/* not reached */
	return -1;
}

static int
parse_data(uint8_t *data, size_t len, fragment *f)
{
	size_t headerlen = DOWNSTREAM_HDR;
	memset(f, 0, sizeof(fragment));
	int ping = (data[2] >> 5) & 1;
	f->compressed = (data[2] >> 4) & 1;
	f->ack_other = (data[2] >> 3) & 1 ? data[1] : -1;
	f->is_nack = (data[2] >> 2) & 1;
	f->start = (data[2] >> 1) & 1;
	f->end = data[2] & 1;
	f->seqID = data[0];
	if (ping) { /* Handle ping stuff */
		headerlen = DOWNSTREAM_PING_HDR;
		if (len < headerlen) return -1; /* invalid packet - continue */
		/* Parse data/ping header */
		static unsigned dn_start_seq, up_start_seq, dn_wsize, up_wsize;
		dn_wsize = data[3]; /* TODO: do something with wsize/start params in ping */
		up_wsize = data[4];
		dn_start_seq = data[5];
		up_start_seq = data[6];
		if (debug >= 3)
			fprintf(stderr, "PING pkt data=%lu WS: up=%u, dn=%u; Start: up=%u, dn=%u\n",
					len - headerlen, up_wsize, dn_wsize, up_start_seq, dn_start_seq);
	}
	f->len = len - headerlen;
	if (f->len > 0) memcpy(f->data, data + headerlen, MIN(f->len, sizeof(f->data)));
	return ping; /* return ping flag (if corresponding query was a ping) */
}

static int
tunnel_tun(int tun_fd, int dns_fd)
{
	size_t outlen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	ssize_t read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return -1;

	/* Check if outgoing buffer can hold data */
	if (window_buffer_available(outbuf) < (read / MAX_FRAGSIZE) + 1) {
		if (debug >= 3)
			fprintf(stderr, "  Outgoing buffer full (%lu/%lu), not adding data!\n", outbuf->numitems, outbuf->length);
		return -1;
	}

	if (debug >= 2)
		fprintf(stderr, " IN: %lu bytes on tunnel\n", read);

	outlen = sizeof(out);
	compress2(out, &outlen, in, read, 9);

	window_add_outgoing_data(outbuf, out, outlen, 1);

	if (conn == CONN_DNS_NULL) {
		send_next_frag(dns_fd);

		// TODO: adjust min send interval based on DNS server droppiness
		send_ping_soon = is_sending() ? 2 : 0;
	} else {
		send_raw_data(dns_fd);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	static long packrecv = 0;
	static long packrecv_oos = 0;
	static long packrecv_servfail = 0;
	static struct query q;
	size_t datalen, buflen;
	static uint8_t buf[64*1024], cbuf[64*1024];
	static fragment f;
	int read, compressed, res;
	int send_something_now = 0;

	memset(&q, 0, sizeof(q));
	memset(buf, 0, sizeof(buf));
	memset(cbuf, 0, sizeof(cbuf));
	read = read_dns_withq(dns_fd, tun_fd, cbuf, sizeof(cbuf), &q);

	if (conn != CONN_DNS_NULL)
		return 1;  /* everything already done */

	if (debug >= 2)
		fprintf(stderr, "RX: id %5d name[0]='%c'\n", q.id, q.name[0]);

	/* Don't process anything that isn't data for us; usually error
	   replies from fragsize probes etc. However a sequence of those,
	   mostly 1 sec apart, will continuously break the >=2-second select
	   timeout, which means we won't send a proper ping for a while.
	   So make select a bit faster, <1sec. */
	if (q.name[0] != 'P' && q.name[0] != 'p' &&
	    q.name[0] != userid_char && q.name[0] != userid_char2) {
		send_ping_soon = 700;
		return -1;	/* nothing done */
	}

	if (read < DOWNSTREAM_HDR) {
		/* Maybe SERVFAIL etc. Send ping to get things back in order,
		   but wait a bit to prevent fast ping-pong loops. */

		if (read < 0)
			write_dns_error(&q, 0);

		if (read < 0 && q.rcode == SERVFAIL && lazymode &&
		    selecttimeout > 1) {
			if (packrecv < 500 && packrecv_servfail < 4) {
				packrecv_servfail++;
				warnx("Hmm, that's %ld. Your data should still go through...", packrecv_servfail);
			} else if (packrecv < 500 && packrecv_servfail == 4) {
				packrecv_servfail++;
				warnx("I think %ld is too many. Setting interval to 1 to hopefully reduce SERVFAILs. But just ignore them if data still comes through. (Use -I1 next time on this network.)", packrecv_servfail);
				selecttimeout = 1;
				send_query_sendcnt = 0;
				send_query_recvcnt = 0;
			} else if (packrecv >= 500 && packrecv_servfail > 0) {
				warnx("(Sorry, stopped counting; try -I1 if you experience hiccups.)");
				packrecv_servfail = 0;
			}
		}

		send_ping_soon = 900;
		return -1;	/* nothing done */
	}

	if (read == 5 && !strncmp("BADIP", (char *)cbuf, 5)) {
		warnx("BADIP: Server rejected sender IP address (maybe iodined -c will help), or server kicked us due to timeout. Will exit if no downstream data is received in 60 seconds.");
		return -1;	/* nothing done */
	}

	if (send_ping_soon) {
		send_something_now = 1;
		send_ping_soon = 0;
	}

	/* Okay, we have a recent downstream packet */
	lastdownstreamtime = time(NULL);
	if (!(packrecv & 0x1000000))
		packrecv++;
	send_query_recvcnt++;  /* overflow doesn't matter */

	/* Decode the downstream data header and fragment-ify ready for processing */
	res = parse_data(cbuf, read, &f);
	if ((debug >= 3 && res) || (debug >= 2 && !res))
		fprintf(stderr, " RX %s frag id %u, ACK %d, nack %d, datalen %lu, s%d e%d\n",
				res ? "PING" : "DATA", f.seqID, f.ack_other, f.is_nack, f.len, f.start, f.end);

	window_ack(outbuf, f.ack_other);

	/* In lazy mode, we shouldn't get immediate replies to our most-recent
	 query, only during heavy data transfer. Since this means the server
	 doesn't have any packets to send, send one relatively fast (but not
	 too fast, to avoid runaway ping-pong loops..) */
	/* Don't send anything too soon; no data waiting from server */
	if (f.len == 0) {
		if (!res && debug >= 1)
			fprintf(stderr, "Received downstream data with 0 length and NOT a ping!");
		send_ping_soon = 700;
		return -1;
	}

	/* Send something quickly to see if any more data needs to come through */
	send_ping_soon = 5;

	/* Downstream data traffic */
	if (!window_process_incoming_fragment(inbuf, &f)) {
		/* Packet outside window - old, duped and irrelevant */
		packrecv_oos ++;
		return -1;	/* nothing done */
	}

	/* Get next ACK if nothing already pending: only do this if we are sending */
	if (next_downstream_ack < 0) {
		if ((next_downstream_ack = window_get_next_ack(inbuf)) >= 0) {
			send_something_now = 1;
		}
	}

	// TODO: check OOS packet count and send ping to update params

	datalen = window_reassemble_data(inbuf, cbuf, sizeof(cbuf), &compressed);
	if (datalen != 0) {
		if (compressed) {
			buflen = sizeof(buf);
			if ((res = uncompress(buf, &buflen, cbuf, datalen)) != Z_OK) {
				if (debug >= 1)
					warnx("Uncompress failed (%d): reassembled data corrupted or incomplete!", res);
			}
			datalen = buflen;
		}
		write_tun(tun_fd, buf, datalen);
		/* ACK frag quickly */
		send_ping_soon = 2;
	} else {
		/* ACK received frag and let server send any more data */
		send_something_now = 1;
	}

	/* Move window along after doing all data processing */
	window_tick(inbuf);

	/* Upstream data traffic */
	if (is_sending() || is_recving()) {
		/* More to send - next fragment*/
		send_next_frag(dns_fd);
		send_ping_soon = 2;
		send_something_now = 0;
	}

	/* Send ping if we didn't send anything yet */
	if (send_something_now) {
		send_ping(dns_fd, 0, next_downstream_ack);
		next_downstream_ack = -1;
		send_ping_soon = 0;
	}

	return read;
}

int
client_tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
	int rv;
	int i;

	rv = 0;
	lastdownstreamtime = time(NULL);
	send_query_sendcnt = 0;  /* start counting now */

	while (running) {
		tv.tv_sec = selecttimeout;
		tv.tv_usec = 0;

		if (is_sending()) {
			tv.tv_sec = 0;
			tv.tv_usec = 2000;
			send_ping_soon = 0;
		}

		if (is_recving()) {
			/* get next thingy soon ish */
			tv.tv_sec = 0;
			tv.tv_usec = 5000;
		}

		if (send_ping_soon) {
			tv.tv_sec = 0;
			tv.tv_usec = send_ping_soon * 1000;
		}

		FD_ZERO(&fds);
		if (window_buffer_available(outbuf) > 16) {
			/* Fill up outgoing buffer with available data
			 * The windowing protocol manages data retransmits, timeouts etc. */
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);

 		if (difftime(lastdownstreamtime, time(NULL)) >= 60) {
 			warnx("No downstream data received in 60 seconds, shutting down.");
 			running = 0;
 		}

		if (running == 0)
			break;

		if (i < 0)
			err(1, "select < 0");

		if (i == 0) {
			/* timeout */
			if (is_sending()) {
				if (outbuf->resends < 3) { // if too many retransmits/timeouts/waiting etc.
					send_next_frag(dns_fd);
				} else {
					outbuf->resends = 0;
					send_ping(dns_fd, 1, -1);
				}
			} else {
				send_ping(dns_fd, 0, -1);
			}
			send_ping_soon = 0;

		} else {

			if (FD_ISSET(tun_fd, &fds)) {
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets send_ping_soon=0. */
			}
			if (FD_ISSET(dns_fd, &fds)) {
				tunnel_dns(tun_fd, dns_fd);
			}
		}
	}

	return rv;
}

static void
send_login(int fd, char *login, int len)
{
	uint8_t data[19];

	memset(data, 0, sizeof(data));
	data[0] = userid;
	memcpy(&data[1], login, MIN(len, 16));

	data[17] = (rand_seed >> 8) & 0xff;
	data[18] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'l', data, sizeof(data));
}

static void
send_fragsize_probe(int fd, int fragsize)
{
	uint8_t probedata[256];
	uint8_t buf[MAX_FRAGSIZE];

	/*
	 * build a large query domain which is random and maximum size,
	 * will also take up maximal space in the return packet
	 */
	memset(probedata, MAX(1, rand_seed & 0xff), sizeof(probedata));
	probedata[1] = MAX(1, (rand_seed >> 8) & 0xff);
	rand_seed++;

	/* Note: must either be same, or larger, than send_chunk() */
	build_hostname(buf, sizeof(buf), probedata, sizeof(probedata), topdomain,
				   dataenc, hostname_maxlen, 5);

	fragsize &= 0x7FF;

	buf[0] = 'r'; /* Probe downstream fragsize packet */
	buf[1] = b32_5to8((userid << 1) | ((fragsize >> 10) & 1));
	buf[2] = b32_5to8((fragsize >> 5) & 31);
	buf[3] = b32_5to8(fragsize & 31);
	buf[4] = 'd'; /* dummy to match send_chunk() */

	send_query(fd, buf);
}

static void
send_set_downstream_fragsize(int fd, int fragsize)
{
	uint8_t data[5];

	data[0] = userid;
	data[1] = (fragsize & 0xff00) >> 8;
	data[2] = (fragsize & 0x00ff);
	data[3] = (rand_seed >> 8) & 0xff;
	data[4] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'n', data, sizeof(data));
}

static void
send_version(int fd, uint32_t version)
{
	uint8_t data[6];

	data[0] = (version >> 24) & 0xff;
	data[1] = (version >> 16) & 0xff;
	data[2] = (version >> 8) & 0xff;
	data[3] = (version >> 0) & 0xff;

	data[4] = (rand_seed >> 8) & 0xff;
	data[5] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'v', data, sizeof(data));
}

static void
send_ip_request(int fd, int userid)
{
	uint8_t buf[512] = "i____.";
	buf[1] = b32_5to8(userid);

	buf[2] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[3] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[4] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat((char *)buf, topdomain, 512 - strlen((char *)buf));
	send_query(fd, buf);
}

static void
send_raw_udp_login(int dns_fd, int userid, int seed)
{
	char buf[16];
	login_calculate(buf, 16, password, seed + 1);

	send_raw(dns_fd, buf, sizeof(buf), userid, RAW_HDR_CMD_LOGIN);
}

static void
send_upenctest(int fd, char *s)
/* NOTE: String may be at most 63-4=59 chars to fit in 1 dns chunk. */
{
	char buf[512] = "z___";

	buf[1] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[2] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[3] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, s, 512);
	strncat(buf, ".", 512);
	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, (uint8_t *)buf);
}

static void
send_downenctest(int fd, char downenc, int variant, char *s, int slen)
/* Note: content/handling of s is not defined yet. */
{
	char buf[512] = "y_____.";

	buf[1] = tolower(downenc);
	buf[2] = b32_5to8(variant);

	buf[3] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[4] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[5] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, (uint8_t *)buf);
}

static void
send_codec_switch(int fd, int userid, int bits)
{
	char buf[512] = "s_____.";
	buf[1] = b32_5to8(userid);
	buf[2] = b32_5to8(bits);

	buf[3] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[4] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[5] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, (uint8_t *)buf);
}


static void
send_downenc_switch(int fd, int userid)
{
	char buf[512] = "o_____.";
	buf[1] = b32_5to8(userid);
	buf[2] = tolower(downenc);

	buf[3] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[4] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[5] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, (uint8_t *)buf);
}

static void
send_lazy_switch(int fd, int userid)
{
	char buf[512] = "o_____.";
	buf[1] = b32_5to8(userid);

	if (lazymode)
		buf[2] = 'l';
	else
		buf[2] = 'i';

	buf[3] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[4] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[5] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, (uint8_t *)buf);
}

static int
handshake_version(int dns_fd, int *seed)
{
	char hex[] = "0123456789abcdef";
	char hex2[] = "0123456789ABCDEF";
	char in[4096];
	uint32_t payload;
	int i;
	int read;

	for (i = 0; running && i < 5; i++) {

		send_version(dns_fd, PROTOCOL_VERSION);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'v', 'V', i+1);

		if (read >= 9) {
			payload =  (((in[4] & 0xff) << 24) |
					((in[5] & 0xff) << 16) |
					((in[6] & 0xff) << 8) |
					((in[7] & 0xff)));

			if (strncmp("VACK", (char *)in, 4) == 0) {
				*seed = payload;
				userid = in[8];
				userid_char = hex[userid & 15];
				userid_char2 = hex2[userid & 15];

				fprintf(stderr, "Version ok, both using protocol v 0x%08x. You are user #%d\n",
					PROTOCOL_VERSION, userid);
				return 0;
			} else if (strncmp("VNAK", (char *)in, 4) == 0) {
				warnx("You use protocol v 0x%08x, server uses v 0x%08x. Giving up",
						PROTOCOL_VERSION, payload);
				return 1;
			} else if (strncmp("VFUL", (char *)in, 4) == 0) {
				warnx("Server full, all %d slots are taken. Try again later", payload);
				return 1;
			}
		} else if (read > 0)
			warnx("did not receive proper login challenge");

		fprintf(stderr, "Retrying version check...\n");
	}
	warnx("couldn't connect to server (maybe other -T options will work)");
	return 1;
}

static int
handshake_login(int dns_fd, int seed)
{
	char in[4096];
	char login[16];
	char server[65];
	char client[65];
	int mtu;
	int i;
	int read;

	login_calculate(login, 16, password, seed);

	for (i=0; running && i<5 ;i++) {

		send_login(dns_fd, login, 16);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'l', 'L', i+1);

		if (read > 0) {
			int netmask;
			if (strncmp("LNAK", in, 4) == 0) {
				fprintf(stderr, "Bad password\n");
				return 1;
			} else if (sscanf(in, "%64[^-]-%64[^-]-%d-%d",
				server, client, &mtu, &netmask) == 4) {

				server[64] = 0;
				client[64] = 0;
				if (tun_setip(client, server, netmask) == 0 &&
					tun_setmtu(mtu) == 0) {

					fprintf(stderr, "Server tunnel IP is %s\n", server);
					return 0;
				} else {
					errx(4, "Failed to set IP and MTU");
				}
			} else {
				fprintf(stderr, "Received bad handshake\n");
			}
		}

		fprintf(stderr, "Retrying login...\n");
	}
	warnx("couldn't login to server");
	return 1;
}

static int
handshake_raw_udp(int dns_fd, int seed)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int len;
	int got_addr;

	memset(&raw_serv, 0, sizeof(raw_serv));
	got_addr = 0;

	fprintf(stderr, "Testing raw UDP data to the server (skip with -r)");
	for (i=0; running && i<3 ;i++) {

		send_ip_request(dns_fd, userid);

		len = handshake_waitdns(dns_fd, in, sizeof(in), 'i', 'I', i+1);

		if (len == 5 && in[0] == 'I') {
			/* Received IPv4 address */
			struct sockaddr_in *raw4_serv = (struct sockaddr_in *) &raw_serv;
			raw4_serv->sin_family = AF_INET;
			memcpy(&raw4_serv->sin_addr, &in[1], sizeof(struct in_addr));
			raw4_serv->sin_port = htons(53);
			raw_serv_len = sizeof(struct sockaddr_in);
			got_addr = 1;
			break;
		}
		if (len == 17 && in[0] == 'I') {
			/* Received IPv6 address */
			struct sockaddr_in6 *raw6_serv = (struct sockaddr_in6 *) &raw_serv;
			raw6_serv->sin6_family = AF_INET6;
			memcpy(&raw6_serv->sin6_addr, &in[1], sizeof(struct in6_addr));
			raw6_serv->sin6_port = htons(53);
			raw_serv_len = sizeof(struct sockaddr_in6);
			got_addr = 1;
			break;
		}

		fprintf(stderr, ".");
		fflush(stderr);
	}
	fprintf(stderr, "\n");
	if (!running)
		return 0;

	if (!got_addr) {
		fprintf(stderr, "Failed to get raw server IP, will use DNS mode.\n");
		return 0;
	}
	fprintf(stderr, "Server is at %s, trying raw login: ", format_addr(&raw_serv, raw_serv_len));
	fflush(stderr);

	/* do login against port 53 on remote server
	 * based on the old seed. If reply received,
	 * switch to raw udp mode */
	for (i=0; running && i<4 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_raw_udp_login(dns_fd, userid, seed);

		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			/* recv() needed for windows, dont change to read() */
			len = recv(dns_fd, in, sizeof(in), 0);
			if (len >= (16 + RAW_HDR_LEN)) {
				char hash[16];
				login_calculate(hash, 16, password, seed - 1);
				if (memcmp(in, raw_header, RAW_HDR_IDENT_LEN) == 0
					&& RAW_HDR_GET_CMD(in) == RAW_HDR_CMD_LOGIN
					&& memcmp(&in[RAW_HDR_LEN], hash, sizeof(hash)) == 0) {

					fprintf(stderr, "OK\n");
					return 1;
				}
			}
		}
		fprintf(stderr, ".");
		fflush(stderr);
	}

	fprintf(stderr, "failed\n");
	return 0;
}

static int
handshake_upenctest(int dns_fd, char *s)
/* NOTE: *s may be max 59 chars; must start with "aA" for case-swap check
   Returns:
   -1: case swap, no need for any further test: error printed; or Ctrl-C
   0: not identical or error or timeout
   1: identical string returned
*/
{
	char in[4096];
	unsigned char *uin = (unsigned char *) in;
	unsigned char *us = (unsigned char *) s;
	int i;
	int read;
        int slen;

	slen = strlen(s);
	for (i=0; running && i<3 ;i++) {

		send_upenctest(dns_fd, s);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'z', 'Z', i+1);

		if (read == -2)
			return 0;	/* hard error */

		if (read > 0 && read < slen + 4)
			return 0;	/* reply too short (chars dropped) */

		if (read > 0) {
			int k;
			/* quick check if case swapped, to give informative error msg */
			if (in[4] == 'A') {
				fprintf(stderr, "DNS queries get changed to uppercase, keeping upstream codec Base32\n");
				return -1;
			}
			if (in[5] == 'a') {
				fprintf(stderr, "DNS queries get changed to lowercase, keeping upstream codec Base32\n");
				return -1;
			}

			for (k = 0; k < slen; k++) {
				if (in[k+4] != s[k]) {
					/* Definitely not reliable */
					if (in[k+4] >= ' ' && in[k+4] <= '~' &&
					    s[k] >= ' ' && s[k] <= '~') {
						fprintf(stderr, "DNS query char '%c' gets changed into '%c'\n",
							s[k], in[k+4]);
					} else {
						fprintf(stderr, "DNS query char 0x%02X gets changed into 0x%02X\n",
							(unsigned int) us[k],
							(unsigned int) uin[k+4]);
					}
					return 0;
				}
			}
			/* if still here, then all okay */
			return 1;
		}

		fprintf(stderr, "Retrying upstream codec test...\n");
	}

	if (!running)
		return -1;

	/* timeout */
	return 0;
}

static int
handshake_upenc_autodetect(int dns_fd)
/* Returns:
   0: keep Base32
   1: Base64 is okay
   2: Base64u is okay
   3: Base128 is okay
*/
{
	/* Note: max 59 chars, must start with "aA".
	   pat64: If 0129 work, assume 3-8 are okay too.

	   RFC1035 par 2.3.1 states that [A-Z0-9-] allowed, but only
	   [A-Z] as first, and [A-Z0-9] as last char _per label_.
	   Test by having '-' as last char.
	 */
        char *pat64="aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ+0129-";
        char *pat64u="aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ_0129-";
        char *pat128a="aA-Aaahhh-Drink-mal-ein-J\344germeister-";
        char *pat128b="aA-La-fl\373te-na\357ve-fran\347aise-est-retir\351-\340-Cr\350te";
        char *pat128c="aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";
        char *pat128d="aA0123456789\274\275\276\277"
		      "\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317";
        char *pat128e="aA"
		      "\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337"
		      "\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357"
		      "\360\361\362\363\364\365\366\367\370\371\372\373\374\375";
	int res;

	/* Try Base128, starting very gently to not draw attention */
	while (1) {
		res = handshake_upenctest(dns_fd, pat128a);
		if (res < 0) {
			/* DNS swaps case, msg already printed; or Ctrl-C */
			return 0;
		} else if (res == 0) {
			/* Probably not okay, skip Base128 entirely */
			break;
		}

		res = handshake_upenctest(dns_fd, pat128b);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		/* if this works, we can test the real stuff */

		res = handshake_upenctest(dns_fd, pat128c);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		res = handshake_upenctest(dns_fd, pat128d);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		res = handshake_upenctest(dns_fd, pat128e);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		/* if still here, then base128 works completely */
		return 3;
	}

	/* Try Base64 (with plus sign) */
	res = handshake_upenctest(dns_fd, pat64);
	if (res < 0) {
		/* DNS swaps case, msg already printed; or Ctrl-C */
		return 0;
	} else if (res > 0) {
		/* All okay, Base64 msg will be printed later */
		return 1;
	}

	/* Try Base64u (with _u_nderscore) */
	res = handshake_upenctest(dns_fd, pat64u);
	if (res < 0) {
		/* DNS swaps case, msg already printed; or Ctrl-C */
		return 0;
	} else if (res > 0) {
		/* All okay, Base64u msg will be printed later */
		return 2;
	}

	/* if here, then nonthing worked */
	fprintf(stderr, "Keeping upstream codec Base32\n");
	return 0;
}

static int
handshake_downenctest(int dns_fd, char trycodec)
/* Returns:
   0: not identical or error or timeout
   1: identical string returned
*/
{
	char in[4096];
	int i;
	int read;
	char *s = DOWNCODECCHECK1;
        int slen = DOWNCODECCHECK1_LEN;

	for (i=0; running && i<3 ;i++) {

		send_downenctest(dns_fd, trycodec, 1, NULL, 0);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', 'Y', i+1);

		if (read == -2)
			return 0;	/* hard error */

		if (read > 0 && read != slen)
			return 0;	/* reply incorrect = unreliable */

		if (read > 0) {
			int k;
			for (k = 0; k < slen; k++) {
				if (in[k] != s[k]) {
					/* Definitely not reliable */
					return 0;
				}
			}
			/* if still here, then all okay */
			return 1;
		}

		fprintf(stderr, "Retrying downstream codec test...\n");
	}

	/* timeout */
	return 0;
}

static char
handshake_downenc_autodetect(int dns_fd)
/* Returns codec char (or ' ' if no advanced codec works) */
{
	int base64ok = 0;
	int base64uok = 0;
	int base128ok = 0;

	if (do_qtype == T_NULL || do_qtype == T_PRIVATE) {
		/* no other choice than raw */
		fprintf(stderr, "No alternative downstream codec available, using default (Raw)\n");
		return ' ';
	}

	fprintf(stderr, "Autodetecting downstream codec (use -O to override)\n");

	/* Try Base64 */
	if (handshake_downenctest(dns_fd, 'S'))
		base64ok = 1;
	else if (running && handshake_downenctest(dns_fd, 'U'))
		base64uok = 1;

	/* Try Base128 only if 64 gives us some perspective */
	if (running && (base64ok || base64uok)) {
		if (handshake_downenctest(dns_fd, 'V'))
			base128ok = 1;
	}

	/* If 128 works, then TXT may give us Raw as well */
	if (running && (base128ok && do_qtype == T_TXT)) {
		if (handshake_downenctest(dns_fd, 'R'))
			return 'R';
	}

	if (!running)
		return ' ';

	if (base128ok)
		return 'V';
	if (base64ok)
		return 'S';
	if (base64uok)
		return 'U';

	fprintf(stderr, "No advanced downstream codecs seem to work, using default (Base32)\n");
	return ' ';
}

static int
handshake_qtypetest(int dns_fd, int timeout)
/* Returns:
   0: doesn't work with this timeout
   1: works properly
*/
{
	char in[4096];
	int read;
	char *s = DOWNCODECCHECK1;
        int slen = DOWNCODECCHECK1_LEN;
	int trycodec;
	int k;

	if (do_qtype == T_NULL || do_qtype == T_PRIVATE)
		trycodec = 'R';
	else
		trycodec = 'T';

	/* We could use 'Z' bouncing here, but 'Y' also tests that 0-255
	   byte values can be returned, which is needed for NULL/PRIVATE
	   to work. */

	send_downenctest(dns_fd, trycodec, 1, NULL, 0);

	read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', 'Y', timeout);

	if (read != slen)
		return 0;	/* incorrect */

	for (k = 0; k < slen; k++) {
		if (in[k] != s[k]) {
			/* corrupted */
			return 0;
		}
	}

	/* if still here, then all okay */
	return 1;
}

static int
handshake_qtype_numcvt(int num)
{
	switch (num) {
	case 0:	return T_NULL;
	case 1:	return T_PRIVATE;
	case 2:	return T_TXT;
	case 3:	return T_SRV;
	case 4:	return T_MX;
	case 5:	return T_CNAME;
	case 6:	return T_A;
	}
	return T_UNSET;
}

static int
handshake_qtype_autodetect(int dns_fd)
/* Returns:
   0: okay, do_qtype set
   1: problem, program exit
*/
{
	int highestworking = 100;
	int timeout;
	int qtypenum;

	fprintf(stderr, "Autodetecting DNS query type (use -T to override)");
	fflush(stderr);

	/* Method: try all "interesting" qtypes with a 1-sec timeout, then try
	   all "still-interesting" qtypes with a 2-sec timeout, etc.
	   "Interesting" means: qtypes that (are expected to) have higher
	   bandwidth than what we know is working already (highestworking).

	   Note that DNS relays may not immediately resolve the first (NULL)
	   query in 1 sec, due to long recursive lookups, so we keep trying
	   to see if things will start working after a while.
	 */

	for (timeout = 1; running && timeout <= 3; timeout++) {
		for (qtypenum = 0; running && qtypenum < highestworking; qtypenum++) {
			do_qtype = handshake_qtype_numcvt(qtypenum);
			if (do_qtype == T_UNSET)
				break;	/* this round finished */

			fprintf(stderr, ".");
			fflush(stderr);

			if (handshake_qtypetest(dns_fd, timeout)) {
				/* okay */
				highestworking = qtypenum;
				if (debug >= 1)
					fprintf(stderr, " Type %s timeout %d works\n", client_get_qtype(), timeout);
				break;
				/* try others with longer timeout */
			}
			/* else: try next qtype with same timeout */
		}
		if (highestworking == 0)
			/* good, we have NULL; abort immediately */
			break;
	}

	fprintf(stderr, "\n");

	if (!running) {
		warnx("Stopped while autodetecting DNS query type (try setting manually with -T)");
		return 1;  /* problem */
	}

	/* finished */
	do_qtype = handshake_qtype_numcvt(highestworking);

	if (do_qtype == T_UNSET) {
		/* also catches highestworking still 100 */
		warnx("No suitable DNS query type found. Are you connected to a network?");
		warnx("If you expect very long roundtrip delays, use -T explicitly.");
		warnx("(Also, connecting to an \"ancient\" version of iodined won't work.)");
		return 1;  /* problem */
	}

	/* "using qtype" message printed in handshake function */
	return 0;  /* okay */
}

static int
handshake_edns0_check(int dns_fd)
/* Returns:
   0: EDNS0 not supported; or Ctrl-C
   1: EDNS0 works
*/
{
	char in[4096];
	int i;
	int read;
	char *s = DOWNCODECCHECK1;
        int slen = DOWNCODECCHECK1_LEN;
	char trycodec;

	if (do_qtype == T_NULL)
		trycodec = 'R';
	else
		trycodec = 'T';

	for (i=0; running && i<3 ;i++) {

		send_downenctest(dns_fd, trycodec, 1, NULL, 0);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', 'Y', i+1);

		if (read == -2)
			return 0;	/* hard error */

		if (read > 0 && read != slen)
			return 0;	/* reply incorrect = unreliable */

		if (read > 0) {
			int k;
			for (k = 0; k < slen; k++) {
				if (in[k] != s[k]) {
					/* Definitely not reliable */
					return 0;
				}
			}
			/* if still here, then all okay */
			return 1;
		}

		fprintf(stderr, "Retrying EDNS0 support test...\n");
	}

	/* timeout or Ctrl-C */
	return 0;
}

static void
handshake_switch_codec(int dns_fd, int bits)
{
	char in[4096];
	int i;
	int read;
	struct encoder *tempenc;

	if (bits == 5)
		tempenc = get_base32_encoder();
	else if (bits == 6)
		tempenc = get_base64_encoder();
	else if (bits == 26)	/* "2nd" 6 bits per byte, with underscore */
		tempenc = get_base64u_encoder();
	else if (bits == 7)
		tempenc = get_base128_encoder();
	else return;

	fprintf(stderr, "Switching upstream to codec %s\n", tempenc->name);

	for (i=0; running && i<5 ;i++) {

		send_codec_switch(dns_fd, userid, bits);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 's', 'S', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				fprintf(stderr, "Server got bad message length.\n");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				fprintf(stderr, "Server rejected the selected codec.\n");
				goto codec_revert;
			}
			in[read] = 0; /* zero terminate */
			fprintf(stderr, "Server switched upstream to codec %s\n", in);
			dataenc = tempenc;

			/* Update outgoing buffer max (decoded) fragsize */
			outbuf->maxfraglen = get_raw_length_from_dns(hostname_maxlen - UPSTREAM_HDR, dataenc, topdomain);
			return;
		}

		fprintf(stderr, "Retrying codec switch...\n");
	}
	if (!running)
		return;

	fprintf(stderr, "No reply from server on codec switch.\n");

codec_revert:
	fprintf(stderr, "Falling back to upstream codec %s\n", dataenc->name);
}

static void
handshake_switch_downenc(int dns_fd)
{
	char in[4096];
	int i;
	int read;
	char *dname;

	dname = "Base32";
	if (downenc == 'S')
		dname = "Base64";
	else if (downenc == 'U')
		dname = "Base64u";
	else if (downenc == 'V')
		dname = "Base128";
	else if (downenc == 'R')
		dname = "Raw";

	fprintf(stderr, "Switching downstream to codec %s\n", dname);
	for (i=0; running && i<5 ;i++) {

		send_downenc_switch(dns_fd, userid);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', 'O', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				fprintf(stderr, "Server got bad message length.\n");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				fprintf(stderr, "Server rejected the selected codec.\n");
				goto codec_revert;
			}
			in[read] = 0; /* zero terminate */
			fprintf(stderr, "Server switched downstream to codec %s\n", in);
			return;
		}

		fprintf(stderr, "Retrying codec switch...\n");
	}
	if (!running)
		return;

	fprintf(stderr, "No reply from server on codec switch.\n");

codec_revert:
	fprintf(stderr, "Falling back to downstream codec Base32\n");
}

static void
handshake_try_lazy(int dns_fd)
{
	char in[4096];
	int i;
	int read;

	fprintf(stderr, "Switching to lazy mode for low-latency\n");
	for (i=0; running && i<5; i++) {

		send_lazy_switch(dns_fd, userid);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', 'O', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				fprintf(stderr, "Server got bad message length.\n");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				fprintf(stderr, "Server rejected lazy mode.\n");
				goto codec_revert;
			} else if (strncmp("Lazy", in, 4) == 0) {
				fprintf(stderr, "Server switched to lazy mode\n");
				lazymode = 1;
				return;
			}
		}

		fprintf(stderr, "Retrying lazy mode switch...\n");
	}
	if (!running)
		return;

	fprintf(stderr, "No reply from server on lazy switch.\n");

codec_revert:
	fprintf(stderr, "Falling back to legacy mode\n");
	lazymode = 0;
	selecttimeout = 1;
}

static void
handshake_lazyoff(int dns_fd)
/* Used in the middle of data transfer, timing is different and no error msgs */
{
	char in[4096];
	int i;
	int read;

	for (i=0; running && i<5; i++) {

		send_lazy_switch(dns_fd, userid);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', 'O', 1);

		if (read == 9 && strncmp("Immediate", in, 9) == 0) {
			warnx("Server switched back to legacy mode.");
			lazymode = 0;
			selecttimeout = 1;
			return;
		}
	}
	if (!running)
		return;

	warnx("No reply from server on legacy mode switch.");
}

static int
fragsize_check(char *in, int read, int proposed_fragsize, int *max_fragsize)
/* Returns: 0: keep checking, 1: break loop (either okay or definitely wrong) */
{
	int acked_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff);
	int okay;
	int i;
	unsigned int v;

	if (read >= 5 && strncmp("BADIP", in, 5) == 0) {
		fprintf(stderr, "got BADIP (Try iodined -c)..\n");
		fflush(stderr);
		return 0;		/* maybe temporary error */
	}

	if (acked_fragsize != proposed_fragsize) {
		/*
		 * got ack for wrong fragsize, maybe late response for
		 * earlier query, or ack corrupted
		 */
		return 0;
	}

	if (read != proposed_fragsize) {
		/*
		 * correctly acked fragsize but read too little (or too
		 * much): this fragsize is definitely not reliable
		 */
		return 1;
	}

	/* here: read == proposed_fragsize == acked_fragsize */

	/* test: */
	/* in[123] = 123; */

	if ((in[2] & 0xff) != 107) {
		warnx("\ncorruption at byte 2, this won't work. Try -O Base32, or other -T options.");
		*max_fragsize = -1;
		return 1;
	}

	/* Check for corruption */
	okay = 1;
	v = in[3] & 0xff;

	for (i = 3; i < read; i++, v = (v + 107) & 0xff)
		if ((in[i] & 0xff) != v) {
			okay = 0;
			break;
		}

	if (okay) {
		fprintf(stderr, "%d ok.. ", acked_fragsize);
		fflush(stderr);
		*max_fragsize = acked_fragsize;
		return 1;
	} else {
		if (downenc != ' ' && downenc != 'T') {
			fprintf(stderr, "%d corrupted at %d.. (Try -O Base32)\n", acked_fragsize, i);
		} else {
			fprintf(stderr, "%d corrupted at %d.. ", acked_fragsize, i);
		}
		fflush(stderr);
		return 1;
	}

	/* notreached */
	return 1;
}


static int
handshake_autoprobe_fragsize(int dns_fd)
{
	char in[MAX_FRAGSIZE];
	int i;
	int read;
	int proposed_fragsize = 768;
	int range = 768;
	int max_fragsize;

	max_fragsize = 0;
	fprintf(stderr, "Autoprobing max downstream fragment size... (skip with -m fragsize)");
	while (running && range > 0 && (range >= 8 || max_fragsize < 300)) {
		/* stop the slow probing early when we have enough bytes anyway */
		for (i=0; running && i<3 ;i++) {

			send_fragsize_probe(dns_fd, proposed_fragsize);

			read = handshake_waitdns(dns_fd, in, sizeof(in), 'r', 'R', 1);

			if (read > 0) {
				/* We got a reply */
				if (fragsize_check(in, read, proposed_fragsize, &max_fragsize) == 1)
					break;
			}

			fprintf(stderr, ".");
			fflush(stderr);
		}
		if (max_fragsize < 0)
			break;

		range >>= 1;
		if (max_fragsize == proposed_fragsize) {
			/* Try bigger */
			proposed_fragsize += range;
		} else {
			/* Try smaller */
			fprintf(stderr, "%d not ok.. ", proposed_fragsize);
			fflush(stderr);
			proposed_fragsize -= range;
		}
	}
	if (!running) {
		warnx("\nstopped while autodetecting fragment size (Try setting manually with -m)");
		return 0;
	}
	if (max_fragsize <= 6) {
		/* Tried all the way down to 2 and found no good size.
		   But we _did_ do all handshake before this, so there must
		   be some workable connection. */
		warnx("\nfound no accepted fragment size.");
		warnx("try setting -M to 200 or lower, or try other -T or -O options.");
		return 0;
	}
	/* data header adds 6 bytes */
	fprintf(stderr, "will use %d-6=%d\n", max_fragsize, max_fragsize - 6);

	/* need 1200 / 16frags = 75 bytes fragsize */
	if (max_fragsize < 82) {
		fprintf(stderr, "Note: this probably won't work well.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	} else if (max_fragsize < 202 &&
	    (do_qtype == T_NULL || do_qtype == T_PRIVATE || do_qtype == T_TXT ||
	     do_qtype == T_SRV || do_qtype == T_MX)) {
		fprintf(stderr, "Note: this isn't very much.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	}

	return max_fragsize - 2;
}

static void
handshake_set_fragsize(int dns_fd, int fragsize)
{
	char in[4096];
	int i;
	int read;

	fprintf(stderr, "Setting downstream fragment size to max %d...\n", fragsize);
	for (i=0; running && i<5 ;i++) {

		send_set_downstream_fragsize(dns_fd, fragsize);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'n', 'N', i+1);

		if (read > 0) {

			if (strncmp("BADFRAG", in, 7) == 0) {
				fprintf(stderr, "Server rejected fragsize. Keeping default.\n");
				return;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				return;
			}

			/* The server returns the accepted fragsize:
			accepted_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff) */
			return;
		}

		fprintf(stderr, "Retrying set fragsize...\n");
	}
	if (!running)
		return;

	fprintf(stderr, "No reply from server when setting fragsize. Keeping default.\n");
}

int
client_handshake(int dns_fd, int raw_mode, int autodetect_frag_size, int fragsize)
{
	int seed;
	int upcodec;
	int r;

	dnsc_use_edns0 = 0;

	/* qtype message printed in handshake function */
	if (do_qtype == T_UNSET) {
		r = handshake_qtype_autodetect(dns_fd);
		if (r) {
			return r;
		}
	}

	fprintf(stderr, "Using DNS type %s queries\n", client_get_qtype());

	r = handshake_version(dns_fd, &seed);
	if (r) {
		return r;
	}

	r = handshake_login(dns_fd, seed);
	if (r) {
		return r;
	}

	if (raw_mode && handshake_raw_udp(dns_fd, seed)) {
		/* TODO: fragsize based on max raw packet size */
		conn = CONN_RAW_UDP;
		selecttimeout = 20;
	} else {
		if (raw_mode == 0) {
			fprintf(stderr, "Skipping raw mode\n");
		}

		dnsc_use_edns0 = 1;
		if (handshake_edns0_check(dns_fd) && running) {
			fprintf(stderr, "Using EDNS0 extension\n");
		} else if (!running) {
			return -1;
		} else {
			fprintf(stderr, "DNS relay does not support EDNS0 extension\n");
			dnsc_use_edns0 = 0;
		}

		upcodec = handshake_upenc_autodetect(dns_fd);
		if (!running)
			return -1;

		if (upcodec == 1) { /* Base64 */
			handshake_switch_codec(dns_fd, 6);
		} else if (upcodec == 2) { /* Base64u */
			handshake_switch_codec(dns_fd, 26);
		} else if (upcodec == 3) { /* Base128 */
			handshake_switch_codec(dns_fd, 7);
		}
		if (!running)
			return -1;

		if (downenc == ' ') {
			downenc = handshake_downenc_autodetect(dns_fd);
		}
		if (!running)
			return -1;

		if (downenc != ' ') {
			handshake_switch_downenc(dns_fd);
		}
		if (!running)
			return -1;

		if (lazymode) {
			handshake_try_lazy(dns_fd);
		}
		if (!running)
			return -1;

		if (autodetect_frag_size) {
			fragsize = handshake_autoprobe_fragsize(dns_fd);
			if (fragsize > MAX_FRAGSIZE) {
				/* This is very unlikely except perhaps over LAN */
				fprintf(stderr, "Can transfer fragsize of %d, however iodine has been compiled with MAX_FRAGSIZE = %d. To fully utilize this connection, please recompile iodine/iodined.", fragsize, MAX_FRAGSIZE);
				fragsize = MAX_FRAGSIZE;
			}
			if (!fragsize) {
				return 1;
			}
		}

		handshake_set_fragsize(dns_fd, fragsize);
		if (!running)
			return -1;
	}

	return 0;
}

