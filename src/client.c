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
#include <fcntl.h>
#include <zlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

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
#include "util.h"
#include "client.h"

int
client_set_qtype(char *qtype)
{
	if (!strcasecmp(qtype, "NULL"))
      		this.do_qtype = T_NULL;
	else if (!strcasecmp(qtype, "PRIVATE"))
		this.do_qtype = T_PRIVATE;
	else if (!strcasecmp(qtype, "CNAME"))
		this.do_qtype = T_CNAME;
	else if (!strcasecmp(qtype, "A"))
		this.do_qtype = T_A;
	else if (!strcasecmp(qtype, "MX"))
		this.do_qtype = T_MX;
	else if (!strcasecmp(qtype, "SRV"))
		this.do_qtype = T_SRV;
	else if (!strcasecmp(qtype, "TXT"))
		this.do_qtype = T_TXT;
	return (this.do_qtype == T_UNSET);
}

char *
client_get_qtype()
{
	char *c = "UNDEFINED";

	if (this.do_qtype == T_NULL)		c = "NULL";
	else if (this.do_qtype == T_PRIVATE)	c = "PRIVATE";
	else if (this.do_qtype == T_CNAME)	c = "CNAME";
	else if (this.do_qtype == T_A)	c = "A";
	else if (this.do_qtype == T_MX)	c = "MX";
	else if (this.do_qtype == T_SRV)	c = "SRV";
	else if (this.do_qtype == T_TXT)	c = "TXT";

	return c;
}

char
parse_encoding(char *encoding)
{
	char enc_char = 0;
	if (!strcasecmp(encoding, "base32"))
		enc_char = 'T';
	else if (!strcasecmp(encoding, "base64"))
		enc_char = 'S';
	else if (!strcasecmp(encoding, "base64u"))
		enc_char = 'U';
	else if (!strcasecmp(encoding, "base128"))
		enc_char = 'V';
	else if (!strcasecmp(encoding, "raw"))
		enc_char = 'R';
	return enc_char;
}

void
client_set_hostname_maxlen(size_t i)
{
	if (i <= 0xFF && i != this.hostname_maxlen) {
		this.hostname_maxlen = i;
		this.maxfragsize_up = get_raw_length_from_dns(this.hostname_maxlen - UPSTREAM_HDR, this.dataenc, this.topdomain);
		if (this.outbuf)
			this.outbuf->maxfraglen = this.maxfragsize_up;
	}
}

const char *
client_get_raw_addr()
{
	return format_addr(&this.raw_serv, this.raw_serv_len);
}

void
client_rotate_nameserver()
{
	this.current_nameserver ++;
	if (this.current_nameserver >= this.nameserv_addrs_len)
		this.current_nameserver = 0;
}

void
immediate_mode_defaults()
{
	this.send_interval_ms = MIN(this.rtt_total_ms / this.num_immediate, 1000);
	this.max_timeout_ms = MAX(4 * this.rtt_total_ms / this.num_immediate, 5000);
	this.server_timeout_ms = 0;
}

/* Client-side query tracking for lazy mode */

/* Handy macro for printing this.stats with messages */
#ifdef DEBUG_BUILD
#define QTRACK_DEBUG(l, ...) \
	if (this.debug >= l) {\
		TIMEPRINT("[QTRACK (%" L "u/%" L "u), ? %" L "u, TO %" L "u, S %" L "u/%" L "u] ", this.num_pending, PENDING_QUERIES_LENGTH, \
				this.num_untracked, this.num_timeouts, window_sending(this.outbuf, NULL), this.outbuf->numitems); \
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
	}
#else
#define QTRACK_DEBUG(...)
#endif

static int
update_server_timeout(int handshake)
/* Calculate server timeout based on average RTT, send ping "handshake" to set
 * if handshake sent, return query ID */
{
	time_t rtt_ms;
	static size_t num_rtt_timeouts = 0;

	/* Get average RTT in ms */
	rtt_ms = (this.num_immediate == 0) ? 1 : this.rtt_total_ms / this.num_immediate;
	if (rtt_ms >= this.max_timeout_ms && this.num_immediate > 5) {
		num_rtt_timeouts++;
		if (num_rtt_timeouts < 3) {
			fprintf(stderr, "Target interval of %ld ms less than average round-trip of "
					"%ld ms! Try increasing interval with -I.\n", this.max_timeout_ms, rtt_ms);
		} else {
			/* bump up target timeout */
			this.max_timeout_ms = rtt_ms + 1000;
			this.server_timeout_ms = 1000;
			if (this.lazymode)
				fprintf(stderr, "Adjusting server timeout to %ld ms, target interval %ld ms. Try -I%.1f next time with this network.\n",
						this.server_timeout_ms, this.max_timeout_ms, this.max_timeout_ms / 1000.0);

			num_rtt_timeouts = 0;
		}
	} else {
		/* Set server timeout based on target interval and RTT */
		this.server_timeout_ms = this.max_timeout_ms - rtt_ms;
		if (this.server_timeout_ms <= 0) {
			this.server_timeout_ms = 0;
			fprintf(stderr, "Setting server timeout to 0 ms: if this continues try disabling lazy mode. (-L0)\n");
		}
	}

	/* update up/down window timeouts to something reasonable */
	this.downstream_timeout_ms = rtt_ms * 2;
	this.outbuf->timeout = ms_to_timeval(this.downstream_timeout_ms);

	if (handshake) {
		/* Send ping handshake to set server timeout */
		return send_ping(1, -1, 1, 0);
	}
	return -1;
}

static void
check_pending_queries()
/* Updates pending queries list */
{
	this.num_pending = 0;
	struct timeval now, qtimeout, max_timeout;
	gettimeofday(&now, NULL);
	/* Max timeout for queries is max interval + 1 second extra */
	max_timeout = ms_to_timeval(this.max_timeout_ms + 1000);
	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (this.pending_queries[i].time.tv_sec > 0 && this.pending_queries[i].id >= 0) {
			timeradd(&this.pending_queries[i].time, &max_timeout, &qtimeout);
			if (!timercmp(&qtimeout, &now, >)) {
				/* Query has timed out, clear timestamp but leave ID */
				this.pending_queries[i].time.tv_sec = 0;
				this.num_timeouts++;
			}
			this.num_pending++;
		}
	}
}

static void
query_sent_now(int id)
{
	int i = 0, found = 0;
	if (!this.pending_queries)
		return;

	if (id < 0 || id > 65535)
		return;

	/* Replace any empty queries first, then timed out ones if necessary */
	for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (this.pending_queries[i].id < 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
			if (this.pending_queries[i].time.tv_sec == 0) {
				found = 1;
				break;
			}
		}
	}
	/* if no slots found after both checks */
	if (!found) {
		QTRACK_DEBUG(1, "Buffer full! Failed to add id %d.", id);
	} else {
		/* Add query into found location */
		this.pending_queries[i].id = id;
		gettimeofday(&this.pending_queries[i].time, NULL);
		this.num_pending ++;
		QTRACK_DEBUG(4, "Adding query id %d into this.pending_queries[%d]", id, i);
		id = -1;
	}
}

static void
got_response(int id, int immediate, int fail)
{
	struct timeval now, rtt;
	time_t rtt_ms;
	gettimeofday(&now, NULL);

	QTRACK_DEBUG(4, "Got answer id %d (%s)%s", id, immediate ? "immediate" : "lazy",
		fail ? ", FAIL" : "");

	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (id >= 0 && this.pending_queries[i].id == id) {
			if (this.num_pending > 0)
				this.num_pending--;

			if (this.pending_queries[i].time.tv_sec == 0) {
				if (this.num_timeouts > 0) {
					/* If query has timed out but is still stored - just in case
					 * ID is kept on timeout in check_pending_queries() */
					this.num_timeouts --;
					immediate = 0;
				} else {
					/* query is empty */
					continue;
				}
			}

			if (immediate || this.debug >= 4) {
				timersub(&now, &this.pending_queries[i].time, &rtt);
				rtt_ms = timeval_to_ms(&rtt);
			}

			QTRACK_DEBUG(5, "    found answer id %d in pending queries[%d], %ld ms old", id, i, rtt_ms);

			if (immediate) {
				/* If this was an immediate response we can use it to get
				   more detailed connection statistics like RTT.
				   This lets us determine and adjust server lazy response time
				   during the session much more accurately. */
				this.rtt_total_ms += rtt_ms;
				this.num_immediate++;

				if (this.autodetect_server_timeout && this.lazymode)
					update_server_timeout(0);
			}

			/* Remove query info from buffer to mark it as answered */
			id = -1;
			this.pending_queries[i].id = -1;
			this.pending_queries[i].time.tv_sec = 0;
			break;
		}
	}
	if (id > 0) {
		QTRACK_DEBUG(4, "    got untracked response to id %d.", id);
		this.num_untracked++;
	}
}

static int
send_query(uint8_t *hostname)
/* Returns DNS ID of sent query */
{
	uint8_t packet[4096];
	struct query q;
	size_t len;

	DEBUG(3, "TX: pkt len %" L "u: hostname '%s'", strlen((char *)hostname), hostname);

	this.chunkid += 7727;
	if (this.chunkid == 0)
		/* 0 is used as "no-query" in iodined.c */
		this.chunkid = rand() & 0xFF;

	q.id = this.chunkid;
	q.type = this.do_qtype;

	len = dns_encode((char *)packet, sizeof(packet), &q, QR_QUERY, (char *)hostname, strlen((char *)hostname));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return -1;
	}

	DEBUG(4, "  Sendquery: id %5d name[0] '%c'", q.id, hostname[0]);

	sendto(this.dns_fd, packet, len, 0, (struct sockaddr*) &this.nameserv_addrs[this.current_nameserver],
			sizeof(struct sockaddr_storage));

	client_rotate_nameserver();

	/* There are DNS relays that time out quickly but don't send anything
	   back on timeout.
	   And there are relays where, in lazy mode, our new query apparently
	   _replaces_ our previous query, and we get no answers at all in
	   lazy mode while legacy immediate-ping-pong works just fine.
	   In this case, the up/down windowsizes may need to be set to 1 for there
	   to only ever be one query pending.
	   Here we detect and fix these situations.
	   (Can't very well do this anywhere else; this is the only place
	   we'll reliably get to in such situations.)
	   Note: only start fixing up connection AFTER we have this.connected
	         and if user hasn't specified server timeout/window timeout etc. */

	this.num_sent++;
	if (this.send_query_sendcnt > 0 && this.send_query_sendcnt < 100 &&
		this.lazymode && this.connected && this.autodetect_server_timeout) {
		this.send_query_sendcnt++;

		if ((this.send_query_sendcnt > this.windowsize_down && this.send_query_recvcnt <= 0) ||
		    (this.send_query_sendcnt > 2 * this.windowsize_down && 4 * this.send_query_recvcnt < this.send_query_sendcnt)) {
			if (this.max_timeout_ms > 500) {
				this.max_timeout_ms -= 200;
				double secs = (double) this.max_timeout_ms / 1000.0;
				fprintf(stderr, "Receiving too few answers. Setting target timeout to %.1fs (-I%.1f)\n", secs, secs);

				/* restart counting */
				this.send_query_sendcnt = 0;
				this.send_query_recvcnt = 0;

			} else if (this.lazymode) {
				fprintf(stderr, "Receiving too few answers. Will try to switch lazy mode off, but that may not"
					" always work any more. Start with -L0 next time on this network.\n");
				this.lazymode = 0;
				this.server_timeout_ms = 0;
			}
			update_server_timeout(1);
		}
	}
	return q.id;
}

static void
send_raw(uint8_t *buf, size_t buflen, int cmd)
{
	char packet[4096];
	int len;

	len = MIN(sizeof(packet) - RAW_HDR_LEN, buflen);

	memcpy(packet, raw_header, RAW_HDR_LEN);
	if (len) {
		memcpy(&packet[RAW_HDR_LEN], buf, len);
	}

	len += RAW_HDR_LEN;
	packet[RAW_HDR_CMD] = (cmd & 0xF0) | (this.userid & 0x0F);

	sendto(this.dns_fd, packet, len, 0, (struct sockaddr*)&this.raw_serv, sizeof(this.raw_serv));
}

static void
send_raw_data(uint8_t *data, size_t datalen)
{
	send_raw(data, datalen, RAW_HDR_CMD_DATA);
}


static int
send_packet(char cmd, const uint8_t *data, const size_t datalen)
/* Base32 encodes data and sends as single DNS query
 * cmd becomes first byte of query, followed by hex userid, encoded
 * data and 3 bytes base32 encoded CMC
 * Returns ID of sent query */
{
	uint8_t buf[512], data_with_cmc[datalen + 2];

	if (data)
		memcpy(data_with_cmc, data, datalen);
	*(uint16_t *) (data_with_cmc + datalen) = this.rand_seed;
	this.rand_seed++;

	buf[0] = cmd;
	buf[1] = this.userid_char;

	build_hostname(buf, sizeof(buf), data_with_cmc, datalen + 2,
				   this.topdomain, b32, this.hostname_maxlen, 2);

	return send_query(buf);
}

int
send_ping(int ping_response, int ack, int set_timeout, int disconnect)
{
	this.num_pings++;
	if (this.conn == CONN_DNS_NULL) {
		uint8_t data[12];
		int id;

		/* Build ping header (see doc/proto_xxxxxxxx.txt) */
		data[0] = ack & 0xFF;

		if (this.outbuf && this.inbuf) {
			data[1] = this.outbuf->windowsize & 0xff;	/* Upstream window size */
			data[2] = this.inbuf->windowsize & 0xff;		/* Downstream window size */
			data[3] = this.outbuf->start_seq_id & 0xff;	/* Upstream window start */
			data[4] = this.inbuf->start_seq_id & 0xff;	/* Downstream window start */
		}

		*(uint16_t *) (data + 5) = htons(this.server_timeout_ms);
		*(uint16_t *) (data + 7) = htons(this.downstream_timeout_ms);

		/* update server frag/lazy timeout, ack flag, respond with ping flag */
		data[9] = ((disconnect & 1) << 5) | ((set_timeout & 1) << 4) |
			((set_timeout & 1) << 3) | ((ack < 0 ? 0 : 1) << 2) | (ping_response & 1);
		data[10] = (this.rand_seed >> 8) & 0xff;
		data[11] = (this.rand_seed >> 0) & 0xff;
		this.rand_seed += 1;

		DEBUG(3, " SEND PING: %srespond %d, ack %d, %s(server %ld ms, downfrag %ld ms), flags %02X, wup %u, wdn %u",
				disconnect ? "DISCONNECT! " : "", ping_response, ack, set_timeout ? "SET " : "",
				this.server_timeout_ms, this.downstream_timeout_ms,
				data[8], this.outbuf->windowsize, this.inbuf->windowsize);

		id = send_packet('p', data, sizeof(data));

		/* Log query ID as being sent now */
		query_sent_now(id);
		return id;
	} else {
		send_raw(NULL, 0, RAW_HDR_CMD_PING);
		return -1;
	}
}

static void
send_next_frag()
/* Sends next available fragment of data from the outgoing window buffer */
{
	static uint8_t buf[MAX_FRAGSIZE], hdr[5];
	int code, id;
	static int datacmc = 0;
	static char *datacmcchars = "abcdefghijklmnopqrstuvwxyz0123456789";
	fragment *f;
	size_t buflen;

	/* Get next fragment to send */
	f = window_get_next_sending_fragment(this.outbuf, &this.next_downstream_ack);
	if (!f) {
		if (this.outbuf->numitems > 0) {
			/* There is stuff to send but we're out of sync, so send a ping
			 * to get things back in order and keep the packets flowing */
			send_ping(1, this.next_downstream_ack, 1, 0);
			this.next_downstream_ack = -1;
			window_tick(this.outbuf);
		}
		return; /* nothing to send */
	}

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */
	buf[0] = this.userid_char;		/* First byte is hex this.userid */

	buf[1] = datacmcchars[datacmc]; /* Second byte is data-CMC */

	/* Next 3 bytes is seq ID, downstream ACK and flags */
	code = ((f->ack_other < 0 ? 0 : 1) << 3) | (f->compressed << 2)
			| (f->start << 1) | f->end;

	hdr[0] = f->seqID & 0xFF;
	hdr[1] = f->ack_other & 0xFF;
	hdr[2] = code << 4; /* Flags are in upper 4 bits - lower 4 unused */

	buflen = sizeof(buf) - 1;
	/* Encode 3 bytes data into 2 bytes after buf */
	b32->encode(buf + 2, &buflen, hdr, 3);

	/* Encode data into buf after header (6 = user + CMC + 4 bytes header) */
	build_hostname(buf, sizeof(buf), f->data, f->len, this.topdomain,
				   this.dataenc, this.hostname_maxlen, 6);

	datacmc++;
	if (datacmc >= 36)
		datacmc = 0;

	DEBUG(3, " SEND DATA: seq %d, ack %d, len %" L "u, s%d e%d c%d flags %1X",
			f->seqID, f->ack_other, f->len, f->start, f->end, f->compressed, hdr[2] >> 4);

	id = send_query(buf);
	/* Log query ID as being sent now */
	query_sent_now(id);

	window_tick(this.outbuf);
	this.num_frags_sent++;
}

static void
write_dns_error(struct query *q, int ignore_some_errors)
/* This is called from:
   1. handshake_waitdns() when already checked that reply fits to our
      latest query.
   2. tunnel_dns() when already checked that reply is for a ping or data
      packet, but possibly timed out.
   Errors should not be ignored, but too many can be annoying.
*/
{
	static size_t errorcounts[24] = {0};
	if (!q) return;

	if (q->rcode < 24) {
		errorcounts[q->rcode]++;
		if (errorcounts[q->rcode] == 20) {
			warnx("Too many error replies, not logging any more.");
			return;
		} else if (errorcounts[q->rcode] > 20) {
			return;
		}
	}

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
read_dns_withq(uint8_t *buf, size_t buflen, struct query *q)
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
	if ((r = recvfrom(this.dns_fd, data, sizeof(data), 0,
			  (struct sockaddr*)&from, &addrlen)) < 0) {
		warn("recvfrom");
		return -1;
	}

	if (this.conn == CONN_DNS_NULL) {
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

		DEBUG(2, "RX: id %5d name[0]='%c'", q->id, q->name[0]);

		return rv;
	} else { /* CONN_RAW_UDP */
		size_t datalen;
		uint8_t buf[64*1024];

		/* minimum length */
		if (r < RAW_HDR_LEN)
			return 0;
		/* should start with header */
		if (memcmp(data, raw_header, RAW_HDR_IDENT_LEN))
			return 0;
		/* should be my user id */
		if (RAW_HDR_GET_USR(data) != this.userid)
			return 0;

		if (RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_DATA ||
		    RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_PING)
			this.lastdownstreamtime = time(NULL);

		/* should be data packet */
		if (RAW_HDR_GET_CMD(data) != RAW_HDR_CMD_DATA)
			return 0;

		r -= RAW_HDR_LEN;
		datalen = sizeof(buf);
		if (uncompress(buf, &datalen, data + RAW_HDR_LEN, r) == Z_OK) {
			write_tun(this.tun_fd, buf, datalen);
		}

		/* all done */
		return 0;
	}
}

int
handshake_waitdns(char *buf, size_t buflen, char cmd, int timeout)
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
	char qcmd;

	cmd = toupper(cmd);

	while (1) {
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(this.dns_fd, &fds);
		r = select(this.dns_fd + 1, &fds, NULL, NULL, &tv);

		if (r < 0)
			return -1;	/* select error */
		if (r == 0)
			return -3;	/* select timeout */

		q.id = -1;
		q.name[0] = '\0';
		rv = read_dns_withq((uint8_t *)buf, buflen, &q);

		qcmd = toupper(q.name[0]);
		if (q.id != this.chunkid || qcmd != cmd) {
			DEBUG(1, "Ignoring unfitting reply id %d starting with '%c'", q.id, q.name[0]);
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
				this.topdomain, this.topdomain);
			return -2;
		}

		/* If we get an immediate SERVFAIL on the handshake query
		   we're waiting for, wait a while before sending the next.
		   SERVFAIL reliably happens during fragsize autoprobe, but
		   mostly long after we've moved along to some other queries.
		   However, some DNS relays, once they throw a SERVFAIL, will
		   for several seconds apply it immediately to _any_ new query
		   for the same this.topdomain. When this happens, waiting a while
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

int
parse_data(uint8_t *data, size_t len, fragment *f, int *immediate, int *ping)
{
	size_t headerlen = DOWNSTREAM_HDR;
	memset(f, 0, sizeof(fragment));
	int error;

	f->seqID = data[0];

	/* Flags */
	f->end = data[2] & 1;
	f->start = (data[2] >> 1) & 1;
	f->compressed = (data[2] >> 2) & 1;
	f->ack_other = (data[2] >> 3) & 1 ? data[1] : -1;
	if (ping) *ping = (data[2] >> 4) & 1;
	error = (data[2] >> 6) & 1;

	if (immediate)
		*immediate = (data[2] >> 5) & 1;

	if (ping && *ping) { /* Handle ping stuff */
		static unsigned dn_start_seq, up_start_seq, dn_wsize, up_wsize;

		headerlen = DOWNSTREAM_PING_HDR;
		if (len < headerlen) return -1; /* invalid packet - continue */

		/* Parse data/ping header */
		dn_wsize = data[3];
		up_wsize = data[4];
		dn_start_seq = data[5];
		up_start_seq = data[6];
		DEBUG(3, "PING pkt data=%" L "u WS: up=%u, dn=%u; Start: up=%u, dn=%u",
					len - headerlen, up_wsize, dn_wsize, up_start_seq, dn_start_seq);
	}
	f->len = len - headerlen;
	if (f->len > 0)
		memcpy(f->data, data + headerlen, MIN(f->len, sizeof(f->data)));
	return error; /* return ping flag (if corresponding query was a ping) */
}

static ssize_t
tunnel_stdin()
{
	size_t datalen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	uint8_t *data;
	ssize_t readlen;

	readlen = read(STDIN_FILENO, in, sizeof(in));
	DEBUG(4, "  IN: %" L "d bytes on stdin, to be compressed: %d", readlen, this.compression_up);
	if (readlen == 0) {
		DEBUG(2, "EOF on stdin!");
		return -1;
	} else if (readlen < 0) {
		warnx("Error %d reading from stdin: %s", errno, strerror(errno));
		return -1;
	}

	if (this.conn != CONN_DNS_NULL || this.compression_up) {
		datalen = sizeof(out);
		compress2(out, &datalen, in, readlen, 9);
		data = out;
	} else {
		datalen = readlen;
		data = in;
	}

	if (this.conn == CONN_DNS_NULL) {
		/* Check if outgoing buffer can hold data */
		if (window_buffer_available(this.outbuf) < (datalen / MAX_FRAGSIZE) + 1) {
			DEBUG(1, "  Outgoing buffer full (%" L "u/%" L "u), not adding data!",
						this.outbuf->numitems, this.outbuf->length);
			return -1;
		}

		window_add_outgoing_data(this.outbuf, data, datalen, this.compression_up);
		/* Don't send anything here to respect min. send interval */
	} else {
		send_raw_data(data, datalen);
	}

	return datalen;
}

static int
tunnel_tun()
{
	size_t datalen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	uint8_t *data;
	ssize_t read;

	if ((read = read_tun(this.tun_fd, in, sizeof(in))) <= 0)
		return -1;

	DEBUG(2, " IN: %" L "u bytes on tunnel, to be compressed: %d", read, this.compression_up);

	if (this.conn != CONN_DNS_NULL || this.compression_up) {
		datalen = sizeof(out);
		compress2(out, &datalen, in, read, 9);
		data = out;
	} else {
		datalen = read;
		data = in;
	}

	if (this.conn == CONN_DNS_NULL) {
		/* Check if outgoing buffer can hold data */
		if (window_buffer_available(this.outbuf) < (read / MAX_FRAGSIZE) + 1) {
			DEBUG(1, "  Outgoing buffer full (%" L "u/%" L "u), not adding data!",
						this.outbuf->numitems, this.outbuf->length);
			return -1;
		}

		window_add_outgoing_data(this.outbuf, data, datalen, this.compression_up);
		/* Don't send anything here to respect min. send interval */
	} else {
		send_raw_data(data, datalen);
	}

	return read;
}

static int
tunnel_dns()
{
	struct query q;
	size_t datalen, buflen;
	uint8_t buf[64*1024], cbuf[64*1024], *data;
	fragment f;
	int read, compressed, ping, immediate, error;

	memset(&q, 0, sizeof(q));
	memset(buf, 0, sizeof(buf));
	memset(cbuf, 0, sizeof(cbuf));
	read = read_dns_withq(cbuf, sizeof(cbuf), &q);

	if (this.conn != CONN_DNS_NULL)
		return 1;  /* everything already done */

	/* Don't process anything that isn't data for us; usually error
	   replies from fragsize probes etc. However a sequence of those,
	   mostly 1 sec apart, will continuously break the >=2-second select
	   timeout, which means we won't send a proper ping for a while.
	   So make select a bit faster, <1sec. */
	if (q.name[0] != 'P' && q.name[0] != 'p' &&
	    q.name[0] != this.userid_char && q.name[0] != this.userid_char2) {
		this.send_ping_soon = 700;
		got_response(q.id, 0, 0);
		return -1;	/* nothing done */
	}

	if (read < DOWNSTREAM_HDR) {
		/* Maybe SERVFAIL etc. Send ping to get things back in order,
		   but wait a bit to prevent fast ping-pong loops.
		   Only change options if user hasn't specified server timeout */

		if (read < 0)
			write_dns_error(&q, 0);

		if (q.rcode == SERVFAIL && read < 0) {
			this.num_servfail++;

			if (this.lazymode) {

				if (this.send_query_recvcnt < 500 && this.num_servfail < 4) {
					fprintf(stderr, "Hmm, that's %" L "d SERVFAILs. Your data should still go through...\n", this.num_servfail);

				} else if (this.send_query_recvcnt < 500 && this.num_servfail >= 10 &&
					this.autodetect_server_timeout && this.max_timeout_ms >= 500 && this.num_servfail % 5 == 0) {

					this.max_timeout_ms -= 200;
					double target_timeout = (float) this.max_timeout_ms / 1000.0;
					fprintf(stderr, "Too many SERVFAILs (%" L "d), reducing timeout to"
						" %.1f secs. (use -I%.1f next time on this network)\n",
							this.num_servfail, target_timeout, target_timeout);

					/* Reset query counts this.stats */
					this.send_query_sendcnt = 0;
					this.send_query_recvcnt = 0;
					update_server_timeout(1);

				} else if (this.send_query_recvcnt < 500 && this.num_servfail >= 40 &&
					this.autodetect_server_timeout && this.max_timeout_ms < 500) {

					/* last-ditch attempt to fix SERVFAILs - disable lazy mode */
					immediate_mode_defaults();
					fprintf(stderr, "Attempting to disable lazy mode due to excessive SERVFAILs\n");
					handshake_switch_options(0, this.compression_down, this.downenc);
				}
			}
		}

		this.send_ping_soon = 900;

		/* Mark query as received */
		got_response(q.id, 0, 1);
		return -1;	/* nothing done */
	}

	this.send_query_recvcnt++;  /* unlikely we will ever overflow (2^64 queries is a LOT) */

	if (read == 5 && !strncmp("BADIP", (char *)cbuf, 5)) {
		this.num_badip++;
		if (this.num_badip % 5 == 1) {
			fprintf(stderr, "BADIP (%" L "d): Server rejected sender IP address (maybe iodined -c will help), or server "
					"kicked us due to timeout. Will exit if no downstream data is received in 60 seconds.\n", this.num_badip);
		}
		return -1;	/* nothing done */
	}

	/* Okay, we have a recent downstream packet */
	this.lastdownstreamtime = time(NULL);

	this.num_recv++;

	/* Mark query as received */
	got_response(q.id, immediate, 0);

	/* Decode the downstream data header and fragment-ify ready for processing */
	error = parse_data(cbuf, read, &f, &immediate, &ping);

	if ((this.debug >= 3 && ping) || (this.debug >= 2 && !ping))
		fprintf(stderr, " RX %s; frag ID %3u, ACK %3d, compression %d, datalen %" L "u, s%d e%d\n",
				ping ? "PING" : "DATA", f.seqID, f.ack_other, f.compressed, f.len, f.start, f.end);


	window_ack(this.outbuf, f.ack_other);
	window_tick(this.outbuf);

	/* respond to TCP forwarding errors by shutting down */
	if (error && this.use_remote_forward) {
		f.data[f.len] = 0;
		warnx("server: TCP forwarding error: %s", f.data);
		this.running = 0;
		return -1;
	}

	/* In lazy mode, we shouldn't get immediate replies to our most-recent
	 query, only during heavy data transfer. Since this means the server
	 doesn't have any packets to send, send one relatively fast (but not
	 too fast, to avoid runaway ping-pong loops..) */
	/* Don't send anything too soon; no data waiting from server */
	if (f.len == 0) {
		if (!ping)
			DEBUG(1, "[WARNING] Received downstream data fragment with 0 length and NOT a ping!");
		if (!this.lazymode)
			this.send_ping_soon = 100;
		else
			this.send_ping_soon = 700;
		return -1;
	}

	/* Get next ACK if nothing already pending: if we get a new ack
	 * then we must send it immediately. */
	if (this.next_downstream_ack >= 0) {
		/* If this happens something is wrong (or last frag was a re-send)
		 * May result in ACKs being delayed. */
		DEBUG(1, "this.next_downstream_ack NOT -1! (%d), %u resends, %u oos", this.next_downstream_ack, this.outbuf->resends, this.outbuf->oos);
	}

	/* Downstream data traffic + ack data fragment */
	this.next_downstream_ack = f.seqID;
	window_process_incoming_fragment(this.inbuf, &f);

	this.num_frags_recv++;

	datalen = window_reassemble_data(this.inbuf, cbuf, sizeof(cbuf), &compressed);
	if (datalen > 0) {
		if (compressed) {
			buflen = sizeof(buf);
			if ((ping = uncompress(buf, &buflen, cbuf, datalen)) != Z_OK) {
				DEBUG(1, "Uncompress failed (%d) for data len %" L "u: reassembled data corrupted or incomplete!", ping, datalen);
				datalen = 0;
			} else {
				datalen = buflen;
			}
			data = buf;
		} else {
			data = cbuf;
		}

		if (datalen) {
			if (this.use_remote_forward)
				write(STDOUT_FILENO, data, datalen);
			else
				write_tun(this.tun_fd, data, datalen);
		}
	}

	/* Move window along after doing all data processing */
	window_tick(this.inbuf);

	return read;
}

int
client_tunnel()
{
	struct timeval tv, nextresend, tmp, now, now2;
	fd_set fds;
	int rv;
	int i, use_min_send;
	int sending, total, maxfd;
	time_t last_stats;
	size_t sent_since_report, recv_since_report;

	this.connected = 1;

	/* start counting now */
	rv = 0;
	this.lastdownstreamtime = time(NULL);
	last_stats = time(NULL);

	/* reset connection statistics */
	this.num_badip = 0;
	this.num_servfail = 0;
	this.num_timeouts = 0;
	this.send_query_recvcnt = 0;
	this.send_query_sendcnt = 0;
	this.num_sent = 0;
	this.num_recv = 0;
	this.num_frags_sent = 0;
	this.num_frags_recv = 0;
	this.num_pings = 0;

	sent_since_report = 0;
	recv_since_report = 0;

	use_min_send = 0;

	if (this.debug >= 5)
		window_debug = this.debug - 3;

	while (this.running) {
		if (!use_min_send)
			tv = ms_to_timeval(this.max_timeout_ms);

		/* TODO: detect DNS servers which drop frequent requests
		 * TODO: adjust number of pending queries based on current data rate */
		if (this.conn == CONN_DNS_NULL && !use_min_send) {

			/* Send a single query per loop */
			sending = window_sending(this.outbuf, &nextresend);
			total = sending;
			check_pending_queries();
			if (this.num_pending < this.windowsize_down && this.lazymode)
				total = MAX(total, this.windowsize_down - this.num_pending);
			else if (this.num_pending < 1 && !this.lazymode)
				total = MAX(total, 1);

			/* Upstream traffic - this is where all ping/data queries are sent */
			if (sending > 0 || total > 0 || this.next_downstream_ack >= 0) {

				if (sending > 0) {
					/* More to send - next fragment */
					send_next_frag();
				} else {
					/* Send ping if we didn't send anything yet */
					send_ping(0, this.next_downstream_ack, (this.num_pings > 20 && this.num_pings % 50 == 0), 0);
					this.next_downstream_ack = -1;
				}

				sending--;
				total--;
				QTRACK_DEBUG(3, "Sent a query to fill server lazy buffer to %" L "u, will send another %d",
							 this.lazymode ? this.windowsize_down : 1, total);

				if (sending > 0 || (total > 0 && this.lazymode)) {
					/* If sending any data fragments, or server has too few
					 * pending queries, send another one after min. interval */
					/* TODO: enforce min send interval even if we get new data */
					tv = ms_to_timeval(this.min_send_interval_ms);
					if (this.min_send_interval_ms)
						use_min_send = 1;
					tv.tv_usec += 1;
				} else if (total > 0 && !this.lazymode) {
					/* In immediate mode, use normal interval when needing
					 * to send non-data queries to probe server. */
					tv = ms_to_timeval(this.send_interval_ms);
				}

				if (sending == 0 && !use_min_send) {
					/* check next resend time when not sending any data */
					if (timercmp(&nextresend, &tv, <))
						tv = nextresend;
				}

				this.send_ping_soon = 0;
			}
		}

		if (this.stats) {
			if (difftime(time(NULL), last_stats) >= this.stats) {
				/* print useful statistics report */
				fprintf(stderr, "\n============ iodine connection statistics (user %1d) ============\n", this.userid);
				fprintf(stderr, " Queries   sent: %8" L "u"  ", answered: %8" L "u"  ", SERVFAILs: %4" L "u\n",
						this.num_sent, this.num_recv, this.num_servfail);
				fprintf(stderr, "  last %3d secs: %7" L "u" " (%4" L "u/s),   replies: %7" L "u" " (%4" L "u/s)\n",
						this.stats, this.num_sent - sent_since_report, (this.num_sent - sent_since_report) / this.stats,
						this.num_recv - recv_since_report, (this.num_recv - recv_since_report) / this.stats);
				fprintf(stderr, "  num IP rejected: %4" L "u,   untracked: %4" L "u,   lazy mode: %1d\n",
						this.num_badip, this.num_untracked, this.lazymode);
				fprintf(stderr, " Min send: %5" L "d ms, Avg RTT: %5" L "d ms  Timeout server: %4" L "d ms\n",
						this.min_send_interval_ms, this.rtt_total_ms / this.num_immediate, this.server_timeout_ms);
				fprintf(stderr, " Queries immediate: %5" L "u, timed out: %4" L "u    target: %4" L "d ms\n",
						this.num_immediate, this.num_timeouts, this.max_timeout_ms);
				if (this.conn == CONN_DNS_NULL) {
					fprintf(stderr, " Frags resent: %4u,   OOS: %4u          down frag: %4" L "d ms\n",
							this.outbuf->resends, this.inbuf->oos, this.downstream_timeout_ms);
					fprintf(stderr, " TX fragments: %8" L "u" ",   RX: %8" L "u" ",   pings: %8" L "u" "\n\n",
							this.num_frags_sent, this.num_frags_recv, this.num_pings);
				}
				/* update since-last-report this.stats */
				sent_since_report = this.num_sent;
				recv_since_report = this.num_recv;
				last_stats = time(NULL);

			}
		}

		if (this.send_ping_soon && !use_min_send) {
			tv.tv_sec = 0;
			tv.tv_usec = this.send_ping_soon * 1000;
			this.send_ping_soon = 0;
		}

		FD_ZERO(&fds);
		maxfd = 0;
		if (this.conn != CONN_DNS_NULL || window_buffer_available(this.outbuf) > 1) {
			/* Fill up outgoing buffer with available data if it has enough space
			 * The windowing protocol manages data retransmits, timeouts etc. */
			if (this.use_remote_forward) {
				FD_SET(STDIN_FILENO, &fds);
				maxfd = MAX(STDIN_FILENO, maxfd);
			} else {
				FD_SET(this.tun_fd, &fds);
				maxfd = MAX(this.tun_fd, maxfd);
			}
		}
		FD_SET(this.dns_fd, &fds);
		maxfd = MAX(this.dns_fd, maxfd);

		DEBUG(4, "Waiting %ld ms before sending more... (min_send %d)", timeval_to_ms(&tv), use_min_send);

		if (use_min_send) {
			gettimeofday(&now, NULL);
		}

		i = select(maxfd + 1, &fds, NULL, NULL, &tv);

		if (use_min_send && i > 0) {
			/* enforce min_send_interval if we get interrupted by new tun data */
			gettimeofday(&now2, NULL);
			timersub(&now2, &now, &tmp);
			timersub(&tv, &tmp, &now);
			tv = now;
		} else {
			use_min_send = 0;
		}

		if (difftime(time(NULL), this.lastdownstreamtime) > 60) {
 			fprintf(stderr, "No downstream data received in 60 seconds, shutting down.\n");
 			this.running = 0;
 		}

		if (this.running == 0)
			break;

		if (i < 0)
			err(1, "select < 0");

		if (i == 0) {
			/* timed out - no new packets recv'd */
		} else {
			if (!this.use_remote_forward && FD_ISSET(this.tun_fd, &fds)) {
				if (tunnel_tun() <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets this.send_ping_soon=0. */
			}
			if (this.use_remote_forward && FD_ISSET(STDIN_FILENO, &fds)) {
				if (tunnel_stdin() <= 0) {
					fprintf(stderr, "server: closing remote TCP forward connection\n");
					/* send ping to disconnect, don't care if it comes back */
					send_ping(0, 0, 0, 1);
					this.running = 0;
					break;
				}
			}

			if (FD_ISSET(this.dns_fd, &fds)) {
				tunnel_dns();
			}
		}
		if (this.running == 0)
			break;
	}

	return rv;
}

static void
send_upenctest(char *s)
/* NOTE: String may be at most 63-4=59 chars to fit in 1 dns chunk. */
{
	char buf[512] = "zCMC";
	size_t buf_space = 10;
	uint32_t cmc = rand();

	b32->encode((uint8_t *)buf + 1, &buf_space, (uint8_t *) &cmc, 4);

	/* Append test string without changing it */
	strncat(buf, ".", 512 - strlen(buf));
	strncat(buf, s, 512 - strlen(buf));
	strncat(buf, ".", 512 - strlen(buf));
	strncat(buf, this.topdomain, 512 - strlen(buf));
	send_query((uint8_t *)buf);
}

static void
send_downenctest(char downenc, int variant)
{
	uint8_t buf[512] = "y_____.", hdr[5];

	buf[1] = downenc;

	hdr[0] = variant;
	*(uint32_t *) (hdr + 1) = rand();

	build_hostname(buf, sizeof(buf), hdr, sizeof(hdr),
				   this.topdomain, b32, this.hostname_maxlen, 2);

	send_query(buf);
}

static void
send_version(uint32_t version)
{
	uint8_t data[8], buf[512];

	*(uint32_t *) data = htonl(version);
	*(uint32_t *) (data + 4) = (uint32_t) rand(); /* CMC */

	buf[0] = 'v';

	build_hostname(buf, sizeof(buf), data, sizeof(data),
				   this.topdomain, b32, this.hostname_maxlen, 1);

	send_query(buf);
}

static void
send_login(char *login, int len)
/* Send DNS login packet. See doc/proto_xxxxxxxx.txt for details */
{
	uint8_t flags = 0, data[100];
	int length = 17, addrlen = 0;
	uint16_t port;

	if (len != 16)
		DEBUG(1, "Login calculated incorrect length hash! len=%d", len);

	memcpy(data + 1, login, 16);

	/* if remote forward address is specified and not currently connecting */
	if (this.remote_forward_connected != 2 &&
		this.remote_forward_addr.ss_family != AF_UNSPEC) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &this.remote_forward_addr;
		struct sockaddr_in *s = (struct sockaddr_in *) &this.remote_forward_addr;

		port = (this.remote_forward_addr.ss_family == AF_INET ? s->sin_port : s6->sin6_port);

		*(uint16_t *) (data + length) = port;

		flags |= 1;
		length += 2;
		/* set remote IP to be non-localhost if this.remote_forward_addr set */
		if (this.remote_forward_addr.ss_family == AF_INET && s->sin_addr.s_addr != INADDR_LOOPBACK) {
			if (this.remote_forward_addr.ss_family == AF_INET6) { /* IPv6 address */
				addrlen = sizeof(s6);
				flags |= 4;
				memcpy(data + length, &s6->sin6_addr, addrlen);
			} else { /* IPv4 address */
				flags |= 2;
				addrlen = sizeof(s);
				memcpy(data + length, &s->sin_addr, addrlen);
			}

			length += addrlen;
		}
		DEBUG(2, "Sending TCP forward login request: port %hu, length %d, addrlen %d",
			  port, length, addrlen);
	} else if (this.remote_forward_connected == 2) {
		/* remote TCP forward connection in progress */
		DEBUG(2, "Sending TCP forward login/poll request to check connection status.");
		flags |= (1 << 4);
	}

	data[0] = flags;

	DEBUG(6, "Sending login request: length=%d, flags=0x%02x, hash=0x%016llx%016llx",
		  length, flags, *(unsigned long long *) (data + 1), *(unsigned long long *) (data + 9));

	send_packet('l', data, length);
}

static void
send_fragsize_probe(uint16_t fragsize)
{
	uint8_t data[256];

	/* Probe downstream fragsize packet */

	/* build a large query domain which is random and maximum size,
	 * will also take up maximum space in the return packet */
	memset(data, MAX(1, this.rand_seed & 0xff), sizeof(data));

	*(uint16_t *) (data) = htons(fragsize);
	this.rand_seed++;

	send_packet('r', data, sizeof(data));
}

static void
send_set_downstream_fragsize(uint16_t fragsize)
{
	uint8_t data[2];
	*(uint16_t *) data = htons(fragsize);

	send_packet('n', data, sizeof(data));
}

static void
send_ip_request()
{
	send_packet('i', NULL, 0);
}

static void
send_raw_udp_login(int seed)
{
	char buf[16];
	login_calculate(buf, sizeof(buf), this.password, seed + 1);

	send_raw((uint8_t *) buf, sizeof(buf), RAW_HDR_CMD_LOGIN);
}

static void
send_codec_switch(uint8_t bits)
{
	send_packet('s', &bits, 1);
}

static void
send_server_options(int lazy, int compression, char denc)
{
	uint8_t optflags = 0;

	if (denc == 'T') /* Base32 */
		optflags |= 1 << 6;
	else if (denc == 'S') /* Base64 */
		optflags |= 1 << 5;
	else if (denc == 'U') /* Base64u */
		optflags |= 1 << 4;
	else if (denc == 'V') /* Base128 */
		optflags |= 1 << 3;
	else if (denc == 'R') /* Raw */
		optflags |= 1 << 2;

	optflags |= (compression & 1) << 1;
	optflags |= lazy & 1;

	send_packet('o', &optflags, 1);
}

static int
handshake_version(int *seed)
{
	char hex[] = "0123456789abcdef";
	char hex2[] = "0123456789ABCDEF";
	char in[4096];
	uint32_t payload;
	int i;
	int read;

	for (i = 0; this.running && i < 5; i++) {

		send_version(PROTOCOL_VERSION);

		read = handshake_waitdns(in, sizeof(in), 'V', i+1);

		if (read >= 9) {
			payload = ntohl(*(uint32_t *) (in + 4));

			if (strncmp("VACK", (char *)in, 4) == 0) {
				/* Payload is login challenge */
				*seed = payload;
				this.userid = in[8];
				this.userid_char = hex[this.userid & 15];
				this.userid_char2 = hex2[this.userid & 15];

				DEBUG(2, "Login challenge: 0x%08x", *seed);

				fprintf(stderr, "Version ok, both using protocol v 0x%08x. You are user #%d\n",
					PROTOCOL_VERSION, this.userid);
				return 0;
			} else if (strncmp("VNAK", (char *)in, 4) == 0) {
				/* Payload is server version */
				warnx("You use protocol v 0x%08x, server uses v 0x%08x. Giving up",
						PROTOCOL_VERSION, payload);
				return 1;
			} else if (strncmp("VFUL", (char *)in, 4) == 0) {
				/* Payload is max number of users on server */
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
handshake_login(int seed)
{
	char in[4096], login[16], server[65], client[65], flag;
	int mtu, netmask, read, numwaiting = 0;

	login_calculate(login, 16, this.password, seed);

	for (int i = 0; this.running && i < 5; i++) {

		send_login(login, 16);

		read = handshake_waitdns(in, sizeof(in), 'L', i + 1);
		in[MIN(read, sizeof(in))] = 0; /* Null terminate */

		if (read > 0) {
			if (strncmp("LNAK", in, 4) == 0) {
				fprintf(stderr, "Bad password\n");
				return 1;
				/* not reached */
			}
			flag = toupper(in[0]);

			switch (flag) {
				case 'I':
					if (sscanf(in, "%c-%64[^-]-%64[^-]-%d-%d",
								&flag, server, client, &mtu, &netmask) == 5) {

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
						goto bad_handshake;
					}
					break;
				case 'C':
					if (!this.use_remote_forward) {
						goto bad_handshake;
					}

					this.remote_forward_connected = 1;
					fprintf(stderr, " done.");
					return 0;
				case 'W':
					if (!this.use_remote_forward || this.remote_forward_connected == 1) {
						goto bad_handshake;
					}

					this.remote_forward_connected = 2;

					if (numwaiting == 0)
						fprintf(stderr, "server: Opening Remote TCP forward.\n");
					else
						fprintf(stderr, "%.*s", numwaiting, "...............");

					numwaiting ++;

					/* wait a while before re-polling server, max 5 tries (14 seconds) */
					if (numwaiting > 1)
						sleep(numwaiting);

					continue;
				case 'E':
					if (!this.use_remote_forward)
						goto bad_handshake;

					char errormsg[100];
					strncpy(errormsg, in + 1, MIN(read, sizeof(errormsg)));
					errormsg[99] = 0;
					fprintf(stderr, "server: Remote TCP forward connection failed: %s\n", errormsg);
					return 1;
				default:
					/* undefined flag */
					bad_handshake:
					fprintf(stderr, "Received bad handshake: %.*s\n", read, in);
					break;
			}

		}

		fprintf(stderr, "Retrying login...\n");
	}
	if (numwaiting != 0)
		warnx("Remote TCP forward connection timed out after 5 tries.");
	else
		warnx("couldn't login to server");

	return 1;
}

static int
handshake_raw_udp(int seed)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int len;
	int got_addr;

	memset(&this.raw_serv, 0, sizeof(this.raw_serv));
	got_addr = 0;

	fprintf(stderr, "Testing raw UDP data to the server (skip with -r)");
	for (i=0; this.running && i<3 ;i++) {

		send_ip_request();

		len = handshake_waitdns(in, sizeof(in), 'I', i+1);

		if (len == 5 && in[0] == 'I') {
			/* Received IPv4 address */
			struct sockaddr_in *raw4_serv = (struct sockaddr_in *) &this.raw_serv;
			raw4_serv->sin_family = AF_INET;
			memcpy(&raw4_serv->sin_addr, &in[1], sizeof(struct in_addr));
			raw4_serv->sin_port = htons(53);
			this.raw_serv_len = sizeof(struct sockaddr_in);
			got_addr = 1;
			break;
		}
		if (len == 17 && in[0] == 'I') {
			/* Received IPv6 address */
			struct sockaddr_in6 *raw6_serv = (struct sockaddr_in6 *) &this.raw_serv;
			raw6_serv->sin6_family = AF_INET6;
			memcpy(&raw6_serv->sin6_addr, &in[1], sizeof(struct in6_addr));
			raw6_serv->sin6_port = htons(53);
			this.raw_serv_len = sizeof(struct sockaddr_in6);
			got_addr = 1;
			break;
		}

		fprintf(stderr, ".");
		fflush(stderr);
	}
	fprintf(stderr, "\n");
	if (!this.running)
		return 0;

	if (!got_addr) {
		fprintf(stderr, "Failed to get raw server IP, will use DNS mode.\n");
		return 0;
	}
	fprintf(stderr, "Server is at %s, trying raw login: ", format_addr(&this.raw_serv, this.raw_serv_len));
	fflush(stderr);

	/* do login against port 53 on remote server
	 * based on the old seed. If reply received,
	 * switch to raw udp mode */
	for (i=0; this.running && i<4 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_raw_udp_login(seed);

		FD_ZERO(&fds);
		FD_SET(this.dns_fd, &fds);

		r = select(this.dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			/* recv() needed for windows, dont change to read() */
			len = recv(this.dns_fd, in, sizeof(in), 0);
			if (len >= (16 + RAW_HDR_LEN)) {
				char hash[16];
				login_calculate(hash, 16, this.password, seed - 1);
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
handshake_upenctest(char *s)
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
	int i, read, slen;

	slen = strlen(s);
	for (i=0; this.running && i<3 ;i++) {

		send_upenctest(s);

		read = handshake_waitdns(in, sizeof(in), 'Z', i+1);

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

	if (!this.running)
		return -1;

	/* timeout */
	return 0;
}

static int
handshake_upenc_autodetect()
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
		res = handshake_upenctest(pat128a);
		if (res < 0) {
			/* DNS swaps case, msg already printed; or Ctrl-C */
			return 0;
		} else if (res == 0) {
			/* Probably not okay, skip Base128 entirely */
			break;
		}

		res = handshake_upenctest(pat128b);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		/* if this works, we can test the real stuff */

		res = handshake_upenctest(pat128c);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		res = handshake_upenctest(pat128d);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		res = handshake_upenctest(pat128e);
		if (res < 0)
			return 0;
		else if (res == 0)
			break;

		/* if still here, then base128 works completely */
		return 3;
	}

	/* Try Base64 (with plus sign) */
	res = handshake_upenctest(pat64);
	if (res < 0) {
		/* DNS swaps case, msg already printed; or Ctrl-C */
		return 0;
	} else if (res > 0) {
		/* All okay, Base64 msg will be printed later */
		return 1;
	}

	/* Try Base64u (with _u_nderscore) */
	res = handshake_upenctest(pat64u);
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
handshake_downenctest(char trycodec)
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

	for (i=0; this.running && i<3 ;i++) {

		send_downenctest(trycodec, 1);

		read = handshake_waitdns(in, sizeof(in), 'Y', i+1);

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
handshake_downenc_autodetect()
/* Returns codec char (or ' ' if no advanced codec works) */
{
	int base64ok = 0;
	int base64uok = 0;
	int base128ok = 0;

	if (this.do_qtype == T_NULL || this.do_qtype == T_PRIVATE) {
		/* no other choice than raw */
		fprintf(stderr, "No alternative downstream codec available, using default (Raw)\n");
		return 'R';
	}

	fprintf(stderr, "Autodetecting downstream codec (use -O to override)\n");

	/* Try Base64 */
	if (handshake_downenctest('S'))
		base64ok = 1;
	else if (this.running && handshake_downenctest('U'))
		base64uok = 1;

	/* Try Base128 only if 64 gives us some perspective */
	if (this.running && (base64ok || base64uok)) {
		if (handshake_downenctest('V'))
			base128ok = 1;
	}

	/* If 128 works, then TXT may give us Raw as well */
	if (this.running && (base128ok && this.do_qtype == T_TXT)) {
		if (handshake_downenctest('R'))
			return 'R';
	}

	if (!this.running)
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
handshake_qtypetest(int timeout)
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

	if (this.do_qtype == T_NULL || this.do_qtype == T_PRIVATE)
		trycodec = 'R';
	else
		trycodec = 'T';

	/* We could use 'Z' bouncing here, but 'Y' also tests that 0-255
	   byte values can be returned, which is needed for NULL/PRIVATE
	   to work. */

	send_downenctest(trycodec, 1);

	read = handshake_waitdns(in, sizeof(in), 'Y', timeout);

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
handshake_qtype_autodetect()
/* Returns:
   0: okay, this.do_qtype set
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

	for (timeout = 1; this.running && timeout <= 3; timeout++) {
		for (qtypenum = 0; this.running && qtypenum < highestworking; qtypenum++) {
			this.do_qtype = handshake_qtype_numcvt(qtypenum);
			if (this.do_qtype == T_UNSET)
				break;	/* this round finished */

			fprintf(stderr, ".");
			fflush(stderr);

			if (handshake_qtypetest(timeout)) {
				/* okay */
				highestworking = qtypenum;
				DEBUG(1, " Type %s timeout %d works", client_get_qtype(), timeout);
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

	if (!this.running) {
		warnx("Stopped while autodetecting DNS query type (try setting manually with -T)");
		return 1;  /* problem */
	}

	/* finished */
	this.do_qtype = handshake_qtype_numcvt(highestworking);

	if (this.do_qtype == T_UNSET) {
		/* also catches highestworking still 100 */
		warnx("No suitable DNS query type found. Are you this.connected to a network?");
		warnx("If you expect very long roundtrip delays, use -T explicitly.");
		warnx("(Also, connecting to an \"ancient\" version of iodined won't work.)");
		return 1;  /* problem */
	}

	/* "using qtype" message printed in handshake function */
	return 0;  /* okay */
}

static int
handshake_edns0_check()
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

	if (this.do_qtype == T_NULL)
		trycodec = 'R';
	else
		trycodec = 'T';

	for (i=0; this.running && i<3 ;i++) {

		send_downenctest(trycodec, 1);

		read = handshake_waitdns(in, sizeof(in), 'Y', i+1);

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
handshake_switch_codec(int bits)
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

	for (i=0; this.running && i<5 ;i++) {

		send_codec_switch(bits);

		read = handshake_waitdns(in, sizeof(in), 'S', i+1);

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
			this.dataenc = tempenc;

			/* Update outgoing buffer max (decoded) fragsize */
			this.maxfragsize_up = get_raw_length_from_dns(this.hostname_maxlen - UPSTREAM_HDR, this.dataenc, this.topdomain);
			return;
		}

		fprintf(stderr, "Retrying codec switch...\n");
	}
	if (!this.running)
		return;

	fprintf(stderr, "No reply from server on codec switch.\n");

codec_revert:
	fprintf(stderr, "Falling back to upstream codec %s\n", this.dataenc->name);
}

void
handshake_switch_options(int lazy, int compression, char denc)
{
	char in[100];
	int read;
	char *dname, *comp_status, *lazy_status;

	comp_status = compression ? "enabled" : "disabled";

	dname = "Base32";
	if (denc == 'S')
		dname = "Base64";
	else if (denc == 'U')
		dname = "Base64u";
	else if (denc == 'V')
		dname = "Base128";
	else if (denc == 'R')
		dname = "Raw";

	lazy_status = lazy ? "lazy" : "immediate";

	fprintf(stderr, "Switching server options: %s mode, downstream codec %s, compression %s...\n",
			lazy_status, dname, comp_status);
	for (int i = 0; this.running && i < 5; i++) {

		send_server_options(lazy, compression, denc);

		read = handshake_waitdns(in, sizeof(in) - 1, 'O', i + 1);

		if (read > 0) {
			in[read] = 0; /* zero terminate */

			if (strncmp("BADLEN", in, 6) == 0) {
				fprintf(stderr, "Server got bad message length.\n");
				goto opt_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				goto opt_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				fprintf(stderr, "Server rejected the selected options.\n");
				goto opt_revert;
			} else if (strcasecmp(dname, in) == 0) {
				fprintf(stderr, "Switched server options, using downsteam codec %s.\n", in);
				this.lazymode = lazy;
				this.compression_down = compression;
				this.downenc = denc;
				return;
			} else {
				fprintf(stderr, "Got invalid response. ");
			}
		}

		fprintf(stderr, "Retrying options switch...\n");
	}
	if (!this.running)
		return;

	fprintf(stderr, "No reply from server on options switch.\n");

opt_revert:
	comp_status = this.compression_down ? "enabled" : "disabled";
	lazy_status = this.lazymode ? "lazy" : "immediate";

	fprintf(stderr, "Falling back to previous configuration: downstream codec %s, %s mode, compression %s.\n",
			this.dataenc->name, lazy_status, comp_status);
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
		if (this.downenc != ' ' && this.downenc != 'T') {
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
handshake_autoprobe_fragsize()
{
	char in[MAX_FRAGSIZE];
	int i;
	int read;
	int proposed_fragsize = 768;
	int range = 768;
	int max_fragsize;

	max_fragsize = 0;
	fprintf(stderr, "Autoprobing max downstream fragment size... (skip with -m fragsize)");
	while (this.running && range > 0 && (range >= 8 || max_fragsize < 300)) {
		/* stop the slow probing early when we have enough bytes anyway */
		for (i=0; this.running && i<3 ;i++) {

			send_fragsize_probe(proposed_fragsize);

			read = handshake_waitdns(in, sizeof(in), 'R', 1);

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
	if (!this.running) {
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
	    (this.do_qtype == T_NULL || this.do_qtype == T_PRIVATE || this.do_qtype == T_TXT ||
	     this.do_qtype == T_SRV || this.do_qtype == T_MX)) {
		fprintf(stderr, "Note: this isn't very much.\n");
		fprintf(stderr, "Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	}

	return max_fragsize - 2;
}

static void
handshake_set_fragsize(int fragsize)
{
	char in[4096];
	int i;
	int read;

	fprintf(stderr, "Setting downstream fragment size to max %d...\n", fragsize);
	for (i=0; this.running && i<5 ;i++) {

		send_set_downstream_fragsize(fragsize);

		read = handshake_waitdns(in, sizeof(in), 'N', i+1);

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
	if (!this.running)
		return;

	fprintf(stderr, "No reply from server when setting fragsize. Keeping default.\n");
}

static void
handshake_set_timeout()
{
	char in[4096];
	int read, id;

	fprintf(stderr, "Setting window sizes to %" L "u frags upstream, %" L "u frags downstream...\n",
		this.windowsize_up, this.windowsize_down);

	fprintf(stderr, "Calculating round-trip time...");

	/* Reset RTT stats */
	this.num_immediate = 0;
	this.rtt_total_ms = 0;

	for (int i = 0; this.running && i < 5; i++) {

		id = this.autodetect_server_timeout ?
			update_server_timeout(1) : send_ping(1, -1, 1, 0);

		read = handshake_waitdns(in, sizeof(in), 'P', i + 1);
		got_response(id, 1, 0);

		fprintf(stderr, ".");
		if (read > 0) {
			if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
			}
			continue;
		}

	}
	if (!this.running)
		return;

	fprintf(stderr, "\nDetermined round-trip time of %ld ms, using server timeout of %ld ms.\n",
		this.rtt_total_ms / this.num_immediate, this.server_timeout_ms);
}

int
client_handshake()
{
	int seed;
	int upcodec;
	int r;

	dnsc_use_edns0 = 0;

	/* qtype message printed in handshake function */
	if (this.do_qtype == T_UNSET) {
		r = handshake_qtype_autodetect();
		if (r) {
			return r;
		}
	}

	fprintf(stderr, "Using DNS type %s queries\n", client_get_qtype());

	if ((r = handshake_version(&seed))) {
		return r;
	}

	if ((r = handshake_login(seed))) {
		return r;
	}

	if (this.raw_mode && handshake_raw_udp(seed)) {
		this.conn = CONN_RAW_UDP;
		this.max_timeout_ms = 10000;
		this.compression_down = 1;
		this.compression_up = 1;
		if (this.use_remote_forward)
			fprintf(stderr, "Warning: Remote TCP forwards over Raw (UDP) mode may be unreliable.\n"
				"         If forwarded connections are unstable, try using '-r' to force DNS tunnelling mode.\n");
	} else {
		if (this.raw_mode == 0) {
			fprintf(stderr, "Skipping raw mode\n");
		}

		dnsc_use_edns0 = 1;
		if (handshake_edns0_check() && this.running) {
			fprintf(stderr, "Using EDNS0 extension\n");
		} else if (!this.running) {
			return -1;
		} else {
			fprintf(stderr, "DNS relay does not support EDNS0 extension\n");
			dnsc_use_edns0 = 0;
		}

		upcodec = handshake_upenc_autodetect();
		if (!this.running)
			return -1;

		if (upcodec == 1) { /* Base64 */
			handshake_switch_codec(6);
		} else if (upcodec == 2) { /* Base64u */
			handshake_switch_codec(26);
		} else if (upcodec == 3) { /* Base128 */
			handshake_switch_codec(7);
		}
		if (!this.running)
			return -1;

		if (this.downenc == ' ') {
			this.downenc = handshake_downenc_autodetect();
		}
		if (!this.running)
			return -1;

		/* Set options for compression, this.lazymode and downstream codec */
		handshake_switch_options(this.lazymode, this.compression_down, this.downenc);
		if (!this.running)
			return -1;

		if (this.autodetect_frag_size) {
			this.max_downstream_frag_size = handshake_autoprobe_fragsize();
			if (this.max_downstream_frag_size > MAX_FRAGSIZE) {
				/* This is very unlikely except perhaps over LAN */
				fprintf(stderr, "Can transfer fragsize of %d, however iodine has been compiled with MAX_FRAGSIZE = %d."
					" To fully utilize this connection, please recompile iodine/iodined.\n", this.max_downstream_frag_size, MAX_FRAGSIZE);
				this.max_downstream_frag_size = MAX_FRAGSIZE;
			}
			if (!this.max_downstream_frag_size) {
				return 1;
			}
		}

		handshake_set_fragsize(this.max_downstream_frag_size);
		if (!this.running)
			return -1;

		/* init windowing protocol */
		this.outbuf = window_buffer_init(64, this.windowsize_up, this.maxfragsize_up, WINDOW_SENDING);
		this.outbuf->timeout = ms_to_timeval(this.downstream_timeout_ms);
		/* Incoming buffer max fragsize doesn't matter */
		this.inbuf = window_buffer_init(64, this.windowsize_down, MAX_FRAGSIZE, WINDOW_RECVING);

		/* init query tracking */
		this.num_untracked = 0;
		this.num_pending = 0;
		this.pending_queries = calloc(PENDING_QUERIES_LENGTH, sizeof(struct query_tuple));
		for (int i = 0; i < PENDING_QUERIES_LENGTH; i++)
			this.pending_queries[i].id = -1;

		/* set server window/timeout parameters and calculate RTT */
		handshake_set_timeout();
	}

	return 0;
}

