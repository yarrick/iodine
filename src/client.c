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

/* Output flags for debug and time between stats update */
int debug;
int stats;

static int running;
static const char *password;

/* Nameserver/domain info */
static struct socket *nameserv_addrs;
static int nameserv_addrs_len;
static int current_nameserver;
static struct socket raw_serv;
static const char *topdomain;

static uint16_t rand_seed;

/* Current up/downstream window data */
static struct frag_buffer *outbuf;
static struct frag_buffer *inbuf;
static size_t windowsize_up;
static size_t windowsize_down;
static size_t maxfragsize_up;

/* Next downstream seqID to be ACK'd (-1 if none pending) */
static int next_downstream_ack;

/* Remembering queries we sent for tracking purposes */
static struct query_tuple *pending_queries;
static size_t num_pending;
static time_t max_timeout_ms;
static time_t send_interval_ms;
static time_t min_send_interval_ms;

/* Server response timeout in ms and downstream window timeout */
static time_t server_timeout_ms;
static time_t downstream_timeout_ms;
static int autodetect_server_timeout;

/* Cumulative Round-Trip-Time in ms */
static time_t rtt_total_ms;
static size_t num_immediate;

/* Connection statistics */
static size_t num_timeouts;
static size_t num_untracked;
static size_t num_servfail;
static size_t num_badip;
static size_t num_sent;
static size_t num_recv;
static size_t send_query_sendcnt = 0;
static size_t send_query_recvcnt = 0;
static size_t num_frags_sent;
static size_t num_frags_recv;
static size_t num_pings;

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

/* Upstream/downstream compression flags */
static int compression_up;
static int compression_down;

/* The encoder to use for downstream data */
static char downenc = ' ';

/* set query type to send */
static uint16_t do_qtype = T_UNSET;

/* My connection mode */
static enum connection conn;
static int connected;

static int lazymode;
static long send_ping_soon;
static time_t lastdownstreamtime;
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
	rand_seed = (uint16_t) rand();
	send_ping_soon = 1;	/* send ping immediately after startup */
	conn = CONN_DNS_NULL;

	chunkid = (uint16_t) rand();

	/* RFC says timeout minimum 5sec */
	max_timeout_ms = 5000;

	windowsize_up = 8;
	windowsize_down = 8;

	compression_up = 0;
	compression_down = 1;

	next_downstream_ack = -1;
	current_nameserver = 0;

	maxfragsize_up = 100;

	num_immediate = 1;
	rtt_total_ms = 1000;
	send_interval_ms = 1000;
	min_send_interval_ms = 1;
	downstream_timeout_ms = 5000;

	outbuf = NULL;
	inbuf = NULL;
	pending_queries = NULL;
	connected = 0;
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
client_set_nameservers(struct socket *addr, int addrslen)
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
client_set_compression(int up, int down)
{
	compression_up = up;
	compression_down = down;
}

void
client_set_dnstimeout(int timeout, int servertimeout, int downfrag, int autodetect)
{
	max_timeout_ms = timeout;
	server_timeout_ms = servertimeout;
	downstream_timeout_ms = downfrag;
	autodetect_server_timeout = autodetect;
}

void
client_set_interval(int interval_msec, int mininterval_msec)
{
	send_interval_ms = interval_msec;
	min_send_interval_ms = mininterval_msec;
}

void
client_set_lazymode(int lazy_mode)
{
	lazymode = lazy_mode;
}

void
client_set_windowsize(size_t up, size_t down)
/* set window sizes for upstream and downstream
 * XXX upstream/downstream windowsizes might as well be the same */
{
	windowsize_up = up;
	windowsize_down = down;
}

void
client_set_hostname_maxlen(size_t i)
{
	if (i <= 0xFF && i != hostname_maxlen) {
		hostname_maxlen = i;
		maxfragsize_up = get_raw_length_from_dns(hostname_maxlen - UPSTREAM_HDR, dataenc, topdomain);
		if (outbuf)
			outbuf->maxfraglen = maxfragsize_up;
	}
}

const char *
client_get_raw_addr()
{
	return format_addr(&raw_serv.addr, raw_serv.length);
}

void
client_rotate_nameserver()
{
	current_nameserver ++;
	if (current_nameserver >= nameserv_addrs_len)
		current_nameserver = 0;
}

void
immediate_mode_defaults()
{
	send_interval_ms = MIN(rtt_total_ms / num_immediate, 1000);
	max_timeout_ms = MAX(4 * rtt_total_ms / num_immediate, 5000);
	server_timeout_ms = 0;
}

/* Client-side query tracking for lazy mode */

/* Handy macro for printing stats with messages */
#ifdef DEBUG_BUILD
#define QTRACK_DEBUG(l, ...) \
	if (debug >= l) {\
		TIMEPRINT("[QTRACK (%lu/%lu), ? %lu, TO %lu, S %lu/%lu] ", num_pending, PENDING_QUERIES_LENGTH, \
				num_untracked, num_timeouts, window_sending(outbuf, NULL), outbuf->numitems); \
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
	}
#else
#define QTRACK_DEBUG(...)
#endif

static int
update_server_timeout(int dns_fd, int handshake)
/* Calculate server timeout based on average RTT, send ping "handshake" to set
 * if handshake sent, return query ID */
{
	time_t rtt_ms;
	static size_t num_rtt_timeouts = 0;

	/* Get average RTT in ms */
	rtt_ms = rtt_total_ms / num_immediate;
	if (rtt_ms >= max_timeout_ms && num_immediate > 5) {
		num_rtt_timeouts++;
		if (num_rtt_timeouts < 3) {
			fprintf(stderr, "Target interval of %ld ms less than average round-trip of "
					"%ld ms! Try increasing interval with -I.\n", max_timeout_ms, rtt_ms);
		} else {
			/* bump up target timeout */
			max_timeout_ms = rtt_ms + 1000;
			server_timeout_ms = 1000;
			if (lazymode)
				fprintf(stderr, "Adjusting server timeout to %ld ms, target interval %ld ms. Try -I%.1f next time with this network.\n",
						server_timeout_ms, max_timeout_ms, max_timeout_ms / 1000.0);

			num_rtt_timeouts = 0;
		}
	} else {
		/* Set server timeout based on target interval and RTT */
		server_timeout_ms = max_timeout_ms - rtt_ms;
		if (server_timeout_ms <= 0) {
			server_timeout_ms = 0;
			fprintf(stderr, "Setting server timeout to 0 ms: if this continues try disabling lazy mode. (-L0)\n");
		}
	}

	/* update up/down window timeouts to something reasonable */
	downstream_timeout_ms = rtt_ms * 2;
	outbuf->timeout = ms_to_timeval(downstream_timeout_ms);

	if (handshake) {
		/* Send ping handshake to set server timeout */
		return send_ping(dns_fd, 1, -1, 1);
	}
	return -1;
}

static void
check_pending_queries()
/* Updates pending queries list */
{
	num_pending = 0;
	struct timeval now, qtimeout, max_timeout;
	gettimeofday(&now, NULL);
	/* Max timeout for queries is max interval + 1 second extra */
	max_timeout = ms_to_timeval(max_timeout_ms + 1000);
	for (int i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (pending_queries[i].time.tv_sec > 0 && pending_queries[i].id >= 0) {
			timeradd(&pending_queries[i].time, &max_timeout, &qtimeout);
			if (!timercmp(&qtimeout, &now, >)) {
				/* Query has timed out, clear timestamp but leave ID */
				pending_queries[i].time.tv_sec = 0;
				num_timeouts++;
			}
			num_pending++;
		}
	}
}

static void
query_sent_now(int id)
{
	int i = 0, found = 0;
	if (!pending_queries)
		return;

	if (id < 0 || id > 65535)
		return;

	/* Replace any empty queries first, then timed out ones if necessary */
	for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
		if (pending_queries[i].id < 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		for (i = 0; i < PENDING_QUERIES_LENGTH; i++) {
			if (pending_queries[i].time.tv_sec == 0) {
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
		pending_queries[i].id = id;
		gettimeofday(&pending_queries[i].time, NULL);
		num_pending ++;
		QTRACK_DEBUG(4, "Adding query id %d into pending_queries[%d]", id, i);
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
		if (id >= 0 && pending_queries[i].id == id) {
			if (num_pending > 0)
				num_pending--;

			if (pending_queries[i].time.tv_sec == 0) {
				if (num_timeouts > 0) {
					/* If query has timed out but is still stored - just in case
					 * ID is kept on timeout in check_pending_queries() */
					num_timeouts --;
					immediate = 0;
				} else {
					/* query is empty */
					continue;
				}
			}

			if (immediate || debug >= 4) {
				timersub(&now, &pending_queries[i].time, &rtt);
				rtt_ms = timeval_to_ms(&rtt);
			}

			QTRACK_DEBUG(5, "    found answer id %d in pending queries[%d], %ld ms old", id, i, rtt_ms);

			if (immediate) {
				/* If this was an immediate response we can use it to get
				   more detailed connection statistics like RTT.
				   This lets us determine and adjust server lazy response time
				   during the session much more accurately. */
				rtt_total_ms += rtt_ms;
				num_immediate++;

				if (autodetect_server_timeout)
					update_server_timeout(-1, 0);
			}

			/* Remove query info from buffer to mark it as answered */
			id = -1;
			pending_queries[i].id = -1;
			pending_queries[i].time.tv_sec = 0;
			break;
		}
	}
	if (id > 0) {
		QTRACK_DEBUG(4, "    got untracked response to id %d.", id);
		num_untracked++;
	}
}

static int
send_query(int fd, uint8_t *hostname)
/* Returns DNS ID of sent query */
{
	uint8_t packet[4096];
	struct query q;
	size_t len;

	DEBUG(3, "TX: pkt len %lu: hostname '%s'", strlen((char *)hostname), hostname);

	chunkid += 7727;
	if (chunkid == 0)
		/* 0 is used as "no-query" in iodined.c */
		chunkid = rand() & 0xFF;

	q.id = chunkid;
	q.type = do_qtype;

	len = dns_encode((char *)packet, sizeof(packet), &q, QR_QUERY, (char *)hostname, strlen((char *)hostname));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return -1;
	}

	DEBUG(4, "  Sendquery: id %5d name[0] '%c'", q.id, hostname[0]);

	sendto(fd, packet, len, 0, (struct sockaddr*) &nameserv_addrs[current_nameserver].addr,
			nameserv_addrs[current_nameserver].length);

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
	   Note: only start fixing up connection AFTER we have connected
	         and if user hasn't specified server timeout/window timeout etc. */

	num_sent++;
	if (send_query_sendcnt > 0 && send_query_sendcnt < 100 &&
		lazymode && connected && autodetect_server_timeout) {
		send_query_sendcnt++;

		if ((send_query_sendcnt > windowsize_down && send_query_recvcnt <= 0) ||
		    (send_query_sendcnt > 2 * windowsize_down && 4 * send_query_recvcnt < send_query_sendcnt)) {
			if (max_timeout_ms > 500) {
				max_timeout_ms -= 200;
				double secs = (double) max_timeout_ms / 1000.0;
				fprintf(stderr, "Receiving too few answers. Setting target timeout to %.1fs (-I%.1f)\n", secs, secs);

				/* restart counting */
				send_query_sendcnt = 0;
				send_query_recvcnt = 0;

			} else if (lazymode) {
				fprintf(stderr, "Receiving too few answers. Will try to switch lazy mode off, but that may not"
					" always work any more. Start with -L0 next time on this network.\n");
				lazymode = 0;
				server_timeout_ms = 0;
			}
			update_server_timeout(fd, 1);
		}
	}
	return q.id;
}

static void
send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd)
{
	char packet[4096];
	int len;

	len = MIN(sizeof(packet) - RAW_HDR_LEN, buflen);

	memcpy(packet, raw_header, RAW_HDR_LEN);
	if (len) {
		memcpy(&packet[RAW_HDR_LEN], buf, len);
	}

	len += RAW_HDR_LEN;
	packet[RAW_HDR_CMD] = (cmd & 0xF0) | (user & 0x0F);

	sendto(fd, packet, len, 0, (struct sockaddr*)&raw_serv.addr, raw_serv.length);
}

static void
send_raw_data(int dns_fd, uint8_t *data, size_t datalen)
{
	send_raw(dns_fd, data, datalen, userid, RAW_HDR_CMD_DATA);
}


static int
send_packet(int fd, char cmd, const uint8_t *data, const size_t datalen)
/* Base32 encodes data and sends as single DNS query
 * Returns ID of sent query */
{
	uint8_t buf[4096];

	buf[0] = cmd;

	build_hostname(buf, sizeof(buf), data, datalen, topdomain, b32, hostname_maxlen, 1);

	return send_query(fd, buf);
}

int
send_ping(int fd, int ping_response, int ack, int set_timeout)
{
	num_pings++;
	if (conn == CONN_DNS_NULL) {
		uint8_t data[13];
		int id;

		/* Build ping header (see doc/proto_xxxxxxxx.txt) */
		data[0] = userid;
		data[1] = ack & 0xFF;

		if (outbuf && inbuf) {
			data[2] = outbuf->windowsize & 0xff;	/* Upstream window size */
			data[3] = inbuf->windowsize & 0xff;		/* Downstream window size */
			data[4] = outbuf->start_seq_id & 0xff;	/* Upstream window start */
			data[5] = inbuf->start_seq_id & 0xff;	/* Downstream window start */
		}

		*(uint16_t *) (data + 6) = htons(server_timeout_ms);
		*(uint16_t *) (data + 8) = htons(downstream_timeout_ms);

		/* update server frag/lazy timeout, ack flag, respond with ping flag */
		data[10] = ((set_timeout & 1) << 4) | ((set_timeout & 1) << 3) | ((ack < 0 ? 0 : 1) << 2) | (ping_response & 1);
		data[11] = (rand_seed >> 8) & 0xff;
		data[12] = (rand_seed >> 0) & 0xff;
		rand_seed += 1;

		DEBUG(3, " SEND PING: respond %d, ack %d, %s(server %ld ms, downfrag %ld ms), flags %02X",
				ping_response, ack, set_timeout ? "SET " : "", server_timeout_ms,
				downstream_timeout_ms, data[8]);

		id = send_packet(fd, 'p', data, sizeof(data));

		/* Log query ID as being sent now */
		query_sent_now(id);
		return id;
	} else {
		send_raw(fd, NULL, 0, userid, RAW_HDR_CMD_PING);
		return -1;
	}
}

static void
send_next_frag(int fd)
/* Sends next available fragment of data from the outgoing window buffer */
{
	static uint8_t buf[MAX_FRAGSIZE], hdr[5];
	int code, id;
	static int datacmc = 0;
	static char *datacmcchars = "abcdefghijklmnopqrstuvwxyz0123456789";
	struct fragment *f;
	size_t buflen;

	/* Get next fragment to send */
	f = window_get_next_sending_fragment(outbuf, &next_downstream_ack);
	if (!f) {
		if (outbuf->numitems > 0) {
			/* There is stuff to send but we're out of sync, so send a ping
			 * to get things back in order and keep the packets flowing */
			send_ping(fd, 1, next_downstream_ack, 1);
			next_downstream_ack = -1;
			window_tick(outbuf);
		}
		return; /* nothing to send */
	}

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */
	buf[0] = userid_char;		/* First byte is hex userid */

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
	build_hostname(buf, sizeof(buf), f->data, f->len, topdomain,
				   dataenc, hostname_maxlen, 6);

	datacmc++;
	if (datacmc >= 36)
		datacmc = 0;

	DEBUG(3, " SEND DATA: seq %d, ack %d, len %lu, s%d e%d c%d flags %1X",
			f->seqID, f->ack_other, f->len, f->start, f->end, f->compressed, hdr[2] >> 4);

	id = send_query(fd, buf);
	/* Log query ID as being sent now */
	query_sent_now(id);

	window_tick(outbuf);
	num_frags_sent++;
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
read_dns_withq(int dns_fd, int tun_fd, uint8_t *buf, size_t buflen, struct query *q)
/* Returns -1 on receive error or decode error, including DNS error replies.
   Returns 0 on replies that could be correct but are useless, and are not
   DNS error replies.
   Returns >0 on correct replies; value is #valid bytes in *buf.
*/
{
	struct socket from;
	uint8_t data[64*1024];
	int r;

	from.length = sizeof(from.addr);
	if ((r = recvfrom(dns_fd, data, sizeof(data), 0,
			  (struct sockaddr*)&from.addr, &from.length)) < 0) {
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
		if (RAW_HDR_GET_USR(data) != userid)
			return 0;

		if (RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_DATA ||
		    RAW_HDR_GET_CMD(data) == RAW_HDR_CMD_PING)
			lastdownstreamtime = time(NULL);

		/* should be data packet */
		if (RAW_HDR_GET_CMD(data) != RAW_HDR_CMD_DATA)
			return 0;

		r -= RAW_HDR_LEN;
		datalen = sizeof(buf);
		if (uncompress(buf, &datalen, data + RAW_HDR_LEN, r) == Z_OK) {
			write_tun(tun_fd, buf, datalen);
		}

		/* all done */
		return 0;
	}
}

int
handshake_waitdns(int dns_fd, char *buf, size_t buflen, char cmd, int timeout)
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
		FD_SET(dns_fd, &fds);
		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if (r < 0)
			return -1;	/* select error */
		if (r == 0)
			return -3;	/* select timeout */

		q.id = -1;
		q.name[0] = '\0';
		rv = read_dns_withq(dns_fd, 0, (uint8_t *)buf, buflen, &q);

		qcmd = toupper(q.name[0]);
		if (q.id != chunkid || qcmd != cmd) {
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

int
parse_data(uint8_t *data, size_t len, struct fragment *f, int *immediate)
{
	size_t headerlen = DOWNSTREAM_HDR;
	int ping;
	memset(f, 0, sizeof(struct fragment));

	f->seqID = data[0];

	/* Flags */
	f->end = data[2] & 1;
	f->start = (data[2] >> 1) & 1;
	f->compressed = (data[2] >> 2) & 1;
	f->ack_other = (data[2] >> 3) & 1 ? data[1] : -1;
	ping = (data[2] >> 4) & 1;

	if (immediate)
		*immediate = (data[2] >> 5) & 1;

	if (ping) { /* Handle ping stuff */
		static unsigned dn_start_seq, up_start_seq, dn_wsize, up_wsize;

		headerlen = DOWNSTREAM_PING_HDR;
		if (len < headerlen) return -1; /* invalid packet - continue */

		/* Parse data/ping header */
		dn_wsize = data[3];
		up_wsize = data[4];
		dn_start_seq = data[5];
		up_start_seq = data[6];
		DEBUG(3, "PING pkt data=%lu WS: up=%u, dn=%u; Start: up=%u, dn=%u",
					len - headerlen, up_wsize, dn_wsize, up_start_seq, dn_start_seq);
	}
	f->len = len - headerlen;
	if (f->len > 0)
		memcpy(f->data, data + headerlen, MIN(f->len, sizeof(f->data)));
	return ping; /* return ping flag (if corresponding query was a ping) */
}

static int
tunnel_tun(int tun_fd, int dns_fd)
{
	size_t datalen;
	uint8_t out[64*1024];
	uint8_t in[64*1024];
	uint8_t *data;
	ssize_t read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return -1;

	DEBUG(2, " IN: %lu bytes on tunnel, to be compressed: %d", read, compression_up);

	if (conn != CONN_DNS_NULL || compression_up) {
		datalen = sizeof(out);
		compress2(out, &datalen, in, read, 9);
		data = out;
	} else {
		datalen = read;
		data = in;
	}

	if (conn == CONN_DNS_NULL) {
		/* Check if outgoing buffer can hold data */
		if (window_buffer_available(outbuf) < (read / MAX_FRAGSIZE) + 1) {
			DEBUG(1, "  Outgoing buffer full (%lu/%lu), not adding data!",
						outbuf->numitems, outbuf->length);
			return -1;
		}

		window_add_outgoing_data(outbuf, data, datalen, compression_up);
		/* Don't send anything here to respect min. send interval */
	} else {
		send_raw_data(dns_fd, data, datalen);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	struct query q;
	size_t datalen, buflen;
	uint8_t buf[64*1024], cbuf[64*1024], *data;
	struct fragment f;
	int read, compressed, res, immediate;

	memset(&q, 0, sizeof(q));
	memset(buf, 0, sizeof(buf));
	memset(cbuf, 0, sizeof(cbuf));
	read = read_dns_withq(dns_fd, tun_fd, cbuf, sizeof(cbuf), &q);

	if (conn != CONN_DNS_NULL)
		return 1;  /* everything already done */

	/* Don't process anything that isn't data for us; usually error
	   replies from fragsize probes etc. However a sequence of those,
	   mostly 1 sec apart, will continuously break the >=2-second select
	   timeout, which means we won't send a proper ping for a while.
	   So make select a bit faster, <1sec. */
	if (q.name[0] != 'P' && q.name[0] != 'p' &&
	    q.name[0] != userid_char && q.name[0] != userid_char2) {
		send_ping_soon = 700;
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
			num_servfail++;

			if (lazymode) {

				if (send_query_recvcnt < 500 && num_servfail < 4) {
					fprintf(stderr, "Hmm, that's %ld SERVFAILs. Your data should still go through...\n", num_servfail);

				} else if (send_query_recvcnt < 500 && num_servfail >= 10 &&
					autodetect_server_timeout && max_timeout_ms >= 500 && num_servfail % 5 == 0) {

					max_timeout_ms -= 200;
					double target_timeout = (float) max_timeout_ms / 1000.0;
					fprintf(stderr, "Too many SERVFAILs (%ld), reducing timeout to"
						" %.1f secs. (use -I%.1f next time on this network)\n",
							num_servfail, target_timeout, target_timeout);

					/* Reset query counts stats */
					send_query_sendcnt = 0;
					send_query_recvcnt = 0;
					update_server_timeout(dns_fd, 1);

				} else if (send_query_recvcnt < 500 && num_servfail >= 40 &&
					autodetect_server_timeout && max_timeout_ms < 500) {

					/* last-ditch attempt to fix SERVFAILs - disable lazy mode */
					immediate_mode_defaults();
					fprintf(stderr, "Attempting to disable lazy mode due to excessive SERVFAILs\n");
					handshake_switch_options(dns_fd, 0, compression_down, downenc);
				}
			}
		}

		send_ping_soon = 900;

		/* Mark query as received */
		got_response(q.id, 0, 1);
		return -1;	/* nothing done */
	}

	send_query_recvcnt++;  /* unlikely we will ever overflow (2^64 queries is a LOT) */

	if (read == 5 && !strncmp("BADIP", (char *)cbuf, 5)) {
		num_badip++;
		if (num_badip % 5 == 1) {
			fprintf(stderr, "BADIP (%ld): Server rejected sender IP address (maybe iodined -c will help), or server "
					"kicked us due to timeout. Will exit if no downstream data is received in 60 seconds.\n", num_badip);
		}
		return -1;	/* nothing done */
	}

	/* Okay, we have a recent downstream packet */
	lastdownstreamtime = time(NULL);

	num_recv++;

	/* Decode the downstream data header and fragment-ify ready for processing */
	res = parse_data(cbuf, read, &f, &immediate);

	/* Mark query as received */
	got_response(q.id, immediate, 0);

	if ((debug >= 3 && res) || (debug >= 2 && !res))
		fprintf(stderr, " RX %s; frag ID %3u, ACK %3d, compression %d, datalen %lu, s%d e%d\n",
				res ? "PING" : "DATA", f.seqID, f.ack_other, f.compressed, f.len, f.start, f.end);


	window_ack(outbuf, f.ack_other);
	window_tick(outbuf);

	/* In lazy mode, we shouldn't get immediate replies to our most-recent
	 query, only during heavy data transfer. Since this means the server
	 doesn't have any packets to send, send one relatively fast (but not
	 too fast, to avoid runaway ping-pong loops..) */
	/* Don't send anything too soon; no data waiting from server */
	if (f.len == 0) {
		if (!res)
			DEBUG(1, "[WARNING] Received downstream data fragment with 0 length and NOT a ping!");
		if (!lazymode)
			send_ping_soon = 100;
		else
			send_ping_soon = 700;
		return -1;
	}

	/* Get next ACK if nothing already pending: if we get a new ack
	 * then we must send it immediately. */
	if (next_downstream_ack >= 0) {
		/* If this happens something is wrong (or last frag was a re-send)
		 * May result in ACKs being delayed. */
		DEBUG(1, "next_downstream_ack NOT -1! (%d), %u resends, %u oos", next_downstream_ack, outbuf->resends, outbuf->oos);
	}

	/* Downstream data traffic + ack data fragment */
	next_downstream_ack = f.seqID;
	window_process_incoming_fragment(inbuf, &f);

	num_frags_recv++;

	datalen = window_reassemble_data(inbuf, cbuf, sizeof(cbuf), &compressed);
	if (datalen > 0) {
		if (compressed) {
			buflen = sizeof(buf);
			if ((res = uncompress(buf, &buflen, cbuf, datalen)) != Z_OK) {
				DEBUG(1, "Uncompress failed (%d) for data len %lu: reassembled data corrupted or incomplete!", res, datalen);
				datalen = 0;
			} else {
				datalen = buflen;
			}
			data = buf;
		} else {
			data = cbuf;
		}

		if (datalen)
			write_tun(tun_fd, data, datalen);
	}

	/* Move window along after doing all data processing */
	window_tick(inbuf);

	return read;
}

int
client_tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv, nextresend, tmp, now, now2;
	fd_set fds;
	int rv;
	int i, use_min_send;
	int sending, total;
	time_t last_stats;
	size_t sent_since_report, recv_since_report;

	connected = 1;

	/* start counting now */
	rv = 0;
	lastdownstreamtime = time(NULL);
	last_stats = time(NULL);

	/* reset connection statistics */
	num_badip = 0;
	num_servfail = 0;
	num_timeouts = 0;
	send_query_recvcnt = 0;
	send_query_sendcnt = 0;
	num_sent = 0;
	num_recv = 0;
	num_frags_sent = 0;
	num_frags_recv = 0;
	num_pings = 0;

	sent_since_report = 0;
	recv_since_report = 0;

	use_min_send = 0;

	if (debug >= 5)
		window_debug = debug - 3;

	while (running) {
		if (!use_min_send)
			tv = ms_to_timeval(max_timeout_ms);

		/* TODO: detect DNS servers which drop frequent requests
		 * TODO: adjust number of pending queries based on current data rate */
		if (conn == CONN_DNS_NULL && !use_min_send) {

			/* Send a single query per loop */
			sending = window_sending(outbuf, &nextresend);
			total = sending;
			check_pending_queries();
			if (num_pending < windowsize_down && lazymode)
				total = MAX(total, windowsize_down - num_pending);
			else if (num_pending < 1 && !lazymode)
				total = MAX(total, 1);

			/* Upstream traffic - this is where all ping/data queries are sent */
			if (sending > 0 || total > 0 || next_downstream_ack >= 0) {

				if (sending > 0) {
					/* More to send - next fragment */
					send_next_frag(dns_fd);
				} else {
					/* Send ping if we didn't send anything yet */
					send_ping(dns_fd, 0, next_downstream_ack, (num_pings > 20 && num_pings % 50 == 0));
					next_downstream_ack = -1;
				}

				sending--;
				total--;
				QTRACK_DEBUG(3, "Sent a query to fill server lazy buffer to %lu, will send another %d",
							 lazymode ? windowsize_down : 1, total);

				if (sending > 0 || (total > 0 && lazymode)) {
					/* If sending any data fragments, or server has too few
					 * pending queries, send another one after min. interval */
					/* TODO: enforce min send interval even if we get new data */
					tv = ms_to_timeval(min_send_interval_ms);
					if (min_send_interval_ms)
						use_min_send = 1;
					tv.tv_usec += 1;
				} else if (total > 0 && !lazymode) {
					/* In immediate mode, use normal interval when needing
					 * to send non-data queries to probe server. */
					tv = ms_to_timeval(send_interval_ms);
				}

				if (sending == 0 && !use_min_send) {
					/* check next resend time when not sending any data */
					if (timercmp(&nextresend, &tv, <))
						tv = nextresend;
				}

				send_ping_soon = 0;
			}
		}

		if (stats) {
			if (difftime(time(NULL), last_stats) >= stats) {
				/* print useful statistics report */
				fprintf(stderr, "\n============ iodine connection statistics (user %1d) ============\n", userid);
				fprintf(stderr, " Queries   sent: %8lu"  ", answered: %8lu"  ", SERVFAILs: %4lu\n",
						num_sent, num_recv, num_servfail);
				fprintf(stderr, "  last %3d secs: %7lu" " (%4lu/s),   replies: %7lu" " (%4lu/s)\n",
						stats, num_sent - sent_since_report, (num_sent - sent_since_report) / stats,
						num_recv - recv_since_report, (num_recv - recv_since_report) / stats);
				fprintf(stderr, "  num IP rejected: %4lu,   untracked: %4lu,   lazy mode: %1d\n",
						num_badip, num_untracked, lazymode);
				fprintf(stderr, " Min send: %5ld ms, Avg RTT: %5ld ms  Timeout server: %4ld ms\n",
						min_send_interval_ms, rtt_total_ms / num_immediate, server_timeout_ms);
				fprintf(stderr, " Queries immediate: %5lu, timed out: %4lu    target: %4ld ms\n",
						num_immediate, num_timeouts, max_timeout_ms);
				if (conn == CONN_DNS_NULL) {
					fprintf(stderr, " Frags resent: %4u,   OOS: %4u          down frag: %4ld ms\n",
							outbuf->resends, inbuf->oos, downstream_timeout_ms);
					fprintf(stderr, " TX fragments: %8lu" ",   RX: %8lu" ",   pings: %8lu" "\n\n",
							num_frags_sent, num_frags_recv, num_pings);
				}
				/* update since-last-report stats */
				sent_since_report = num_sent;
				recv_since_report = num_recv;
				last_stats = time(NULL);

			}
		}

		if (send_ping_soon && !use_min_send) {
			tv.tv_sec = 0;
			tv.tv_usec = send_ping_soon * 1000;
			send_ping_soon = 0;
		}

		FD_ZERO(&fds);
		if (conn != CONN_DNS_NULL || window_buffer_available(outbuf) > 16) {
			/* Fill up outgoing buffer with available data if it has enough space
			 * The windowing protocol manages data retransmits, timeouts etc. */
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		DEBUG(4, "Waiting %ld ms before sending more... (min_send %d)", timeval_to_ms(&tv), use_min_send);

		if (use_min_send) {
			gettimeofday(&now, NULL);
		}

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);

		if (use_min_send && i > 0) {
			/* enforce min_send_interval if we get interrupted by new tun data */
			gettimeofday(&now2, NULL);
			timersub(&now2, &now, &tmp);
			timersub(&tv, &tmp, &now);
			tv = now;
		} else {
			use_min_send = 0;
		}

		if (difftime(time(NULL), lastdownstreamtime) > 60) {
 			fprintf(stderr, "No downstream data received in 60 seconds, shutting down.\n");
 			running = 0;
 		}

		if (running == 0)
			break;

		if (i < 0)
			err(1, "select < 0");

		if (i == 0) {
			/* timed out - no new packets recv'd */
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
send_fragsize_probe(int fd, uint16_t fragsize)
{
	uint8_t probedata[256];
	uint8_t buf[MAX_FRAGSIZE];
	uint8_t hdr[3];
	size_t hdr_len_enc = 6;

	buf[0] = 'r'; /* Probe downstream fragsize packet */

	hdr[0] = userid;
	*(uint16_t *) (hdr + 1) = htons(fragsize);

	b32->encode(buf + 1, &hdr_len_enc, hdr, 3);
	/* build a large query domain which is random and maximum size,
	 * will also take up maximum space in the return packet */
	memset(probedata, MAX(1, rand_seed & 0xff), sizeof(probedata));
	probedata[1] = MAX(1, (rand_seed >> 8) & 0xff);
	rand_seed++;

	/* Note: must either be same, or larger, than send_chunk() */
	build_hostname(buf, sizeof(buf), probedata, sizeof(probedata), topdomain,
				   dataenc, hostname_maxlen, 6);

	send_query(fd, buf);
}

static void
send_set_downstream_fragsize(int fd, uint16_t fragsize)
{
	uint8_t data[5];

	data[0] = userid;
	*(uint16_t *) (data + 1) = htons(fragsize);
	data[3] = (rand_seed >> 8) & 0xff;
	data[4] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'n', data, sizeof(data));
}

static void
send_version(int fd, uint32_t version)
{
	uint8_t data[6];

	version = htonl(version);
	*(uint32_t *) data = version;

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

	send_raw(dns_fd, (uint8_t *) buf, sizeof(buf), userid, RAW_HDR_CMD_LOGIN);
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

	strncat(buf, s, 512 - strlen(buf));
	strncat(buf, ".", 512 - strlen(buf));
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
send_server_options(int fd, int userid, int lazy, int compression, char denc, char *options)
/* Options must be length >=4 */
{
	char buf[512] = "oU3___CMC.";
	buf[1] = b32_5to8(userid);

	options[0] = tolower(denc);
	options[1] = lazy ? 'l' : 'i';
	options[2] = compression ? 'c' : 'd';
	options[3] = 0;
	strncpy(buf + 3, options, 3);

	buf[6] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[7] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[8] = b32_5to8((rand_seed) & 0x1f);
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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'V', i+1);

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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'L', i+1);

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

		len = handshake_waitdns(dns_fd, in, sizeof(in), 'I', i+1);

		if (len == 5 && in[0] == 'I') {
			/* Received IPv4 address */
			struct sockaddr_in *raw4_serv = (struct sockaddr_in *) &raw_serv.addr;
			raw4_serv->sin_family = AF_INET;
			memcpy(&raw4_serv->sin_addr, &in[1], sizeof(struct in_addr));
			raw4_serv->sin_port = htons(53);
			raw_serv.length = sizeof(struct sockaddr_in);
			got_addr = 1;
			break;
		}
		if (len == 17 && in[0] == 'I') {
			/* Received IPv6 address */
			struct sockaddr_in6 *raw6_serv = (struct sockaddr_in6 *) &raw_serv.addr;
			raw6_serv->sin6_family = AF_INET6;
			memcpy(&raw6_serv->sin6_addr, &in[1], sizeof(struct in6_addr));
			raw6_serv->sin6_port = htons(53);
			raw_serv.length = sizeof(struct sockaddr_in6);
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
	fprintf(stderr, "Server is at %s, trying raw login: ", format_addr(&raw_serv.addr, raw_serv.length));
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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'Z', i+1);

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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'Y', i+1);

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
		return 'R';
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

	read = handshake_waitdns(dns_fd, in, sizeof(in), 'Y', timeout);

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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'Y', i+1);

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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'S', i+1);

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
			maxfragsize_up = get_raw_length_from_dns(hostname_maxlen - UPSTREAM_HDR, dataenc, topdomain);
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

void
handshake_switch_options(int dns_fd, int lazy, int compression, char denc)
{
	char in[4096];
	int read;
	char *dname, *comp_status, *lazy_status;
	char opts[4];

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
	for (int i = 0; running && i < 5; i++) {

		send_server_options(dns_fd, userid, lazy, compression, denc, opts);

		read = handshake_waitdns(dns_fd, in, sizeof(in) - 1, 'O', i + 1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				fprintf(stderr, "Server got bad message length.\n");
				goto opt_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
				goto opt_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				fprintf(stderr, "Server rejected the selected options.\n");
				goto opt_revert;
			}
			fprintf(stderr, "Switched server options successfully. (%s)\n", opts);
			lazymode = lazy;
			compression_down = compression;
			downenc = denc;
			return;
		}

		fprintf(stderr, "Retrying options switch...\n");
	}
	if (!running)
		return;

	fprintf(stderr, "No reply from server on options switch.\n");

opt_revert:
	comp_status = compression_down ? "enabled" : "disabled";
	lazy_status = lazymode ? "lazy" : "immediate";

	fprintf(stderr, "Falling back to previous configuration: downstream codec %s, %s mode, compression %s.\n",
			dataenc->name, lazy_status, comp_status);
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

			read = handshake_waitdns(dns_fd, in, sizeof(in), 'R', 1);

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

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'N', i+1);

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

static void
handshake_set_timeout(int dns_fd)
{
	char in[4096];
	int read, id;

	if (autodetect_server_timeout && lazymode) {
		fprintf(stderr, "Calculating round-trip time for optimum server timeout...");
	} else {
		fprintf(stderr, "Setting window sizes to %lu frags upstream, %lu frags downstream...",
				windowsize_up, windowsize_down);
	}

	for (int i = 0; running && i < 5; i++) {

		id = autodetect_server_timeout ?
			update_server_timeout(dns_fd, 1) : send_ping(dns_fd, 1, -1, 1);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'P', i + 1);
		got_response(id, 1, 0);

		fprintf(stderr, ".");
		if (read > 0) {
			if (strncmp("BADIP", in, 5) == 0) {
				fprintf(stderr, "Server rejected sender IP address.\n");
			}
			if (autodetect_server_timeout)
				continue;
			else
				break;
		}

	}
	if (!running)
		return;

	if (autodetect_server_timeout)
		fprintf(stderr, "\nDetermined round-trip time of %ld ms, server timeout of %ld ms.\n",
			rtt_total_ms / num_immediate, server_timeout_ms);
	else
		fprintf(stderr, " done\n");
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
		conn = CONN_RAW_UDP;
		max_timeout_ms = 10000;
		compression_down = 1;
		compression_up = 1;
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

		/* Set options for compression, lazymode and downstream codec */
		handshake_switch_options(dns_fd, lazymode, compression_down, downenc);
		if (!running)
			return -1;

		if (autodetect_frag_size) {
			fragsize = handshake_autoprobe_fragsize(dns_fd);
			if (fragsize > MAX_FRAGSIZE) {
				/* This is very unlikely except perhaps over LAN */
				fprintf(stderr, "Can transfer fragsize of %d, however iodine has been compiled with MAX_FRAGSIZE = %d."
					" To fully utilize this connection, please recompile iodine/iodined.\n", fragsize, MAX_FRAGSIZE);
				fragsize = MAX_FRAGSIZE;
			}
			if (!fragsize) {
				return 1;
			}
		}

		handshake_set_fragsize(dns_fd, fragsize);
		if (!running)
			return -1;

		/* init windowing protocol */
		outbuf = window_buffer_init(64, windowsize_up, maxfragsize_up, WINDOW_SENDING);
		outbuf->timeout = ms_to_timeval(downstream_timeout_ms);
		/* Incoming buffer max fragsize doesn't matter */
		inbuf = window_buffer_init(64, windowsize_down, MAX_FRAGSIZE, WINDOW_RECVING);

		/* init query tracking */
		num_untracked = 0;
		num_pending = 0;
		pending_queries = calloc(PENDING_QUERIES_LENGTH, sizeof(struct query_tuple));
		for (int i = 0; i < PENDING_QUERIES_LENGTH; i++)
			pending_queries[i].id = -1;

		/* set server window/timeout parameters and calculate RTT */
		handshake_set_timeout(dns_fd);
	}

	return 0;
}

