/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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
#include <time.h>
#include <zlib.h>
#include <ctype.h>

#include "common.h"
#include "version.h"

#include "dns.h"
#include "encoding.h"
#include "base32.h"
#include "base64.h"
#include "base64u.h"
#include "base128.h"
#include "user.h"
#include "login.h"
#include "tun.h"
#include "fw_query.h"
#include "util.h"
#include "server.h"
#include "window.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#else
#include <err.h>
#endif

/* Global server variables */
int running = 1;
char *topdomain;
char password[33];
struct encoder *b32;
struct encoder *b64;
struct encoder *b64u;
struct encoder *b128;

int check_ip;
int my_mtu;
in_addr_t my_ip;
int netmask;

in_addr_t ns_ip;

int bind_port;
int debug;

void
server_init()
{
	running = 1;
	ns_ip = INADDR_ANY;
	netmask = 27;
	debug = 0;
	check_ip = 1;
	memset(password, 0, sizeof(password));
	fw_query_init();
	b32 = get_base32_encoder();
	b64 = get_base64_encoder();
	b64u = get_base64u_encoder();
	b128 = get_base128_encoder();
}

void
server_stop()
{
	running = 0;
}

static void
send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd, struct sockaddr_storage *from, socklen_t fromlen)
{
	char packet[buflen + RAW_HDR_LEN];
	int len = buflen;

	memcpy(packet, raw_header, RAW_HDR_LEN);
	if (len) {
		memcpy(&packet[RAW_HDR_LEN], buf, len);
	}

	len += RAW_HDR_LEN;
	packet[RAW_HDR_CMD] = cmd | (user & 0x0F);

	DEBUG(3, "TX-raw: client %s (user %d), cmd %d, %d bytes",
			format_addr(from, fromlen), user, cmd, len);

	sendto(fd, packet, len, 0, (struct sockaddr *) from, fromlen);
}

/* Ringbuffer Query Handling (qmem) and DNS Cache:
   This is used to make the handling duplicates and query timeouts simpler
   and all handled in one place.
   Using this, lazy mode is possible with n queries (n <= windowsize)

   New queries are placed consecutively in the buffer, replacing any old
   queries (already responded to) if length == QMEM_LEN. Old queries are kept
   as a record for duplicate requests. If a dupe is found and USE_DNSCACHE is
   defined, the previous answer is sent (if it exists), otherwise an invalid
   response is sent.

   On the DNS cache:
   This cache is implemented to better handle the aggressively impatient DNS
   servers that very quickly re-send requests when we choose to not
   immediately answer them in lazy mode. This cache works much better than
   pruning(=dropping) the improper requests, since the DNS server will
   actually get an answer instead of silence.

   Because of the CMC in both ping and upstream data, unwanted cache hits
   are prevented. Due to the combination of CMC and varying sequence IDs, it
   is extremely unlikely that any duplicate answers will be incorrectly sent
   during a session (given QMEM_LEN is not very large). */

#define QMEM_DEBUG(l, u, ...) \
	if (debug >= l) {\
		TIMEPRINT("[QMEM u%d (%lu/%u)] ", u, users[u].qmem.num_pending, users[u].outgoing->windowsize); \
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
	}

static void
qmem_init(int userid)
/* initialize user QMEM and DNS cache (if enabled) */
{
	memset(&users[userid].qmem, 0, sizeof(struct qmem_buffer));
	for (size_t i = 0; i < QMEM_LEN; i++) {
		users[userid].qmem.queries[i].q.id = -1;
	}
}

static int
qmem_is_cached(int dns_fd, int userid, struct query *q)
/* Check if an answer for a particular query is cached in qmem
 * If so, sends an "invalid" answer or one from DNS cache
 * Returns 0 if new query (ie. not cached), 1 if cached (and then answered) */
{
	struct qmem_buffer *buf;
	struct query *pq;
	char *data = "x";
	char dataenc = 'T';
	size_t len = 1;
	int dnscache = 0;
	buf = &users[userid].qmem;

	/* Check if this is a duplicate query */
	for (size_t p = buf->start; p != buf->end; p = (p + 1) % QMEM_LEN) {
		pq = &buf->queries[p].q;
		if (pq->id != q->id)
			continue;
		if (pq->type != q->type)
			continue;

		if (strcasecmp(pq->name, q->name))
			continue;

		/* Aha! A match! */

#ifdef USE_DNSCACHE
		/* Check if answer is in DNS cache */
		if (buf->queries[p].a.len) {
			data = (char *)buf->queries[p].a.data;
			len = buf->queries[p].a.len;
			dataenc = users[userid].downenc;
			dnscache = 1;
		}
#endif

		QMEM_DEBUG(2, userid, "OUT from qmem for '%s', %s", q->name,
				dnscache ? "answer from DNS cache" : "sending invalid response");
		write_dns(dns_fd, q, data, len, dataenc);
		return 1;
	}
	return 0;
}

static int
qmem_append(int userid, struct query *q)
/* Appends incoming query to the buffer. */
{
	struct qmem_buffer *buf;
	buf = &users[userid].qmem;

	if (buf->num_pending >= QMEM_LEN) {
		/* this means we have QMEM_LEN *pending* queries; overwrite oldest one
		 * to prevent buildup of ancient queries */
		QMEM_DEBUG(2, userid, "Full of pending queries! Replacing old query %d with new %d.",
				   buf->queries[buf->start].q.id, q->id);
	}

	if (buf->length < QMEM_LEN) {
		buf->length++;
	} else {
		/* will replace oldest query (in buf->queries[buf->start]) */
		buf->start = (buf->start + 1) % QMEM_LEN;
	}

	QMEM_DEBUG(5, userid, "add query ID %d, timeout %lu ms", q->id, timeval_to_ms(&users[userid].dns_timeout));

	/* Copy query into buffer */
	memcpy(&buf->queries[buf->end].q, q, sizeof(struct query));
#ifdef USE_DNSCACHE
	buf->queries[buf->end].a.len = 0;
#endif
	buf->end = (buf->end + 1) % QMEM_LEN;
	buf->num_pending += 1;
	return 1;
}

static void
qmem_answered(int userid, uint8_t *data, size_t len)
/* Call when oldest/first/earliest query added has been answered */
{
	struct qmem_buffer *buf;
	size_t answered;
	buf = &users[userid].qmem;

	if (buf->num_pending == 0) {
		/* Most likely caused by bugs somewhere else. */
		QMEM_DEBUG(1, userid, "Query answered with 0 in qmem! Fix bugs.");
		return;
	}
	answered = buf->start_pending;
	buf->start_pending = (buf->start_pending + 1) % QMEM_LEN;
	buf->num_pending -= 1;

#ifdef USE_DNSCACHE
	/* Add answer to query entry */
	if (len && data) {
		if (len > 4096) {
			QMEM_DEBUG(1, userid, "got answer with length >4096!");
		}
		memcpy(&buf->queries[answered].a.data, data, MIN(len, 4096));
		buf->queries[answered].a.len = len;
	}
#endif

	QMEM_DEBUG(3, userid, "query ID %d answered", buf->queries[answered].q.id);
}

struct query *
qmem_get_next_response(int userid)
/* Gets oldest query to be responded to (for lazy mode) or NULL if none available
 * The query is NOT marked as "answered" since that is done later. */
{
	struct qmem_buffer *buf;
	struct query *q;
	buf = &users[userid].qmem;
	if (buf->length == 0 || buf->num_pending == 0)
		return NULL;
	q = &buf->queries[buf->start_pending].q;
	QMEM_DEBUG(3, userid, "next response using cached query: ID %d", q->id);
	return q;
}

static struct timeval
qmem_max_wait(struct dnsfd *dns_fds, int *touser, struct query **sendq)
/* Gets max interval before the next query has to be responded to
 * Response(s) are sent automatically for queries if:
 *  - the query has timed out
 *  - the user has data to send or pending ACKs, and spare pending queries
 *  - the user has excess pending queries (>downstream window size)
 * Returns largest safe time to wait before next timeout */
{
	struct timeval now, timeout, soonest, tmp, age, nextresend;
	soonest.tv_sec = 10;
	soonest.tv_usec = 0;
	int userid, qnum, nextuser = -1, immediate, resend = 0;
	struct query *q = NULL, *nextq = NULL;
	size_t sending, total, sent;
	time_t age_ms;
	struct tun_user *u;

	gettimeofday(&now, NULL);
	for (userid = 0; userid < created_users; userid++) {
		if (!user_active(userid))
			continue;

		u = &users[userid];

		if (u->qmem.num_pending == 0)
			continue;

		/* Keep track of how many fragments we can send */
		if (u->lazy) {
			total = window_sending(u->outgoing, &nextresend);
			if ((nextresend.tv_sec != 0 || nextresend.tv_usec != 0)
				&& u->qmem.num_pending >= 1) {
				/* will use nextresend as max wait time if it is smallest
				 * and if user has spare queries */
				resend = 1;
				soonest = nextresend;
			}

			if (u->qmem.num_pending > u->outgoing->windowsize) {
				/* calculate number of "excess" queries */
				total = MAX(total, u->qmem.num_pending - u->outgoing->windowsize);
			}
		} else {
			/* User in immediate mode, must answer all pending queries */
			total = u->qmem.num_pending;
		}

		sending = total;
		sent = 0;

		qnum = u->qmem.start_pending;
		for (; qnum != u->qmem.end; qnum = (qnum + 1) % QMEM_LEN) {
			q = &u->qmem.queries[qnum].q;

			/* queries will always be in time order */
			timeradd(&q->time_recv, &u->dns_timeout, &timeout);
			if (sending > 0 || !timercmp(&now, &timeout, <) || u->next_upstream_ack >= 0) {
				/* respond to a query with ping/data if:
				 *  - query has timed out (ping, or data if available)
				 *  - user has pending data (always data)
				 *  - user has pending ACK (either) */
				timersub(&now, &q->time_recv, &age);
				age_ms = timeval_to_ms(&age);

				/* only consider "immediate" when age is negligible */
				immediate = llabs(age_ms) <= 10;

				QMEM_DEBUG(3, userid, "Auto response to cached query: ID %d, %ld ms old (%s), timeout %ld ms",
						q->id, age_ms, immediate ? "immediate" : "lazy", timeval_to_ms(&u->dns_timeout));

				sent++;
				QMEM_DEBUG(4, userid, "ANSWER q id %d, ACK %d; sent %lu of %lu + sending another %lu",
						q->id, u->next_upstream_ack, sent, total, sending);

				send_data_or_ping(dns_fds, userid, q, 0, immediate);

				if (sending > 0)
					sending--;
				continue;
			}

			timersub(&timeout, &now, &tmp);
			if (timercmp(&tmp, &soonest, <)) {
				/* the oldest non-timed-out query in the buffer will be the
				 * soonest to timeout for this user; we can skip the rest */
				soonest = tmp;
				nextuser = userid;
				nextq = q;
				break;
			}
		}
	}

	if (debug >= 5) {
		time_t soonest_ms = timeval_to_ms(&soonest);
		if (nextq && nextuser >= 0) {
			QMEM_DEBUG(5, nextuser, "can wait for %lu ms, will send id %d", soonest_ms, nextq->id);
		} else {
			if (nextuser < 0)
				nextuser = 0;
			if (soonest_ms != 10000 && resend) {
				/* only if resending some frags */
				QMEM_DEBUG(5, nextuser, "Resending some fragments")
			} else {
				QMEM_DEBUG(2, nextuser, "Don't need to send anything to any users, waiting %lu ms", soonest_ms);
			}
		}
	}

	if (sendq)
		*sendq = nextq;
	if (touser)
		*touser = nextuser;

	return soonest;
}

static int
get_dns_fd(struct dnsfd *fds, struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		return fds->v6fd;
	}
	return fds->v4fd;
}


static void
forward_query(int bind_fd, struct query *q)
{
	char buf[64*1024];
	int len;
	struct fw_query fwq;
	struct sockaddr_in *myaddr;
	in_addr_t newaddr;

	len = dns_encode(buf, sizeof(buf), q, QR_QUERY, q->name, strlen(q->name));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	/* Store sockaddr for q->id */
	memcpy(&(fwq.addr), &(q->from), q->fromlen);
	fwq.addrlen = q->fromlen;
	fwq.id = q->id;
	fw_query_put(&fwq);

	newaddr = inet_addr("127.0.0.1");
	myaddr = (struct sockaddr_in *) &(q->from);
	memcpy(&(myaddr->sin_addr), &newaddr, sizeof(in_addr_t));
	myaddr->sin_port = htons(bind_port);

	DEBUG(2, "TX: NS reply");

	if (sendto(bind_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("forward query error");
	}
}

static void
send_version_response(int fd, version_ack_t ack, uint32_t payload, int userid, struct query *q)
{
	char out[9];

	switch (ack) {
	case VERSION_ACK:
		strncpy(out, "VACK", sizeof(out));
		break;
	case VERSION_NACK:
		strncpy(out, "VNAK", sizeof(out));
		break;
	case VERSION_FULL:
		strncpy(out, "VFUL", sizeof(out));
		break;
	}

	out[4] = ((payload >> 24) & 0xff);
	out[5] = ((payload >> 16) & 0xff);
	out[6] = ((payload >> 8) & 0xff);
	out[7] = ((payload) & 0xff);
	out[8] = userid & 0xff;

	write_dns(fd, q, out, sizeof(out), users[userid].downenc);
}

void
send_data_or_ping(struct dnsfd *dns_fds, int userid, struct query *q,
				  int ping, int immediate)
/* Sends current fragment to user, or a ping if no data available.
   ping: 1=force send ping (even if data available), 0=only send if no data.
   immediate: 1=not from qmem (ie. fresh query), 0=query is from qmem */
{
	uint8_t pkt[MAX_FRAGSIZE + DOWNSTREAM_PING_HDR];
	size_t datalen, headerlen;
	struct fragment *f;
	struct frag_buffer *out, *in;

	in = users[userid].incoming;
	out = users[userid].outgoing;

	window_tick(out);

	f = window_get_next_sending_fragment(out, &users[userid].next_upstream_ack);

	/* Build downstream data/ping header (see doc/proto_xxxxxxxx.txt) for details */
	if (!f) {
		/* No data, may as well send data/ping header (with extra info) */
		ping = 1;
		datalen = 0;
		pkt[0] = 0; /* Pings don't need seq IDs unless they have data */
		pkt[1] = users[userid].next_upstream_ack & 0xFF;
		pkt[2] = (users[userid].next_upstream_ack < 0 ? 0 : 1) << 3;
		users[userid].next_upstream_ack = -1;
	} else {
		datalen = f->len;
		pkt[0] = f->seqID & 0xFF;
		pkt[1] = f->ack_other & 0xFF;
		pkt[2] = ((f->ack_other < 0 ? 0 : 1) << 3) | ((f->compressed & 1) << 2) | (f->start << 1) | f->end;
		headerlen = DOWNSTREAM_HDR;
	}

	/* If this is being responded to immediately (ie. not from qmem) */
	pkt[2] |= (immediate & 1) << 5;

	if (ping) {
		/* set ping flag and build extra header */
		pkt[2] |= 1 << 4;
		pkt[3] = out->windowsize & 0xFF;
		pkt[4] = in->windowsize & 0xFF;
		pkt[5] = out->start_seq_id & 0xFF;
		pkt[6] = in->start_seq_id & 0xFF;
		headerlen = DOWNSTREAM_PING_HDR;
	}
	if (datalen + headerlen > sizeof(pkt)) {
		/* Should never happen, or at least user should be warned about
		 * fragsize > MAX_FRAGLEN earlier on */
		warnx("send_frag_or_dataless: fragment too large to send! (%lu)", datalen);
		return;
	}
	if (f)
		memcpy(pkt + headerlen, f->data, datalen);

	write_dns(get_dns_fd(dns_fds, &q->from), q, (char *)pkt,
			  datalen + headerlen, users[userid].downenc);

	/* mark query as answered */
	qmem_answered(userid, pkt, datalen + headerlen);
	window_tick(out);
}

void
user_process_incoming_data(int tun_fd, struct dnsfd *dns_fds, int userid, int ack)
{
	uint8_t pkt[65536];
	size_t datalen;
	int compressed = 0;

	window_ack(users[userid].outgoing, ack);
	window_tick(users[userid].outgoing);

	datalen = window_reassemble_data(users[userid].incoming, pkt, sizeof(pkt), &compressed);
	window_tick(users[userid].incoming);

	/* Update time info */
	users[userid].last_pkt = time(NULL);

	if (datalen > 0) {
		/* Data reassembled successfully + cleared out of buffer */
		handle_full_packet(tun_fd, dns_fds, userid, pkt, datalen, compressed);
	}
}

static int
user_send_data(int userid, struct dnsfd *dns_fds, uint8_t *indata,
		size_t len, int compressed)
/* Appends data to a user's outgoing queue and sends it (in raw mode only) */
{
	size_t datalen;
	int ret = 0;
	uint8_t out[65536], *data;

	data = indata;
	datalen = len;

	/* use compressed or uncompressed packet to match user settings */
	if (users[userid].down_compression && !compressed) {
		datalen = sizeof(out);
		compress2(out, &datalen, indata, len, 9);
		data = out;
	} else if (!users[userid].down_compression && compressed) {
		datalen = sizeof(out);
		ret = uncompress(out, &datalen, indata, len);
		if (ret != Z_OK) {
			DEBUG(1, "FAIL: Uncompress == %d: %lu bytes to user %d!", ret, len, userid);
			return 0;
		}
	}

	compressed = users[userid].down_compression;

	if (users[userid].conn == CONN_DNS_NULL && data && datalen) {
		/* append new data to user's outgoing queue; sent later in qmem_max_wait */
		ret = window_add_outgoing_data(users[userid].outgoing, data, datalen, compressed);

	} else if (data && datalen) { /* CONN_RAW_UDP */
		if (!compressed)
			DEBUG(1, "Sending in RAW mode uncompressed to user %d!", userid);
		int dns_fd = get_dns_fd(dns_fds, &users[userid].host);
		send_raw(dns_fd, data, datalen, userid, RAW_HDR_CMD_DATA,
					&users[userid].host, users[userid].hostlen);
		ret = 1;
	}

	return ret;
}

static int
tunnel_bind(int bind_fd, struct dnsfd *dns_fds)
{
	char packet[64*1024];
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct fw_query *query;
	unsigned short id;
	int dns_fd;
	int r;

	fromlen = sizeof(struct sockaddr);
	r = recvfrom(bind_fd, packet, sizeof(packet), 0,
		(struct sockaddr*)&from, &fromlen);

	if (r <= 0)
		return 0;

	id = dns_get_id(packet, r);

	DEBUG(3, "RX: Got response on query %u from DNS", (id & 0xFFFF));

	/* Get sockaddr from id */
	fw_query_get(id, &query);
	if (!query) {
		DEBUG(2, "Lost sender of id %u, dropping reply", (id & 0xFFFF));
		return 0;
	}

	DEBUG(3, "TX: client %s id %u, %d bytes",
			format_addr(&query->addr, query->addrlen), (id & 0xffff), r);

	dns_fd = get_dns_fd(dns_fds, &query->addr);
	if (sendto(dns_fd, packet, r, 0, (const struct sockaddr *) &(query->addr),
		query->addrlen) <= 0) {
		warn("forward reply error");
	}

	return 0;
}

static int
tunnel_tun(int tun_fd, struct dnsfd *dns_fds)
{
	struct ip *header;
	static uint8_t in[64*1024];
	int userid;
	int read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return 0;

	/* find target ip in packet, in is padded with 4 bytes TUN header */
	header = (struct ip*) (in + 4);
	userid = find_user_by_ip(header->ip_dst.s_addr);
	if (userid < 0)
		return 0;

	DEBUG(3, "IN: %d byte pkt from tun to user %d; compression %d",
				read, userid, users[userid].down_compression);

	return user_send_data(userid, dns_fds, in, read, 0);
}

static int
tunnel_dns(int tun_fd, int dns_fd, struct dnsfd *dns_fds, int bind_fd)
{
	struct query q;
	int read;
	int domain_len;
	int inside_topdomain = 0;

	if ((read = read_dns(dns_fd, dns_fds, tun_fd, &q)) <= 0)
		return 0;

	DEBUG(3, "RX: client %s ID %5d, type %d, name %s",
			format_addr(&q.from, q.fromlen), q.id, q.type, q.name);

	domain_len = strlen(q.name) - strlen(topdomain);
	if (domain_len >= 0 && !strcasecmp(q.name + domain_len, topdomain))
		inside_topdomain = 1;
	/* require dot before topdomain */
	if (domain_len >= 1 && q.name[domain_len - 1] != '.')
		inside_topdomain = 0;

	if (inside_topdomain) {
		/* This is a query we can handle */

		/* Handle A-type query for ns.topdomain, possibly caused
		   by our proper response to any NS request */
		if (domain_len == 3 && q.type == T_A &&
		    (q.name[0] == 'n' || q.name[0] == 'N') &&
		    (q.name[1] == 's' || q.name[1] == 'S') &&
		     q.name[2] == '.') {
			handle_a_request(dns_fd, &q, 0);
			return 0;
		}

		/* Handle A-type query for www.topdomain, for anyone that's
		   poking around */
		if (domain_len == 4 && q.type == T_A &&
		    (q.name[0] == 'w' || q.name[0] == 'W') &&
		    (q.name[1] == 'w' || q.name[1] == 'W') &&
		    (q.name[2] == 'w' || q.name[2] == 'W') &&
		     q.name[3] == '.') {
			handle_a_request(dns_fd, &q, 1);
			return 0;
		}

		switch (q.type) {
		case T_NULL:
		case T_PRIVATE:
		case T_CNAME:
		case T_A:
		case T_MX:
		case T_SRV:
		case T_TXT:
			/* encoding is "transparent" here */
			handle_null_request(tun_fd, dns_fd, dns_fds, &q, domain_len);
			break;
		case T_NS:
			handle_ns_request(dns_fd, &q);
			break;
		default:
			break;
		}
	} else {
		/* Forward query to other port ? */
		DEBUG(2, "Requested domain outside our topdomain.");
		if (bind_fd) {
			forward_query(bind_fd, &q);
		}
	}
	return 0;
}

int
server_tunnel(int tun_fd, struct dnsfd *dns_fds, int bind_fd, int max_idle_time)
{
	struct timeval tv;
	fd_set fds;
	int i;
	int userid;
	struct query *answer_now = NULL;
	time_t last_action = time(NULL);

	if (debug >= 5)
		window_debug = debug - 3;

	while (running) {
		int maxfd;
		/* max wait time based on pending queries */
		tv = qmem_max_wait(dns_fds, &userid, &answer_now);

		FD_ZERO(&fds);
		maxfd = 0;

		if (dns_fds->v4fd >= 0) {
			FD_SET(dns_fds->v4fd, &fds);
			maxfd = MAX(dns_fds->v4fd, maxfd);
		}
		if (dns_fds->v6fd >= 0) {
			FD_SET(dns_fds->v6fd, &fds);
			maxfd = MAX(dns_fds->v6fd, maxfd);
		}

		if (bind_fd) {
			/* wait for replies from real DNS */
			FD_SET(bind_fd, &fds);
			maxfd = MAX(bind_fd, maxfd);
		}

		/* Don't read from tun if all users have filled outpacket queues */
		if(!all_users_waiting_to_send()) {
			FD_SET(tun_fd, &fds);
			maxfd = MAX(tun_fd, maxfd);
		}

		i = select(maxfd + 1, &fds, NULL, NULL, &tv);

		if(i < 0) {
			if (running)
				warn("select");
			return 1;
		}

		if (i == 0) {
			if (max_idle_time) {
				/* only trigger the check if that's worth ( ie, no need to loop over if there
				is something to send */
				if (difftime(time(NULL), last_action) > max_idle_time) {
					for (userid = 0; userid < created_users; userid++) {
						last_action = (users[userid].last_pkt > last_action) ? users[userid].last_pkt : last_action;
					}
					if (difftime(time(NULL), last_action) > max_idle_time) {
						fprintf(stderr, "Server idle for too long, shutting down...\n");
						running = 0;
					}
				}
			}
		} else {
			if (FD_ISSET(tun_fd, &fds)) {
				tunnel_tun(tun_fd, dns_fds);
			}
			if (FD_ISSET(dns_fds->v4fd, &fds)) {
				tunnel_dns(tun_fd, dns_fds->v4fd, dns_fds, bind_fd);
			}
			if (FD_ISSET(dns_fds->v6fd, &fds)) {
				tunnel_dns(tun_fd, dns_fds->v6fd, dns_fds, bind_fd);
			}
			if (FD_ISSET(bind_fd, &fds)) {
				tunnel_bind(bind_fd, dns_fds);
			}
		}
	}

	return 0;
}

void
handle_full_packet(int tun_fd, struct dnsfd *dns_fds, int userid, uint8_t *data, size_t len, int compressed)
{
	size_t rawlen;
	uint8_t out[64*1024], *rawdata;
	struct ip *hdr;
	int touser;
	int ret;

	/* Check if data needs to be uncompressed */
	if (compressed) {
		rawlen = sizeof(out);
		ret = uncompress(out, &rawlen, data, len);
		rawdata = out;
	} else {
		rawlen = len;
		rawdata = data;
		ret = Z_OK;
	}

	if (ret == Z_OK) {
		hdr = (struct ip*) (out + 4);
		touser = find_user_by_ip(hdr->ip_dst.s_addr);
		DEBUG(2, "FULL PKT: %lu bytes from user %d (touser %d)", len, userid, touser);
		if (touser == -1) {
			/* send the uncompressed packet to tun device */
			write_tun(tun_fd, rawdata, rawlen);
		} else {
			/* don't re-compress if possible */
			if (users[touser].down_compression && compressed) {
				user_send_data(touser, dns_fds, data, len, 1);
			} else {
				user_send_data(touser, dns_fds, rawdata, rawlen, 0);
			}
		}
	} else {
		DEBUG(2, "Discarded upstream data from user %d, uncompress() result: %d", userid, ret);
	}
}

static void
handle_raw_login(uint8_t *packet, size_t len, struct query *q, int fd, int userid)
{
	char myhash[16];

	if (len < 16) {
		DEBUG(2, "Invalid raw login packet: length %lu < 16 bytes!", len);
		return;
	}

	if (userid < 0 || userid >= created_users ||
		check_authenticated_user_and_ip(userid, q) != 0) {
		DEBUG(2, "User %d not authenticated, ignoring raw login!", userid);
		return;
	}

	DEBUG(1, "RX-raw: login, len %lu, from user %d", len, userid);

	/* User sends hash of seed + 1 */
	login_calculate(myhash, 16, password, users[userid].seed + 1);
	if (memcmp(packet, myhash, 16) == 0) {
		/* Update time info for user */
		users[userid].last_pkt = time(NULL);

		/* Store remote IP number */
		memcpy(&(users[userid].host), &(q->from), q->fromlen);
		users[userid].hostlen = q->fromlen;

		/* Correct hash, reply with hash of seed - 1 */
		user_set_conn_type(userid, CONN_RAW_UDP);
		login_calculate(myhash, 16, password, users[userid].seed - 1);
		send_raw(fd, (uint8_t *)myhash, 16, userid, RAW_HDR_CMD_LOGIN, &q->from, q->fromlen);

		users[userid].authenticated_raw = 1;
	}
}

static void
handle_raw_data(uint8_t *packet, size_t len, struct query *q, struct dnsfd *dns_fds, int tun_fd, int userid)
{
	if (check_authenticated_user_and_ip(userid, q) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update time info for user */
	users[userid].last_pkt = time(NULL);

	/* copy to packet buffer, update length */

	DEBUG(3, "RX-raw: full pkt raw, length %lu, from user %d", len, userid);

	handle_full_packet(tun_fd, dns_fds, userid, packet, len, 1);
}

static void
handle_raw_ping(struct query *q, int dns_fd, int userid)
{
	if (check_authenticated_user_and_ip(userid, q) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update time info for user */
	users[userid].last_pkt = time(NULL);

	DEBUG(3, "RX-raw: ping from user %d", userid);

	/* Send ping reply */
	send_raw(dns_fd, NULL, 0, userid, RAW_HDR_CMD_PING, &q->from, q->fromlen);
}

static int
raw_decode(uint8_t *packet, size_t len, struct query *q, int dns_fd, struct dnsfd *dns_fds, int tun_fd)
{
	int raw_user;
	uint8_t raw_cmd;

	/* minimum length */
	if (len < RAW_HDR_LEN) return 0;
	/* should start with header */
	if (memcmp(packet, raw_header, RAW_HDR_IDENT_LEN))
		return 0;

	raw_cmd = RAW_HDR_GET_CMD(packet);
	raw_user = RAW_HDR_GET_USR(packet);

	DEBUG(3, "RX-raw: client %s, user %d, raw command 0x%02X, length %lu",
			  format_addr(&q->from, q->fromlen), raw_user, raw_cmd, len);

	packet += RAW_HDR_LEN;
	len -= RAW_HDR_LEN;
	switch (raw_cmd) {
	case RAW_HDR_CMD_LOGIN:
		/* Login challenge */
		handle_raw_login(packet, len, q, dns_fd, raw_user);
		break;
	case RAW_HDR_CMD_DATA:
		/* Data packet */
		handle_raw_data(packet, len, q, dns_fds, tun_fd, raw_user);
		break;
	case RAW_HDR_CMD_PING:
		/* Keepalive packet */
		handle_raw_ping(q, dns_fd, raw_user);
		break;
	default:
		DEBUG(1, "Unhandled raw command %02X from user %d", raw_cmd, raw_user);
		break;
	}
	return 1;
}

int
read_dns(int fd, struct dnsfd *dns_fds, int tun_fd, struct query *q)
/* FIXME: dns_fds and tun_fd are because of raw_decode() below */
{
	struct sockaddr_storage from;
	socklen_t addrlen;
	uint8_t packet[64*1024];
	int r;
#ifndef WINDOWS32
	char control[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;

	addrlen = sizeof(struct sockaddr_storage);
	iov.iov_base = packet;
	iov.iov_len = sizeof(packet);

	msg.msg_name = (caddr_t) &from;
	msg.msg_namelen = (unsigned) addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;

	r = recvmsg(fd, &msg, 0);
#else
	addrlen = sizeof(struct sockaddr_storage);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);
#endif /* !WINDOWS32 */

	if (r > 0) {
		memcpy(&q->from, &from, addrlen);
		q->fromlen = addrlen;
		gettimeofday(&q->time_recv, NULL);

		/* TODO do not handle raw packets here! */
		if (raw_decode(packet, r, q, fd, dns_fds, tun_fd)) {
			return 0;
		}
		if (dns_decode(NULL, 0, q, QR_QUERY, (char *)packet, r) < 0) {
			return 0;
		}

#ifndef WINDOWS32
		memset(&q->destination, 0, sizeof(struct sockaddr_storage));
		/* Read destination IP address */
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {

			if (cmsg->cmsg_level == IPPROTO_IP &&
				cmsg->cmsg_type == DSTADDR_SOCKOPT) {

				struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
				addr->sin_family = AF_INET;
				addr->sin_addr = *dstaddr(cmsg);
				q->dest_len = sizeof(*addr);
				break;
			}
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_PKTINFO) {

				struct in6_pktinfo *pktinfo;
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->destination;
				pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
				addr->sin6_family = AF_INET6;
				memcpy(&addr->sin6_addr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
				q->dest_len = sizeof(*addr);
				break;
			}
		}
#endif

		return strlen(q->name);
	} else if (r < 0) {
		/* Error */
		warn("read dns");
	}

	return 0;
}

static size_t
write_dns_nameenc(uint8_t *buf, size_t buflen, uint8_t *data, size_t datalen, char downenc)
/* Returns #bytes of data that were encoded */
{
	static int td_cmc;
	char td[3];
	struct encoder *enc;

	/* Make a rotating topdomain to prevent filtering, ie 10-bit CMC */
	td_cmc ++;
	td_cmc &= 0x3FF;

	td[0] = b32_5to8(td_cmc & 0x1F);
	td[1] = b32_5to8((td_cmc >> 5) & 0x1F);
	td[2] = 0;

	/* encode data,datalen to CNAME/MX answer */
	if (downenc == 'S') {
		buf[0] = 'i';
		enc = b64;
	} else if (downenc == 'U') {
		buf[0] = 'j';
		enc = b64u;
	} else if (downenc == 'V') {
		buf[0] = 'k';
		enc = b128;
	} else {
		buf[0] = 'h';
		enc = b32;
	}

	return build_hostname(buf, buflen, data, datalen, td, enc, 0xFF, 1);
}

void
write_dns(int fd, struct query *q, char *data, size_t datalen, char downenc)
{
	char buf[64*1024];
	int len = 0;

	if (q->type == T_CNAME || q->type == T_A) {
		char cnamebuf[1024];		/* max 255 */

		write_dns_nameenc((uint8_t *)cnamebuf, sizeof(cnamebuf), (uint8_t *)data, datalen, downenc);

		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, cnamebuf, sizeof(cnamebuf));
	} else if (q->type == T_MX || q->type == T_SRV) {
		char mxbuf[64*1024];
		char *b = mxbuf;
		int offset = 0;
		int res;

		while (1) {
			res = write_dns_nameenc((uint8_t *)b, sizeof(mxbuf) - (b - mxbuf),
									(uint8_t *)data + offset, datalen - offset, downenc);
			if (res < 1) {
				/* nothing encoded */
				b++;	/* for final \0 */
				break;
			}

			b = b + strlen(b) + 1;

			offset += res;
			if (offset >= datalen)
				break;
		}

		/* Add final \0 */
		*b = '\0';

		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, mxbuf,
				 sizeof(mxbuf));
	} else if (q->type == T_TXT) {
		/* TXT with base32 */
		uint8_t txtbuf[64*1024];
		size_t space = sizeof(txtbuf) - 1;;

		memset(txtbuf, 0, sizeof(txtbuf));

		if (downenc == 'S') {
			txtbuf[0] = 's';	/* plain base64(Sixty-four) */
			len = b64->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'U') {
			txtbuf[0] = 'u';	/* Base64 with Underscore */
			len = b64u->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'V') {
			txtbuf[0] = 'v';	/* Base128 */
			len = b128->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'R') {
			txtbuf[0] = 'r';	/* Raw binary data */
			len = MIN(datalen, sizeof(txtbuf) - 1);
			memcpy(txtbuf + 1, data, len);
		} else {
			txtbuf[0] = 't';	/* plain base32(Thirty-two) */
			len = b32->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, (char *)txtbuf, len+1);
	} else {
		/* Normal NULL-record encode */
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, data, datalen);
	}

	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	DEBUG(3, "TX: client %s ID %5d, %lu bytes data, type %d, name '%10s'",
			format_addr(&q->from, q->fromlen), q->id, datalen, q->type, q->name);

	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

void
handle_null_request(int tun_fd, int dns_fd, struct dnsfd *dns_fds, struct query *q, int domain_len)
/* Handles a NULL DNS request. See doc/proto_XXXXXXXX.txt for details on iodine protocol. */
{
	struct in_addr tempip;
	uint8_t in[512];
	char logindata[16];
	uint8_t out[64*1024];
	static uint8_t unpacked[64*1024];
	char *tmp[2];
	int userid;
	size_t read;

	userid = -1;

	/* Everything here needs at least two chars in the name */
	if (domain_len < 2)
		return;

	memcpy(in, q->name, MIN(domain_len, sizeof(in)));

	DEBUG(3, "NULL request length %d/%lu, command '%c'", domain_len, sizeof(in), in[0]);

	if(in[0] == 'V' || in[0] == 'v') { /* Version request */
		uint32_t version = !PROTOCOL_VERSION;

		read = unpack_data(unpacked, sizeof(unpacked), in + 1, domain_len - 1, b32);
		/* Version greeting, compare and send ack/nak */
		if (read > 4) {
			/* Received V + 32bits version (network byte order) */
			version = ntohl(*(uint32_t *) unpacked);
		} /* if invalid pkt, just send VNAK */

		if (version == PROTOCOL_VERSION) {
			userid = find_available_user();
			if (userid >= 0) {
				struct tun_user *u = &users[userid];
				u->seed = rand();
				/* Store remote IP number */
				memcpy(&(u->host), &(q->from), q->fromlen);
				u->hostlen = q->fromlen;

				u->encoder = get_base32_encoder();

				if (q->type == T_NULL || q->type == T_PRIVATE) {
					u->downenc = 'R';
					u->downenc_bits = 8;
				} else {
					u->downenc = 'T';
					u->downenc_bits = 5;
				}
				u->down_compression = 1;
				send_version_response(dns_fd, VERSION_ACK, u->seed, userid, q);
				syslog(LOG_INFO, "Accepted version for user #%d from %s",
					userid, format_addr(&q->from, q->fromlen));
				u->fragsize = 100; /* very safe */
				u->conn = CONN_DNS_NULL;
				u->lazy = 0;
				// TODO: client specified window size
				u->outgoing->maxfraglen = u->encoder->get_raw_length(u->fragsize) - DOWNSTREAM_PING_HDR;
				window_buffer_clear(u->outgoing);
				window_buffer_clear(u->incoming);
				u->next_upstream_ack = -1;
				qmem_init(userid);

				DEBUG(1, "User %d connected with correct version from %s.",
							userid, format_addr(&q->from, q->fromlen));
			} else {
				/* No space for another user */
				send_version_response(dns_fd, VERSION_FULL, created_users, 0, q);
				syslog(LOG_INFO, "dropped user from %s, server full",
					format_addr(&q->from, q->fromlen));
			}
		} else {
			send_version_response(dns_fd, VERSION_NACK, PROTOCOL_VERSION, 0, q);
			syslog(LOG_INFO, "dropped user from %s, sent bad version %08X",
				format_addr(&q->from, q->fromlen), version);
		}
		return;
	} else if (in[0] == 'L' || in[0] == 'l') { /* Login request */
		read = unpack_data(unpacked, sizeof(unpacked), in + 1, domain_len - 1, b32);
		if (read < 17) {
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Login phase, handle auth */
		userid = unpacked[0];
		DEBUG(2, "Received login request for user %d from %s.",
					userid, format_addr(&q->from, q->fromlen));
		if (check_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			syslog(LOG_WARNING, "dropped login request from user #%d from %s; expected source %s",
				userid, format_addr(&q->from, q->fromlen), format_addr(&users[userid].host, users[userid].hostlen));
			return;
		} else {
			users[userid].last_pkt = time(NULL);
			login_calculate(logindata, 16, password, users[userid].seed);

			if (read >= 18 && (memcmp(logindata, unpacked + 1, 16) == 0)) {
				/* Store login ok */
				users[userid].authenticated = 1;

				/* Send ip/mtu/netmask info */
				tempip.s_addr = my_ip;
				tmp[0] = strdup(inet_ntoa(tempip));
				tempip.s_addr = users[userid].tun_ip;
				tmp[1] = strdup(inet_ntoa(tempip));

				read = snprintf((char *)out, sizeof(out), "%s-%s-%d-%d",
						tmp[0], tmp[1], my_mtu, netmask);

				write_dns(dns_fd, q, (char *)out, read, users[userid].downenc);
				syslog(LOG_NOTICE, "accepted password from user #%d, given IP %s", userid, tmp[1]);

				free(tmp[1]);
				free(tmp[0]);
			} else {
				write_dns(dns_fd, q, "LNAK", 4, 'T');
				syslog(LOG_WARNING, "rejected login request from user #%d from %s, bad password",
					userid, format_addr(&q->from, q->fromlen));
			}
		}
		return;
	} else if(in[0] == 'I' || in[0] == 'i') { /* IP address request */
		char reply[17];
		int length;

		userid = b32_8to5(in[1]);
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		reply[0] = 'I';
		if (q->from.ss_family == AF_INET) {
			if (ns_ip != INADDR_ANY) {
				/* If set, use assigned external ip (-n option) */
				memcpy(&reply[1], &ns_ip, sizeof(ns_ip));
			} else {
				/* otherwise return destination ip from packet */
				struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
				memcpy(&reply[1], &addr->sin_addr, sizeof(struct in_addr));
			}
			length = 1 + sizeof(struct in_addr);
		} else {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->destination;
			memcpy(&reply[1], &addr->sin6_addr, sizeof(struct in6_addr));
			length = 1 + sizeof(struct in6_addr);
		}

		write_dns(dns_fd, q, reply, length, 'T');
	} else if(in[0] == 'Z' || in[0] == 'z') { /* Upstream codec check */
		/* Check for case conservation and chars not allowed according to RFC */

		/* Reply with received hostname as data */
		/* No userid here, reply with lowest-grade downenc */
		write_dns(dns_fd, q, (char *)in, domain_len, 'T');
		return;
	} else if(in[0] == 'S' || in[0] == 's') { /* Switch upstream codec */
		int codec;
		struct encoder *enc;
		if (domain_len < 3) { /* len at least 3, example: "S15" */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		userid = b32_8to5(in[1]);

		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		codec = b32_8to5(in[2]);

		switch (codec) {
		case 5: /* 5 bits per byte = base32 */
			enc = b32;
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 6: /* 6 bits per byte = base64 */
			enc = b64;
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 26: /* "2nd" 6 bits per byte = base64u, with underscore */
			enc = b64u;
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 7: /* 7 bits per byte = base128 */
			enc = b128;
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		default:
			write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
			break;
		}
		return;
	} else if(in[0] == 'O' || in[0] == 'o') { /* Protocol options */
		int bits = 0;
		int numopts;
		char *opts;

		int tmp_lazy, tmp_downenc, tmp_comp;
		if (domain_len < 7) { /* len at least 7, example: "oa1tcmc" */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		userid = b32_8to5(in[1]);

		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		numopts = in[2] - '0';

		if (domain_len < numopts + 6 || numopts == 0 || numopts > 9) {
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return; /* invalid packet */
		}

		/* Temporary variables: don't change anything until all options parsed */
		tmp_lazy = users[userid].lazy;
		tmp_comp = users[userid].down_compression;
		tmp_downenc = users[userid].downenc;

		opts = (char *) in + 3;

		for (int i = 0; i < numopts; i++) {
			switch (toupper(opts[i])) {
			case 'T':
				tmp_downenc = 'T';
				bits = 5;
				break;
			case 'S':
				tmp_downenc = 'S';
				bits = 6;
				break;
			case 'U':
				tmp_downenc = 'U';
				bits = 6;
				break;
			case 'V':
				tmp_downenc = 'V';
				bits = 7;
				break;
			case 'R':
				tmp_downenc = 'R';
				bits = 8;
				break;
			case 'L':
				tmp_lazy = 1;
				break;
			case 'I':
				tmp_lazy = 0;
				break;
			case 'C':
				tmp_comp = 1;
				break;
			case 'D':
				tmp_comp = 0;
				break;
			default:
				write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
				return;
			}
		}

		/* Automatically switch to raw encoding if PRIVATE or NULL request */
		if ((q->type == T_NULL || q->type == T_PRIVATE) && !bits) {
			users[userid].downenc = 'R';
			bits = 8;
			DEBUG(2, "Assuming raw data encoding with NULL/PRIVATE requests for user %d.", userid);
		}
		if (bits) {
			int f = users[userid].fragsize;
			users[userid].outgoing->maxfraglen = (bits * f) / 8 - DOWNSTREAM_PING_HDR;
			users[userid].downenc_bits = bits;
		}

		DEBUG(1, "Options for user %d: down compression %d, data bits %d/maxlen %u (enc '%c'), lazy %d.",
			  userid, tmp_comp, bits, users[userid].outgoing->maxfraglen, tmp_downenc, tmp_lazy);

		/* Store any changes */
		users[userid].down_compression = tmp_comp;
		users[userid].downenc = tmp_downenc;
		users[userid].lazy = tmp_lazy;

		write_dns(dns_fd, q, opts, numopts, users[userid].downenc);
		return;
	} else if(in[0] == 'Y' || in[0] == 'y') { /* Downstream codec check */
		int i;
		char *datap;
		int datalen;

		if (domain_len < 6) { /* len at least 6, example: "YTxCMC" */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		i = b32_8to5(in[2]);	/* check variant */

		switch (i) {
		case 1:
			datap = DOWNCODECCHECK1;
			datalen = DOWNCODECCHECK1_LEN;
			break;
		default:
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		switch (toupper(in[1])) {
		case 'T':
		case 'S':
		case 'U':
		case 'V':
			if (q->type == T_TXT ||
			    q->type == T_SRV || q->type == T_MX ||
			    q->type == T_CNAME || q->type == T_A) {
				write_dns(dns_fd, q, datap, datalen, toupper(in[1]));
				return;
			}
			break;
		case 'R':
			if (q->type == T_NULL || q->type == T_TXT) {
				write_dns(dns_fd, q, datap, datalen, 'R');
				return;
			}
			break;
		}

		/* if still here, then codec not available */
		write_dns(dns_fd, q, "BADCODEC", 8, 'T');
		return;

	} else if(in[0] == 'R' || in[0] == 'r') { /* Downstream fragsize probe */
		int req_frag_size;

		if (domain_len < 16) {  /* we'd better have some chars for data... */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Downstream fragsize probe packet */
		read = unpack_data(unpacked, sizeof(unpacked), in + 1, 5, b32);

		userid = unpacked[0];
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		req_frag_size = ntohs(*(uint16_t *) (unpacked + 1));
		DEBUG(3, "Got downstream fragsize probe from user %d, required fragsize %d", userid, req_frag_size);

		if (req_frag_size < 2 || req_frag_size > 2047) {
			write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
		} else {
			char buf[2048];
			int i;
			unsigned int v = ((unsigned int) rand()) & 0xff;

			memset(buf, 0, sizeof(buf));
			buf[0] = (req_frag_size >> 8) & 0xff;
			buf[1] = req_frag_size & 0xff;
			/* make checkable pseudo-random sequence */
			buf[2] = 107;
			for (i = 3; i < 2048; i++, v = (v + 107) & 0xff)
				buf[i] = v;
			write_dns(dns_fd, q, buf, req_frag_size, users[userid].downenc);
		}
		return;
	} else if(in[0] == 'N' || in[0] == 'n') { /* Downstream fragsize */
		int max_frag_size;

		read = unpack_data(unpacked, sizeof(unpacked), in + 1, domain_len - 1, b32);

		if (read < 3) {
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Downstream fragsize packet */
		userid = unpacked[0];
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		max_frag_size = ntohs(*(uint16_t *)(unpacked + 1));
		if (max_frag_size < 2) {
			write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
		} else {
			users[userid].fragsize = max_frag_size;
			users[userid].outgoing->maxfraglen = (users[userid].downenc_bits * max_frag_size) /
				8 - DOWNSTREAM_PING_HDR;
			write_dns(dns_fd, q, (char *) unpacked + 1, 2, users[userid].downenc);

			DEBUG(1, "Setting max downstream data length to %u bytes for user %d; %d bits (%c)",
				  users[userid].outgoing->maxfraglen, userid, users[userid].downenc_bits, users[userid].downenc);
		}
		return;
	} else if(in[0] == 'P' || in[0] == 'p') { /* Ping request */
		int dn_seq, up_seq, dn_winsize, up_winsize, dn_ack;
		int respond, set_qtimeout, set_wtimeout;
		unsigned qtimeout_ms, wtimeout_ms;

		read = unpack_data(unpacked, sizeof(unpacked), in + 1, domain_len - 1, b32);
		if (read < UPSTREAM_PING) {
			DEBUG(1, "Invalid ping! Length %lu", read);
			return;
		}

		/* Check userid */
		userid = unpacked[0];
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		/* Check if cached */
		if (qmem_is_cached(dns_fd, userid, q))
			return;

		dn_ack = ((unpacked[10] >> 2) & 1) ? unpacked[1] : -1;
		up_winsize = unpacked[2];
		dn_winsize = unpacked[3];
		up_seq = unpacked[4];
		dn_seq = unpacked[5];

		/* Query timeout and window frag timeout */
		qtimeout_ms = ntohs(*(uint16_t *) (unpacked + 6));
		wtimeout_ms = ntohs(*(uint16_t *) (unpacked + 8));

		respond = unpacked[10] & 1;
		set_qtimeout = (unpacked[10] >> 3) & 1;
		set_wtimeout = (unpacked[10] >> 4) & 1;

		DEBUG(3, "PING pkt user %d, down %d/%d, up %d/%d, ACK %d, %sqtime %u ms, %swtime %u ms, respond %d (flags %02X)",
					userid, dn_seq, dn_winsize, up_seq, up_winsize, dn_ack,
					set_qtimeout ? "SET " : "", qtimeout_ms, set_wtimeout ? "SET " : "",
					wtimeout_ms, respond, unpacked[10]);

		if (set_qtimeout) {
			/* update user's query timeout if timeout flag set */
			users[userid].dns_timeout = ms_to_timeval(qtimeout_ms);

			/* if timeout is 0, we do not enable lazy mode but it is effectively the same */
			int newlazy = !(qtimeout_ms == 0);
			if (newlazy != users[userid].lazy)
				DEBUG(2, "User %d: not setting lazymode to %d with timeout %u",
					  userid, newlazy, qtimeout_ms);
		}

		if (set_wtimeout) {
			/* update sending window fragment ACK timeout */
			users[userid].outgoing->timeout = ms_to_timeval(wtimeout_ms);
		}

		qmem_append(userid, q);

		if (respond) {
			/* ping handshake - set windowsizes etc, respond NOW using this query
			 * NOTE: not added to qmem */
			DEBUG(2, "PING HANDSHAKE set windowsizes (old/new) up: %d/%d, dn: %d/%d",
				  users[userid].outgoing->windowsize, dn_winsize, users[userid].incoming->windowsize, up_winsize);
			users[userid].outgoing->windowsize = dn_winsize;
			users[userid].incoming->windowsize = up_winsize;
			send_data_or_ping(dns_fds, userid, q, 1, 1);
			return;
		}

		user_process_incoming_data(tun_fd, dns_fds, userid, dn_ack);

		/* if respond flag not set, query waits in qmem and is used later */
	} else if (isxdigit(in[0])) { /* Upstream data packet */
		int code = 0;
		struct fragment f;
		size_t len;

		/* Need 6 char header + >=1 char data */
		if (domain_len < UPSTREAM_HDR + 1)
			return;

		if ((in[0] >= '0' && in[0] <= '9'))
			code = in[0] - '0';
		if ((in[0] >= 'a' && in[0] <= 'f'))
			code = in[0] - 'a' + 10;
		if ((in[0] >= 'A' && in[0] <= 'F'))
			code = in[0] - 'A' + 10;

		userid = code;
		/* Check user and sending IP address */
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal IP */
		}

		/* Check if cached */
		if (qmem_is_cached(dns_fd, userid, q)) {
			/* if is cached, by this point it has already been answered */
			return;
		}

		qmem_append(userid, q);
		/* Decode upstream data header - see docs/proto_XXXXXXXX.txt */
		/* First byte (after userid) = CMC (ignored); skip 2 bytes */
		len = sizeof(unpacked);
		read = b32->decode(unpacked, &len, in + 2, 5);

		f.seqID = unpacked[0];
		unpacked[2] >>= 4; /* Lower 4 bits are unused */
		f.ack_other = ((unpacked[2] >> 3) & 1) ? unpacked[1] : -1;
		f.compressed = (unpacked[2] >> 2) & 1;
		f.start = (unpacked[2] >> 1) & 1;
		f.end = unpacked[2] & 1;

		/* Decode remainder of data with user encoding into fragment */
		f.len = unpack_data(f.data, MAX_FRAGSIZE, in + UPSTREAM_HDR,
						   domain_len - UPSTREAM_HDR, users[userid].encoder);

		DEBUG(3, "frag seq %3u, datalen %5lu, ACK %3d, compression %1d, s%1d e%1d",
					f.seqID, f.len, f.ack_other, f.compressed, f.start, f.end);

		/* if already waiting for an ACK to be sent back upstream (on incoming buffer) */
		if (users[userid].next_upstream_ack >= 0) {
			/* Shouldn't normally happen; will always be reset after sending a packet. */
			DEBUG(1, "[WARNING] next_upstream_ack == %d for user %d.", users[userid].next_upstream_ack, userid);
		}

		window_process_incoming_fragment(users[userid].incoming, &f);
		users[userid].next_upstream_ack = f.seqID;

		user_process_incoming_data(tun_fd, dns_fds, userid, f.ack_other);

		/* Nothing to do. ACK for this fragment is sent later in qmem_max_wait,
		 * using an old query. This is left in qmem until needed/times out */
	}
}


void
handle_ns_request(int dns_fd, struct query *q)
/* Mostly identical to handle_a_request() below */
{
	char buf[64*1024];
	int len;

	if (ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &ns_ip, sizeof(ns_ip));
	}

	len = dns_encode_ns_response(buf, sizeof(buf), q, topdomain);
	if (len < 1) {
		warnx("dns_encode_ns_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: NS reply client %s ID %5d, type %d, name %s, %d bytes",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("ns reply send error");
	}
}

void
handle_a_request(int dns_fd, struct query *q, int fakeip)
/* Mostly identical to handle_ns_request() above */
{
	char buf[64*1024];
	int len;

	if (fakeip) {
		in_addr_t ip = inet_addr("127.0.0.1");
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &ip, sizeof(ip));

	} else if (ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &ns_ip, sizeof(ns_ip));
	}

	len = dns_encode_a_response(buf, sizeof(buf), q);
	if (len < 1) {
		warnx("dns_encode_a_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: A reply client %s ID %5d, type %d, name %s, %d bytes",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("a reply send error");
	}
}
