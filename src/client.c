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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <zlib.h>
#include <time.h>

#include "config.h"
#ifndef WINDOWS
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include "common.h"
#include "compat.h"
#include "encoding.h"
#include "dns.h"
#include "login.h"
#include "random.h"
#include "raw.h"
#include "sock.h"
#include "tun.h"
#include "version.h"
#include "client.h"
#include "udp.h"
#include "ui.h"

static void handshake_lazyoff(sock_t dns_fd);

static int running;
static const char *password;

static struct net_addr nameserv;
static struct udp_addr raw_serv;
static const char *topdomain;

static uint16_t rand_seed;

/* Current up/downstream IP packet */
static struct packet outpkt;
static struct packet inpkt;
int outchunkresent = 0;

/* My userid at the server */
static unsigned char userid;
static char userid_char;

/* DNS id for next packet */
static uint16_t chunkid;
static uint16_t chunkid_prev;
static uint16_t chunkid_prev2;

/* The encoder used for data packets
 * Defaults to Base32, can be changed after handshake */
static const struct encoder *dataenc = &base32_ops;

/* The encoder to use for downstream data */
static const struct encoder *downenc = NULL;

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
static int hostname_maxlen = 0xFF;

void
client_init(void)
{
	running = 1;
	secure_random(&rand_seed, sizeof(rand_seed));
	send_ping_soon = 1;	/* send ping immediately at startup */
	conn = CONN_DNS_NULL;

	secure_random(&chunkid, sizeof(chunkid));
	chunkid_prev = 0;
	chunkid_prev2 = 0;

	outpkt.len = 0;
	outpkt.seqno = 0;
	outpkt.fragment = 0;
	outchunkresent = 0;
	inpkt.len = 0;
	inpkt.seqno = 0;
	inpkt.fragment = 0;
}

void
client_stop(void)
{
	running = 0;
}

enum connection
client_get_conn(void)
{
	return conn;
}

void
client_set_nameserver(struct net_addr *addr)
{
	nameserv = *addr;
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
client_get_qtype(void)
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

int
client_set_downenc(char *encoding)
{
	const struct encoder *enc = get_encoder_by_name(encoding);
	if (enc) {
		if (do_qtype == T_UNSET || encoder_valid_for_qtype(enc, do_qtype)) {
			downenc = enc;
			return 0;
		}
		return 1;
	}
	return 1;
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
client_set_hostname_maxlen(int i)
{
	if (i <= 0xFF)
		hostname_maxlen = i;
}

const char *
client_get_raw_addr(void)
{
	return format_addr(&raw_serv.remote);
}

static void
send_query(sock_t fd, char *hostname)
{
	char packet[4096];
	struct dns_msg q;
	size_t len;

	chunkid_prev2 = chunkid_prev;
	chunkid_prev = chunkid;
	chunkid += 7727;
	if (chunkid == 0)
		/* 0 is used as "no-query" in iodined.c */
		chunkid = 7727;

	q.id = chunkid;
	q.type = do_qtype;
	memset(&q.address.local.addr, 0, sizeof(q.address.local.addr));
	q.address.local.addrlen = 0;
	q.address.remote = nameserv;

	len = dns_encode(packet, sizeof(packet), &q, QR_QUERY, hostname, strlen(hostname));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

#if 0
	ui_log("  Sendquery: id %5d name[0] '%c'\n", q.id, hostname[0]);
#endif

	send_udp(fd, packet, len, &q.address);

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
send_packet(sock_t fd, char cmd, const char *data, const size_t datalen)
{
	char buf[4096];

	buf[0] = cmd;

	build_hostname(buf + 1, sizeof(buf) - 1, data, datalen, topdomain,
		       &base32_ops, hostname_maxlen);
	send_query(fd, buf);
}

static inline int
is_sending(void)
{
	return (outpkt.len != 0);
}

static void
send_chunk(sock_t fd)
{
	char buf[4096];
	unsigned int avail;
	unsigned int code;
	char *p;
	static int datacmc = 0;
	char *datacmcchars = "abcdefghijklmnopqrstuvwxyz0123456789";

	p = outpkt.data;
	p += outpkt.offset;
	avail = outpkt.len - outpkt.offset;

	/* Note: must be same, or smaller than send_fragsize_probe() */
	outpkt.sentlen = build_hostname(buf + 5, sizeof(buf) - 5, p, avail,
					topdomain, dataenc, hostname_maxlen);

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */

	buf[0] = userid_char;		/* First byte is hex userid */

	code = ((outpkt.seqno & 7) << 2) | ((outpkt.fragment & 15) >> 2);
	buf[1] = b32_5to8(code); /* Second byte is 3 bits seqno, 2 upper bits fragment count */

	code = ((outpkt.fragment & 3) << 3) | (inpkt.seqno & 7);
	buf[2] = b32_5to8(code); /* Third byte is 2 bits lower fragment count, 3 bits downstream packet seqno */

	code = ((inpkt.fragment & 15) << 1) | (outpkt.sentlen == avail);
	buf[3] = b32_5to8(code); /* Fourth byte is 4 bits downstream fragment count, 1 bit last frag flag */

	buf[4] = datacmcchars[datacmc];	/* Fifth byte is data-CMC */
	datacmc++;
	if (datacmc >= 36)
		datacmc = 0;

#if 0
	ui_log("  Send: down %d/%d up %d/%d, %d bytes\n",
		inpkt.seqno, inpkt.fragment, outpkt.seqno, outpkt.fragment,
		outpkt.sentlen);
#endif

	send_query(fd, buf);
}

static void
send_ping(sock_t fd)
{
	if (conn == CONN_DNS_NULL) {
		char data[4];

		data[0] = userid;
		data[1] = ((inpkt.seqno & 7) << 4) | (inpkt.fragment & 15);
		data[2] = (rand_seed >> 8) & 0xff;
		data[3] = (rand_seed >> 0) & 0xff;

		rand_seed++;

#if 0
		ui_log("  Send: down %d/%d         (ping)\n",
			inpkt.seqno, inpkt.fragment);
#endif

		send_packet(fd, 'p', data, sizeof(data));
	} else {
		struct raw_msg msg = {
			.cmd = RAW_HDR_CMD_PING,
			.userid = userid,
		};

		send_raw(fd, &msg, &raw_serv);
	}
}

static void
log_dns_error(struct dns_msg *q, int ignore_some_errors)
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

static int
tunnel_raw(sock_t tun_fd, sock_t dns_fd)
{
	struct udp_addr addr;
	struct raw_msg msg;
	char data[64*1024];
	unsigned long packetlen;
	char packet[64*1024];
	int r;

	r = read_udp(dns_fd, data, sizeof(data), &addr);
	if (r < 0) {
		return -1;
	}

	if (!raw_decode(&msg, data, r)) return 0;
	/* should be my user id */
	if (msg.userid != userid) return 0;

	if (msg.cmd == RAW_HDR_CMD_DATA || msg.cmd == RAW_HDR_CMD_PING)
		lastdownstreamtime = time(NULL);

	/* should be data packet */
	if (msg.cmd != RAW_HDR_CMD_DATA) return 0;

	packetlen = sizeof(packet);
	if (uncompress((uint8_t*)packet, &packetlen, (const uint8_t*) msg.data, msg.len) == Z_OK) {
		write_tun(tun_fd, packet, packetlen);
	}

	/* don't process any further */
	return 0;
}

static int
read_dns(sock_t dns_fd, char *buf, int buflen, struct dns_msg *q)
/* Returns -1 on receive error or decode error, including DNS error replies.
   Returns 0 on replies that could be correct but are useless, and are not
   DNS error replies.
   Returns >0 on correct replies; value is #valid bytes in *buf.
*/
{
	char data[64*1024];
	int rv;

	rv = read_udp(dns_fd, data, sizeof(data), &q->address);
	if (rv <= 0)
		/* useless packet */
		return rv;

	rv = dns_decode_answer(buf, buflen, q, data, rv);
	if (rv <= 0)
		return rv;

	if (q->rtype == T_NULL || q->rtype == T_PRIVATE) {
		return rv;
	}
	return payload_unwrap(buf, rv, q->rtype);
}

static int
handshake_waitdns(sock_t dns_fd, char *buf, int buflen, char cmd, int timeout)
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
	struct dns_msg q;
	int r, rv;

	if (buflen <= 0)
		return -1;

	/* In case it was uppercase, will be compared to lowercase below */
	cmd = ascii_tolower(cmd);
	while (1) {
		unsigned char command;
		r = sock_select(timeout * 1000, NULL, dns_fd);

		if (r < 0)
			return -1;	/* select error */
		if (r == 0)
			return -3;	/* select timeout */

		q.id = 0;
		q.name[0] = '\0';
		rv = read_dns(dns_fd, buf, buflen - 1, &q);
		command = ascii_tolower(q.name[0]);

		if (q.id != chunkid || command != cmd) {
#if 0
			ui_log("Ignoring unfitting reply id %d starting with '%c'\n", q.id, q.name[0]);
#endif
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
		    (command == 'y' || command == 'v')) {
			ui_log("Got empty reply. This nameserver may not be resolving recursively, use another.\n");
			ui_log("Try \"iodine [options] ns.%s %s\" first, it might just work.\n",
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
			log_dns_error(&q, 1);
			return -2;
		}
		/* rv either 0 or >0, always NUL-terminate in the reserved byte. */
		buf[rv] = '\0';
		return rv;
	}

	/* not reached */
	return -1;
}

static int
tunnel_tun(sock_t tun_fd, sock_t dns_fd)
{
	unsigned long outlen;
	unsigned long inlen;
	char out[64*1024];
	char in[64*1024];
	ssize_t read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return -1;

	/* We may be here only to empty the tun device; then return -1
	   to force continue in select loop. */
	if (is_sending())
		return -1;

	outlen = sizeof(out);
	inlen = read;
	compress2((uint8_t*)out, &outlen, (uint8_t*)in, inlen, 9);

	memcpy(outpkt.data, out, MIN(outlen, sizeof(outpkt.data)));
	outpkt.sentlen = 0;
	outpkt.offset = 0;
	outpkt.seqno = (outpkt.seqno + 1) & 7;
	outpkt.len = outlen;
	outpkt.fragment = 0;
	outchunkresent = 0;

	if (conn == CONN_DNS_NULL) {
		send_chunk(dns_fd);

		send_ping_soon = 0;
	} else {
		struct raw_msg msg = {
			.cmd = RAW_HDR_CMD_DATA,
			.userid = userid,
			.data = outpkt.data,
			.len = outpkt.len,
		};

		send_raw(dns_fd, &msg, &raw_serv);
		outpkt.len = 0;
	}

	return read;
}

static int
tunnel_dns(sock_t tun_fd, sock_t dns_fd)
{
	static long packrecv = 0;
	static long packrecv_oos = 0;
	static long packrecv_servfail = 0;
	int up_ack_seqno;
	int up_ack_fragment;
	int new_down_seqno;
	int new_down_fragment;
	struct dns_msg q;
	unsigned long datalen;
	char buf[64*1024];
	int read;
	int send_something_now = 0;
	unsigned char command;

	memset(q.name, 0, sizeof(q.name));
	read = read_dns(dns_fd, buf, sizeof(buf), &q);

#if 0
	ui_log("				Recv: id %5d name[0]='%c'\n",
		q.id, q.name[0]);
#endif

	/* Don't process anything that isn't data for us; usually error
	   replies from fragsize probes etc. However a sequence of those,
	   mostly 1 sec apart, will continuously break the >=2-second select
	   timeout, which means we won't send a proper ping for a while.
	   So make select a bit faster, <1sec. */
	command = ascii_tolower(q.name[0]);
	if (command != 'p' && command != userid_char) {
		send_ping_soon = 700;
		return -1;	/* nothing done */
	}

	if (read < 2) {
		/* Maybe SERVFAIL etc. Send ping to get things back in order,
		   but wait a bit to prevent fast ping-pong loops. */

		if (read < 0)
			log_dns_error(&q, 0);

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

		/* read == 1 happens with "QMEM" illegal replies, caused by
		   heavy reordering, or after short disconnections when
		   data-CMC has looped around into the "duplicate" values.
		   All these cases are helped by faster pinging. */
#if 0
		if (read == 1)
			ui_log("   q=%c id %5d 1-byte illegal \"QMEM\" reply\n", q.name[0], q.id);
#endif

		send_ping_soon = 900;
		return -1;	/* nothing done */
	}

	if (read == 5 && !strncmp("BADIP", buf, 5)) {
		warnx("BADIP: Server rejected sender IP address (maybe iodined -c will help), or server kicked us due to timeout. Will exit if no downstream data is received in 60 seconds.");
		return -1;	/* nothing done */
	}

	if (send_ping_soon) {
		send_something_now = 1;
		send_ping_soon = 0;
	}

	/* Decode the data header, update seqno and frag;
	   already checked read>=2
	   Note that buf[] gets overwritten when down-pkt complete */
	new_down_seqno = (buf[1] >> 5) & 7;
	new_down_fragment = (buf[1] >> 1) & 15;
	up_ack_seqno = (buf[0] >> 4) & 7;
	up_ack_fragment = buf[0] & 15;

#if 0
	ui_log("				Recv: id %5d down %d/%d up %d/%d, %d bytes\n",
		q.id, new_down_seqno, new_down_fragment, up_ack_seqno,
		up_ack_fragment, read);
#endif

	/* Downstream data traffic */

	if (read > 2 && new_down_seqno != inpkt.seqno &&
	    recent_seqno(inpkt.seqno, new_down_seqno)) {
		/* This is the previous seqno, or a bit earlier.
		   Probably out-of-sequence dupe due to unreliable
		   intermediary DNS. Don't get distracted, but send
		   ping quickly to get things back in order.
		   Ping will send our current seqno idea.
		   If it's really a new packet that skipped multiple seqnos
		   (why??), server will re-send and drop a few times and
		   eventually everything will work again. */
		read = 2;
		send_ping_soon = 500;
		/* Still process upstream ack, if any */
	}

	if (!(packrecv & 0x1000000))
		packrecv++;
	send_query_recvcnt++;  /* overflow doesn't matter */

	/* Don't process any non-recent stuff any further.
	   No need to remember more than 3 ids: in practice any older replies
	   arrive after new/current replies, and whatever data the old replies
	   have, it has become useless in the mean time.
	   Actually, ever since iodined is replying to both the original query
	   and the last dupe, this hardly triggers any more.
	 */
	if (q.id != chunkid && q.id != chunkid_prev && q.id != chunkid_prev2) {
		packrecv_oos++;
#if 0
		ui_log("   q=%c Packs received = %8ld  Out-of-sequence = %8ld\n", q.name[0], packrecv, packrecv_oos);
#endif
		if (lazymode && packrecv < 1000 && packrecv_oos == 5) {
			if (selecttimeout > 1)
				warnx("Hmm, getting some out-of-sequence DNS replies. Setting interval to 1 (use -I1 next time on this network). If data traffic still has large hiccups, try if -L0 works better.");
			else
				warnx("Hmm, getting some out-of-sequence DNS replies. If data traffic often has large hiccups, try running with -L0 .");
			selecttimeout = 1;
			send_query_sendcnt = 0;
			send_query_recvcnt = 0;
		}

		if (send_something_now) {
			send_ping(dns_fd);
			send_ping_soon = 0;
		}
		return -1;	/* nothing done */
	}
#if 0
	ui_log("   q=%c Packs received = %8ld  Out-of-sequence = %8ld\n", q.name[0], packrecv, packrecv_oos);
#endif

	/* Okay, we have a recent downstream packet */
	lastdownstreamtime = time(NULL);

	/* In lazy mode, we shouldn't get much replies to our most-recent
	   query, only during heavy data transfer. Since this means the server
	   doesn't have any packets left, send one relatively fast (but not
	   too fast, to avoid runaway ping-pong loops..) */
	if (q.id == chunkid && lazymode) {
		if (!send_ping_soon || send_ping_soon > 900)
			send_ping_soon = 900;
	}

	if (read == 2 && new_down_seqno != inpkt.seqno &&
	    !recent_seqno(inpkt.seqno, new_down_seqno)) {
		/* This is a seqno that we didn't see yet, but it has
		   no data any more. Possible since iodined will send
		   fitting packs just once and not wait for ack.
		   Real data got lost, or will arrive shortly.
		   Update our idea of the seqno, and drop any waiting
		   old pack. Send ping to get things back on track. */
		inpkt.seqno = new_down_seqno;
		inpkt.fragment = new_down_fragment;
		inpkt.len = 0;
		send_ping_soon = 500;
	}

	while (read > 2) {
	/* "if" with easy exit */

		if (new_down_seqno != inpkt.seqno) {
			/* New packet (and not dupe of recent; checked above) */
			/* Forget any old packet, even if incomplete */
			inpkt.seqno = new_down_seqno;
			inpkt.fragment = new_down_fragment;   /* hopefully 0 */
			inpkt.len = 0;
		} else if (inpkt.fragment == 0 && new_down_fragment == 0 &&
			   inpkt.len == 0) {
			/* Weird situation: we probably got a no-data reply
			   for this seqno (see above), and the actual data
			   is following now. */
			/* okay, nothing to do here, just so that next else-if
			   doesn't trigger */
		} else if (new_down_fragment <= inpkt.fragment) {
			/* Same packet but duplicate fragment, ignore.
			   If the server didn't get our ack for it, the next
			   ping or chunk will do that. */
			send_ping_soon = 500;
			break;
		} else if (new_down_fragment > inpkt.fragment + 1) {
			/* Quite impossible. We missed a fragment, but the
			   server got our ack for it and is sending the next
			   fragment already. Don't handle it but let server
			   re-send and drop. */
			send_ping_soon = 500;
			break;
		}
		inpkt.fragment = new_down_fragment;

		datalen = MIN((unsigned int)(read - 2), sizeof(inpkt.data) - inpkt.len);

		/* we are here only when read > 2, so datalen "always" >=1 */

		/* Skip 2 byte data header and append to packet */
		memcpy(&inpkt.data[inpkt.len], &buf[2], datalen);
		inpkt.len += datalen;

		if (buf[1] & 1) { /* If last fragment flag is set */
			/* Uncompress packet and send to tun */
			/* RE-USES buf[] */
			datalen = sizeof(buf);
			if (uncompress((uint8_t*)buf, &datalen, (uint8_t*) inpkt.data, inpkt.len) == Z_OK) {
				write_tun(tun_fd, buf, datalen);
			}
			inpkt.len = 0;
			/* Keep .seqno and .fragment as is, so that we won't
			   reassemble from duplicate fragments */
		}

		/* Send anything to ack the received seqno/frag, and get more */
		if (inpkt.len == 0) {
			/* was last frag; wait just a trifle because our
			   tun will probably return TCP-ack immediately.
			   5msec = 200 DNSreq/sec */
			send_ping_soon = 5;
		} else {
			/* server certainly has more data */
			send_something_now = 1;
		}

		break;
	}

	/* NOTE: buf[] was overwritten when down-packet complete */


	/* Upstream data traffic */

	if (is_sending()) {
		/* already checked read>=2 */
#if 0
		ui_log("Got ack for %d,%d - expecting %d,%d - id=%d cur=%d prev=%d prev2=%d\n",
			up_ack_seqno, up_ack_fragment, outpkt.seqno, outpkt.fragment,
			q.id, chunkid, chunkid_prev, chunkid_prev2);
#endif

		if (up_ack_seqno == outpkt.seqno &&
		    up_ack_fragment == outpkt.fragment) {
			/* Okay, previously sent fragment has arrived */

			outpkt.offset += outpkt.sentlen;
			if (outpkt.offset >= outpkt.len) {
				/* Packet completed */
				outpkt.offset = 0;
				outpkt.len = 0;
				outpkt.sentlen = 0;
				outchunkresent = 0;

				/* Normally, server still has a query in queue,
				   but sometimes not. So send a ping.
				   (Comment this out and you'll see occasional
				   hiccups.)
				   But since the server often still has a
				   query and we can expect a TCP-ack returned
				   from our tun device quickly in many cases,
				   don't be too fast.
				   20msec still is 50 DNSreq/second... */
				if (!send_ping_soon || send_ping_soon > 20)
					send_ping_soon = 20;
			} else {
				/* More to send */
				outpkt.fragment++;
				outchunkresent = 0;
				send_chunk(dns_fd);
				send_ping_soon = 0;
				send_something_now = 0;
			}
		}
		/* else: Some wrong fragment has arrived, or old fragment is
		   acked again, mostly by ping responses.
		   Don't resend chunk, usually not needed; select loop will
		   re-send on timeout (1sec if is_sending()). */
	}


	/* Send ping if we didn't send anything yet */
	if (send_something_now) {
		send_ping(dns_fd);
		send_ping_soon = 0;
	}

	return read;
}

int
client_tunnel(sock_t tun_fd, sock_t dns_fd)
{
	fd_set fds;
	int i;

	lastdownstreamtime = time(NULL);
	send_query_sendcnt = 0;  /* start counting now */

	while (running) {
		int timeout_ms = selecttimeout * 1000;
		sock_t watch_tun;

		if (is_sending()) {
			/* fast timeout for retransmits */
			timeout_ms = 1000;
		}

		if (send_ping_soon) {
			timeout_ms = send_ping_soon;
		}

		/* If re-sending upstream data, chances are that
		   we're several seconds behind already and TCP
		   will start filling tun buffer with (useless)
		   retransmits.
		   Get up-to-date fast by simply dropping stuff,
		   that's what TCP is designed to handle. */
		watch_tun = (!is_sending() || outchunkresent >= 2) ? tun_fd : INVALID_SOCK;

		i = sock_select(timeout_ms, &fds, watch_tun, dns_fd);

 		if (lastdownstreamtime + 60 < time(NULL)) {
 			warnx("No downstream data received in 60 seconds, shutting down.");
 			running = 0;
 		}

		if (running == 0)
			break;

		if (i < 0)
			err(1, "select");

		if (i == 0) {
			/* timeout */
			if (is_sending()) {
				/* Re-send current fragment; either frag
				   or ack probably dropped somewhere.
				   But problem: no cache-miss-counter,
				   so hostname will be identical.
				   Just drop whole packet after 3 retries,
				   and TCP retransmit will solve it.
				   NOTE: tun dropping above should be
				   >=(value_here - 1) */
				if (outchunkresent < 3) {
					outchunkresent++;
					send_chunk(dns_fd);
				} else {
					outpkt.offset = 0;
					outpkt.len = 0;
					outpkt.sentlen = 0;
					outchunkresent = 0;

					send_ping(dns_fd);
				}
			} else {
				send_ping(dns_fd);
			}
			send_ping_soon = 0;

		} else {

			if (sock_isset(tun_fd, &fds)) {
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets send_ping_soon=0. */
			}
			if (sock_isset(dns_fd, &fds)) {
				if (conn == CONN_DNS_NULL) {
					if (tunnel_dns(tun_fd, dns_fd) <= 0)
						continue;
				} else {
					if (tunnel_raw(tun_fd, dns_fd) <= 0)
						continue;
				}
			}
		}
	}

	return 0;
}

static void
send_login(sock_t fd, char *login, int len)
{
	char data[19];

	memset(data, 0, sizeof(data));
	data[0] = userid;
	memcpy(&data[1], login, MIN(len, 16));

	data[17] = (rand_seed >> 8) & 0xff;
	data[18] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'l', data, sizeof(data));
}

static void
send_fragsize_probe(sock_t fd, int fragsize)
{
	char probedata[256];
	char buf[4096];

	/*
	 * build a large query domain which is random and maximum size,
	 * will also take up maximal space in the return packet
	 */
	memset(probedata, MAX(1, rand_seed & 0xff), sizeof(probedata));
	probedata[1] = MAX(1, (rand_seed >> 8) & 0xff);
	rand_seed++;

	/* Note: must either be same, or larger, than send_chunk() */
	build_hostname(buf + 5, sizeof(buf) - 5, probedata, sizeof(probedata),
		       topdomain, dataenc, hostname_maxlen);

	fragsize &= 2047;

	buf[0] = 'r'; /* Probe downstream fragsize packet */
	buf[1] = b32_5to8((userid << 1) | ((fragsize >> 10) & 1));
	buf[2] = b32_5to8((fragsize >> 5) & 31);
	buf[3] = b32_5to8(fragsize & 31);
	buf[4] = 'd'; /* dummy to match send_chunk() */

	send_query(fd, buf);
}

static void
send_set_downstream_fragsize(sock_t fd, int fragsize)
{
	char data[5];

	data[0] = userid;
	data[1] = (fragsize & 0xff00) >> 8;
	data[2] = (fragsize & 0x00ff);
	data[3] = (rand_seed >> 8) & 0xff;
	data[4] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'n', data, sizeof(data));
}

static void
send_version(sock_t fd, uint32_t version)
{
	char data[6];

	data[0] = (version >> 24) & 0xff;
	data[1] = (version >> 16) & 0xff;
	data[2] = (version >> 8) & 0xff;
	data[3] = (version >> 0) & 0xff;

	data[4] = (rand_seed >> 8) & 0xff;
	data[5] = (rand_seed >> 0) & 0xff;

	rand_seed++;

	send_packet(fd, 'v', data, sizeof(data));
}

/* Add lower 15 bits of rand seed as base32,
 * followed by a dot and the tunnel domain and send */
static void
send_handshake_query(sock_t fd, char *prefix)
{
	char buf[300];
	char cmc_dot[5];

	cmc_dot[0] = b32_5to8((rand_seed >> 10) & 0x1f);
	cmc_dot[1] = b32_5to8((rand_seed >> 5) & 0x1f);
	cmc_dot[2] = b32_5to8((rand_seed) & 0x1f);
	cmc_dot[3] = '.';
	cmc_dot[4] = 0;
	rand_seed++;

	snprintf(buf, sizeof(buf), "%.60s%s%s", prefix, cmc_dot, topdomain);
	send_query(fd, buf);
}

static void
send_raw_udp_login(sock_t dns_fd, int seed)
{
	char buf[16];
	struct raw_msg msg = {
		.cmd = RAW_HDR_CMD_LOGIN,
		.userid = userid,
		.data = buf,
		.len = sizeof(buf),
	};
	login_calculate(buf, sizeof(buf), password, seed + 1);

	send_raw(dns_fd, &msg, &raw_serv);
}

static void
send_upenctest(sock_t fd, const char *s)
/* NOTE: String may be at most 63-4=59 chars to fit in 1 dns chunk. */
{
	char buf[512] = "z___";

	buf[1] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[2] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[3] = b32_5to8((rand_seed) & 0x1f);
	rand_seed++;

	strncat(buf, s, 128);
	strncat(buf, ".", 2);
	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, buf);
}

static void
send_downenctest(sock_t fd, char downenc, int variant)
{
	char prefix[4] = "y__";
	prefix[1] = ascii_tolower(downenc);
	prefix[2] = b32_5to8(variant);

	/* Use send_query directly if we ever send more data here. */
	send_handshake_query(fd, prefix);
}

static void
send_lazy_switch(sock_t fd)
{
	char sw_lazy[] = { 'o', b32_5to8(userid), 'i', 0 };

	if (lazymode)
		sw_lazy[2] = 'l';

	send_handshake_query(fd, sw_lazy);
}

static int
handshake_version(sock_t dns_fd, int *seed)
{
	char hex[] = "0123456789abcdef";
	char in[4096];
	uint32_t payload;
	int i;
	int read;

	for (i = 0; running && i < 5; i++) {

		send_version(dns_fd, PROTOCOL_VERSION);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'v', i+1);

		if (read >= 9) {
			payload = (((in[4] & 0xffU) << 24) |
					((in[5] & 0xffU) << 16) |
					((in[6] & 0xffU) << 8) |
					((in[7] & 0xffU)));

			if (strncmp("VACK", in, 4) == 0) {
				*seed = payload;
				userid = in[8];
				userid_char = hex[userid & 15];

				ui_log("Version ok, both using protocol v 0x%08x. You are user #%d\n",
					PROTOCOL_VERSION, userid);
				return 0;
			} else if (strncmp("VNAK", in, 4) == 0) {
				warnx("You use protocol v 0x%08x, server uses v 0x%08x. Giving up",
						PROTOCOL_VERSION, payload);
				return 1;
			} else if (strncmp("VFUL", in, 4) == 0) {
				warnx("Server full, all %d slots are taken. Try again later", payload);
				return 1;
			}
		} else if (read > 0)
			warnx("did not receive proper login challenge");

		ui_log("Retrying version check...\n");
	}
	warnx("couldn't connect to server (maybe other -T options will work)");
	return 1;
}

static int
handshake_login(sock_t dns_fd, int seed)
{
	char in[4096];
	char login[16];
	int mtu;
	int i;
	int read;

	login_calculate(login, 16, password, seed);

	for (i = 0; running && i < 5; i++) {

		send_login(dns_fd, login, 16);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'l', i+1);

		if (read > 0) {
			struct in_addr serveraddr;
			struct in_addr clientaddr;
			char server[65];
			char client[65];
			int netbits;

			if (strncmp("LNAK", in, 4) == 0) {
				ui_log("Bad password\n");
				return 1;
			} else if (strncmp("BADIP", in, 5) == 0) {
				warnx("BADIP: Server rejected sender IP address (maybe iodined -c will help)");
				return 1;
			} else if (sscanf(in, "%64[^-]-%64[^-]-%d-%d",
				   server, client, &mtu, &netbits) == 4) {
				server[64] = 0;
				client[64] = 0;
				if (netbits < 1 || netbits > 32) {
					ui_log("Received bad handshake (netbits %d)\n", netbits);
				} else if (inet_pton(AF_INET, client, &clientaddr) <= 0) {
					ui_log("Received bad client IP (%s)\n", client);
				} else if (inet_pton(AF_INET, server, &serveraddr) <= 0) {
					ui_log("Received bad server IP (%s)\n", server);
				} else if (tun_setip(&clientaddr,
						     &serveraddr, netbits) == 0 &&
					   tun_setmtu(mtu) == 0) {
					ui_log("Server tunnel IP is %s\n", server);
					return 0;
				} else {
					errx(4, "Failed to set IP and MTU");
				}
			} else {
				ui_log("Received malformed handshake\n");
			}
		}

		ui_log("Retrying login...\n");
	}
	warnx("couldn't login to server");
	return 1;
}

static int
handshake_raw_udp(sock_t dns_fd, int seed)
{
	char get_ip[] = { 'i', b32_5to8(userid), 0 };
	char in[4096];
	int i;
	int r;
	int len;
	int got_addr;

	memset(&raw_serv, 0, sizeof(raw_serv));
	got_addr = 0;

	ui_log_partial("Requesting server address to attempt raw UDP mode (skip with -r) ");
	for (i = 0; running && i < 3; i++) {

		send_handshake_query(dns_fd, get_ip);

		len = handshake_waitdns(dns_fd, in, sizeof(in), 'i', i+1);

		if (len == 5 && in[0] == 'I') {
			/* Received IPv4 address */
			struct sockaddr_in *raw4_serv = (struct sockaddr_in *) &raw_serv.remote.addr;
			raw4_serv->sin_family = AF_INET;
			memcpy(&raw4_serv->sin_addr, &in[1], sizeof(struct in_addr));
			raw4_serv->sin_port = htons(DNS_PORT);
			raw_serv.remote.addrlen = sizeof(struct sockaddr_in);
			got_addr = 1;
			break;
		}
		if (len == 17 && in[0] == 'I') {
			/* Received IPv6 address */
			struct sockaddr_in6 *raw6_serv = (struct sockaddr_in6 *) &raw_serv.remote.addr;
			raw6_serv->sin6_family = AF_INET6;
			memcpy(&raw6_serv->sin6_addr, &in[1], sizeof(struct in6_addr));
			raw6_serv->sin6_port = htons(DNS_PORT);
			raw_serv.remote.addrlen = sizeof(struct sockaddr_in6);
			got_addr = 1;
			break;
		}

		ui_log_partial(".");
	}
	ui_log("\n");
	if (!running)
		return 0;

	if (!got_addr) {
		ui_log("Failed to get raw server IP, will use DNS mode.\n");
		return 0;
	}
	ui_log_partial("Server is at %s, trying raw login: (skip with -r) ",
		client_get_raw_addr());

	/* do login against port 53 on remote server
	 * based on the old seed. If reply received,
	 * switch to raw udp mode */
	for (i = 0; running && i < 4; i++) {
		send_raw_udp_login(dns_fd, seed);

		r = sock_select((i + 1) * 1000, NULL, dns_fd);

		if (r > 0) {
			struct udp_addr address;
			struct raw_msg msg;
			len = read_udp(dns_fd, in, sizeof(in), &address);
			if (len > 0 && raw_decode(&msg, in, len) &&
				msg.cmd == RAW_HDR_CMD_LOGIN && msg.len >= 16) {
				char hash[16];
				login_calculate(hash, 16, password, seed - 1);
				if (memcmp(msg.data, hash, sizeof(hash)) == 0) {
					ui_log("OK\n");
					return 1;
				}
			}
		}
		ui_log_partial(".");
	}

	ui_log("failed\n");
	return 0;
}

static int
handshake_upenctest(sock_t dns_fd, const char *s)
/* NOTE: *s may be max 59 chars; must start with "aA" for case-swap check
   Returns:
   -1: case swap, no need for any further test: error printed; or Ctrl-C
   0: not identical or error or timeout
   1: identical string returned
*/
{
	char in[4096];
	unsigned char *uin = (unsigned char *) in;
	const unsigned char *us = (const unsigned char *) s;
	int i;
	int read;
	int slen;

	slen = strlen(s);
	for (i = 0; running && i < 3; i++) {

		send_upenctest(dns_fd, s);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'z', i+1);

		if (read == -2)
			return 0;	/* hard error */

		if (read > 0 && read < slen + 4)
			return 0;	/* reply too short (chars dropped) */

		if (read > 0) {
			int k;
#if 0
			/* in[56] = '@'; */
			/* in[56] = '_'; */
			/* if (in[29] == '\344') in[29] = 'a'; */
			in[read] = '\0';
			ui_log("BounceReply: >%s<\n", in);
#endif
			/* quick check if case swapped, to give informative error msg */
			if (in[4] == 'A') {
				ui_log("DNS queries get changed to uppercase, keeping upstream codec Base32\n");
				return -1;
			}
			if (in[5] == 'a') {
				ui_log("DNS queries get changed to lowercase, keeping upstream codec Base32\n");
				return -1;
			}

			for (k = 0; k < slen; k++) {
				if (in[k+4] != s[k]) {
					/* Definitely not reliable */
					if (in[k+4] >= ' ' && in[k+4] <= '~' &&
					    s[k] >= ' ' && s[k] <= '~') {
						ui_log("DNS query char '%c' gets changed into '%c'\n",
							s[k], in[k+4]);
					} else {
						ui_log("DNS query char 0x%02X gets changed into 0x%02X\n",
							(unsigned int) us[k],
							(unsigned int) uin[k+4]);
					}
					return 0;
				}
			}
			/* if still here, then all okay */
			return 1;
		}

		ui_log("Retrying upstream codec test...\n");
	}

	if (!running)
		return -1;

	/* timeout */
	return 0;
}

static int
handshake_upenc_autodetect(sock_t dns_fd)
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
	const char *pat64 = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ+0129-";
	const char *pat64u = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ_0129-";
	const char *pat128a = "aA-Aaahhh-Drink-mal-ein-J\344germeister-";
	const char *pat128b = "aA-La-fl\373te-na\357ve-fran\347aise-est-retir\351-\340-Cr\350te";
	const char *pat128c = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";
	const char *pat128d = "aA0123456789\274\275\276\277"
		"\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317";
	const char *pat128e="aA"
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
	ui_log("Keeping upstream codec Base32\n");
	return 0;
}

static int
handshake_downenctest(sock_t dns_fd, const struct encoder *trycodec)
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

	for (i = 0; running && i < 3; i++) {

		send_downenctest(dns_fd, trycodec->down_char, 1);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', i+1);

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

		ui_log("Retrying downstream codec test...\n");
	}

	/* timeout */
	return 0;
}

static const struct encoder *
handshake_downenc_autodetect(sock_t dns_fd)
{
	const struct encoder *selected = NULL;

	if (do_qtype == T_NULL || do_qtype == T_PRIVATE) {
		/* no other choice than raw */
		ui_log("No alternative downstream codec available, using default (Raw)\n");
		return NULL;
	}

	ui_log("Autodetecting downstream codec (use -O to override)\n");

	/* Try Base64 */
	if (handshake_downenctest(dns_fd, &base64_ops)) {
		selected = &base64_ops;
	} else if (running && handshake_downenctest(dns_fd, &base64u_ops)) {
		selected = &base64u_ops;
	}

	/* Try Base128 only if 64 gives us some perspective */
	if (running && selected) {
		if (handshake_downenctest(dns_fd, &base128_ops)) {
			selected = &base128_ops;

			/* If 128 works, then TXT may give us Raw as well */
			if (running && do_qtype == T_TXT) {
				if (handshake_downenctest(dns_fd, &raw_ops)) {
					selected = &raw_ops;
				}
			}
		}
	}

	if (!running)
		return NULL;

	if (selected) {
		return selected;
	}

	ui_log("No advanced downstream codecs seem to work, using default (Base32)\n");
	return NULL;
}

static int
handshake_qtypetest(sock_t dns_fd, int timeout)
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

	send_downenctest(dns_fd, trycodec, 1);

	read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', timeout);

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
handshake_qtype_autodetect(sock_t dns_fd)
/* Returns:
   0: okay, do_qtype set
   1: problem, program exit
*/
{
	int highestworking = 100;
	int timeout;
	int qtypenum;

	ui_log_partial("Autodetecting DNS query type (use -T to override)");

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

			ui_log_partial(".");

			if (handshake_qtypetest(dns_fd, timeout)) {
				/* okay */
				highestworking = qtypenum;
#if 0
				ui_log(" Type %s timeout %d works\n",
					client_get_qtype(), timeout);
#endif
				break;
				/* try others with longer timeout */
			}
			/* else: try next qtype with same timeout */
		}
		if (highestworking == 0)
			/* good, we have NULL; abort immediately */
			break;
	}

	ui_log("\n");

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
handshake_edns0_check(sock_t dns_fd)
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
	const struct encoder *codec;

	if (do_qtype == T_NULL || do_qtype == T_PRIVATE)
		codec = &raw_ops;
	else
		codec = &base32_ops;

	for (i = 0; running && i < 3; i++) {

		send_downenctest(dns_fd, codec->down_char, 1);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'y', i+1);

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

		ui_log("Retrying EDNS0 support test...\n");
	}

	/* timeout or Ctrl-C */
	return 0;
}

static void
handshake_switch_codec(sock_t dns_fd, int bits)
{
	char sw_codec[] = { 's', b32_5to8(userid), b32_5to8(bits), 0 };
	char in[4096];
	int i;
	int read;
	const struct encoder *tempenc;

	if (bits == 5)
		tempenc = &base32_ops;
	else if (bits == 6)
		tempenc = &base64_ops;
	else if (bits == 26)	/* "2nd" 6 bits per byte, with underscore */
		tempenc = &base64u_ops;
	else if (bits == 7)
		tempenc = &base128_ops;
	else return;

	ui_log("Switching upstream to codec %s\n", tempenc->name);

	for (i = 0; running && i < 5; i++) {

		send_handshake_query(dns_fd, sw_codec);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 's', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				ui_log("Server got bad message length. ");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				ui_log("Server rejected sender IP address. ");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				ui_log("Server rejected the selected codec. ");
				goto codec_revert;
			}
			ui_log("Server switched upstream to codec %s\n", in);
			dataenc = tempenc;
			return;
		}

		ui_log("Retrying codec switch...\n");
	}
	if (!running)
		return;

	ui_log("No reply from server on codec switch. ");

codec_revert:
	ui_log("Falling back to upstream codec %s\n", dataenc->name);
}

static void
handshake_switch_downenc(sock_t dns_fd)
{
	char sw_downenc[] = { 'o', b32_5to8(userid), downenc->down_char, 0 };
	char in[4096];
	int i;
	int read;

	ui_log("Switching downstream to codec %s\n", downenc->name);
	for (i = 0; running && i < 5; i++) {

		send_handshake_query(dns_fd, sw_downenc);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				ui_log("Server got bad message length. ");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				ui_log("Server rejected sender IP address. ");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				ui_log("Server rejected the selected codec. ");
				goto codec_revert;
			}
			ui_log("Server switched downstream to codec %s\n", in);
			return;
		}

		ui_log("Retrying codec switch...\n");
	}
	if (!running)
		return;

	ui_log("No reply from server on codec switch. ");

codec_revert:
	ui_log("Falling back to downstream codec Base32\n");
}

static void
handshake_try_lazy(sock_t dns_fd)
{
	char in[4096];
	int i;
	int read;

	ui_log("Switching to lazy mode for low-latency\n");
	for (i = 0; running && i < 5 ;i++) {

		send_lazy_switch(dns_fd);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', i+1);

		if (read > 0) {
			if (strncmp("BADLEN", in, 6) == 0) {
				ui_log("Server got bad message length. ");
				goto codec_revert;
			} else if (strncmp("BADIP", in, 5) == 0) {
				ui_log("Server rejected sender IP address. ");
				goto codec_revert;
			} else if (strncmp("BADCODEC", in, 8) == 0) {
				ui_log("Server rejected lazy mode. ");
				goto codec_revert;
			} else if (strncmp("Lazy", in, 4) == 0) {
				ui_log("Server switched to lazy mode\n");
				lazymode = 1;
				return;
			}
		}

		ui_log("Retrying lazy mode switch...\n");
	}
	if (!running)
		return;

	ui_log("No reply from server on lazy switch. ");

codec_revert:
	ui_log("Falling back to legacy mode\n");
	lazymode = 0;
	selecttimeout = 1;
}

static void
handshake_lazyoff(sock_t dns_fd)
/* Used in the middle of data transfer, timing is different and no error msgs */
{
	char in[4096];
	int i;
	int read;

	for (i = 0; running && i < 5; i++) {

		send_lazy_switch(dns_fd);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'o', 1);

		if (read == 9 && strncmp("Immediate", in, 9) == 0) {
			warnx("Server switched back to legacy mode.\n");
			lazymode = 0;
			selecttimeout = 1;
			return;
		}
	}
	if (!running)
		return;

	warnx("No reply from server on legacy mode switch.\n");
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
		ui_log_partial("got BADIP (Try iodined -c)..");
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
		ui_log("\n");
		warnx("corruption at byte 2, this won't work. Try -O Base32, or other -T options.");
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
		ui_log_partial("%d ok.. ", acked_fragsize);
		*max_fragsize = acked_fragsize;
		return 1;
	}

	if (downenc && downenc != &base32_ops) {
		ui_log("%d corrupted at %d.. (Try -O Base32)\n", acked_fragsize, i);
	} else {
		ui_log_partial("%d corrupted at %d.. ", acked_fragsize, i);
	}
	return 1;
}


static int
handshake_autoprobe_fragsize(sock_t dns_fd)
{
	char in[4096];
	int i;
	int read;
	int proposed_fragsize = 592;
	int range = 592;
	int max_fragsize;

	max_fragsize = 0;
	ui_log("Autoprobing max downstream fragment size... (skip with -m fragsize)\n");
	while (running && range > 0 && (range >= 8 || max_fragsize < 300)) {
		/* stop the slow probing early when we have enough bytes anyway */
		for (i = 0; running && i < 3; i++) {

			send_fragsize_probe(dns_fd, proposed_fragsize);

			read = handshake_waitdns(dns_fd, in, sizeof(in), 'r', 1);

			if (read > 0) {
				/* We got a reply */
				if (fragsize_check(in, read, proposed_fragsize, &max_fragsize) == 1)
					break;
			}

			ui_log_partial(".");
		}
		if (max_fragsize < 0)
			break;

		range >>= 1;
		if (max_fragsize == proposed_fragsize) {
			/* Try bigger */
			proposed_fragsize += range;
		} else {
			/* Try smaller */
			ui_log_partial("%d not ok.. ", proposed_fragsize);
			proposed_fragsize -= range;
		}
	}
	if (!running) {
		ui_log("\n");
		warnx("stopped while autodetecting fragment size (Try setting manually with -m)");
		return 0;
	}
	if (max_fragsize <= 2) {
		/* Tried all the way down to 2 and found no good size.
		   But we _did_ do all handshake before this, so there must
		   be some workable connection. */
		ui_log("\n");
		warnx("found no accepted fragment size.");
		warnx("try setting -M to 200 or lower, or try other -T or -O options.");
		return 0;
	}
	/* data header adds 2 bytes */
	ui_log("will use %d-2=%d\n", max_fragsize, max_fragsize - 2);

	/* need 1200 / 16frags = 75 bytes fragsize */
	if (max_fragsize < 82) {
		ui_log("Note: this probably won't work well.\n");
		ui_log("Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	} else if (max_fragsize < 202 &&
	    (do_qtype == T_NULL || do_qtype == T_PRIVATE || do_qtype == T_TXT ||
	     do_qtype == T_SRV || do_qtype == T_MX)) {
		ui_log("Note: this isn't very much.\n");
		ui_log("Try setting -M to 200 or lower, or try other DNS types (-T option).\n");
	}

	return max_fragsize - 2;
}

static void
handshake_set_fragsize(sock_t dns_fd, int fragsize)
{
	char in[4096];
	int i;
	int read;

	ui_log("Setting downstream fragment size to max %d...\n", fragsize);
	for (i = 0; running && i < 5; i++) {

		send_set_downstream_fragsize(dns_fd, fragsize);

		read = handshake_waitdns(dns_fd, in, sizeof(in), 'n', i+1);

		if (read > 0) {

			if (strncmp("BADFRAG", in, 7) == 0) {
				ui_log("Server rejected fragsize. Keeping default.\n");
				return;
			} else if (strncmp("BADIP", in, 5) == 0) {
				ui_log("Server rejected sender IP address.\n");
				return;
			}

			/* The server returns the accepted fragsize:
			accepted_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff) */
			return;
		}

		ui_log("Retrying set fragsize...\n");
	}
	if (!running)
		return;

	ui_log("No reply from server when setting fragsize. Keeping default.\n");
}

int
client_handshake(sock_t dns_fd, int raw_mode, int autodetect_frag_size, int fragsize)
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

	ui_log("Using DNS type %s queries\n", client_get_qtype());

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
		selecttimeout = 20;
	} else {
		if (raw_mode == 0) {
			ui_log("Skipping raw mode\n");
		}

		dnsc_use_edns0 = 1;
		if (handshake_edns0_check(dns_fd) && running) {
			ui_log("Using EDNS0 extension\n");
		} else if (!running) {
			return -1;
		} else {
			ui_log("DNS relay does not support EDNS0 extension\n");
			dnsc_use_edns0 = 0;
		}

		upcodec = handshake_upenc_autodetect(dns_fd);
		if (!running)
			return -1;

		if (upcodec == 1) {
			handshake_switch_codec(dns_fd, 6);
		} else if (upcodec == 2) {
			handshake_switch_codec(dns_fd, 26);
		} else if (upcodec == 3) {
			handshake_switch_codec(dns_fd, 7);
		}
		if (!running)
			return -1;

		if (!downenc) {
			downenc = handshake_downenc_autodetect(dns_fd);
		}
		if (!running)
			return -1;

		if (downenc) {
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

