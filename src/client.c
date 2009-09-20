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

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <zlib.h>
#include <time.h>

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <arpa/nameser.h>
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
#include "dns.h"
#include "login.h"
#include "tun.h"
#include "version.h"
#include "client.h"

static void handshake_lazyoff(int dns_fd);

static int running;
static const char *password;

static struct sockaddr_in nameserv;
static struct sockaddr_in raw_serv;
static const char *topdomain;

static uint16_t rand_seed;

/* Current up/downstream IP packet */
static struct packet outpkt;
static struct packet inpkt;
int outchunkresent = 0;

/* My userid at the server */
static char userid;
static char userid_char;		/* used when sending (uppercase) */
static char userid_char2;		/* also accepted when receiving (lowercase) */

/* DNS id for next packet */
static uint16_t chunkid;
static uint16_t chunkid_prev;
static uint16_t chunkid_prev2;

/* Base32 encoder used for non-data packets and replies */
static struct encoder *b32;
/* Base64 encoder for replies */
static struct encoder *b64;

/* The encoder used for data packets
 * Defaults to Base32, can be changed after handshake */
static struct encoder *dataenc;
  
/* The encoder to use for downstream data */
static char downenc = ' ';
 
/* set query type to send */
static unsigned short do_qtype = T_NULL;

/* My connection mode */
static enum connection conn;

int selecttimeout;		/* RFC says timeout minimum 5sec */

int lazymode;

long send_ping_soon;

time_t lastdownstreamtime;

void
client_init()
{
	running = 1;
	b32 = get_base32_encoder();
	b64 = get_base64_encoder();
	dataenc = get_base32_encoder();
	rand_seed = ((unsigned int) rand()) & 0xFFFF;
	send_ping_soon = 1;	/* send ping immediately after startup */
	conn = CONN_DNS_NULL;

	chunkid = ((unsigned int) rand()) & 0xFFFF;
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
client_set_nameserver(const char *cp, int port) 
{
	struct in_addr addr;

	if (inet_aton(cp, &addr) != 1)
		errx(1, "error parsing nameserver address: '%s'", cp);

	memset(&nameserv, 0, sizeof(nameserv));
	nameserv.sin_family = AF_INET;
	nameserv.sin_port = htons(port);
	nameserv.sin_addr = addr;
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

void
set_qtype(char *qtype)
{
	if (!strcasecmp(qtype, "NULL"))
      		do_qtype = T_NULL;
	else if (!strcasecmp(qtype, "CNAME"))
		do_qtype = T_CNAME;
	else if (!strcasecmp(qtype, "A"))
		do_qtype = T_A;
	else if (!strcasecmp(qtype, "MX"))
		do_qtype = T_MX;
	else if (!strcasecmp(qtype, "TXT"))
		do_qtype = T_TXT;
}

void
set_downenc(char *encoding)
{
	if (!strcasecmp(encoding, "base32"))
		downenc = 'T';
	else if (!strcasecmp(encoding, "base64"))
		downenc = 'S';
	else if (!strcasecmp(encoding, "raw"))
		downenc = 'R';
}

void 
client_set_selecttimeout(int select_timeout)
{
	selecttimeout = select_timeout;
}

void
client_set_lazymode(int lazy_mode) {
	lazymode = lazymode;
}

const char *
client_get_raw_addr()
{
	return inet_ntoa(raw_serv.sin_addr);
}

static void
send_query(int fd, char *hostname)
{
	char packet[4096];
	struct query q;
	size_t len;

	chunkid_prev2 = chunkid_prev;
	chunkid_prev = chunkid;
	chunkid += 7727;
	if (chunkid == 0)
		/* 0 is used as "no-query" in iodined.c */
		chunkid = 7727;

	q.id = chunkid;
	q.type = do_qtype;

	len = dns_encode(packet, sizeof(packet), &q, QR_QUERY, hostname, strlen(hostname));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	sendto(fd, packet, len, 0, (struct sockaddr*)&nameserv, sizeof(nameserv));
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
send_raw_data(int dns_fd)
{
	send_raw(dns_fd, outpkt.data, outpkt.len, userid, RAW_HDR_CMD_DATA);
	outpkt.len = 0;
}


static void
send_packet(int fd, char cmd, const char *data, const size_t datalen)
{
	char buf[4096];

	buf[0] = cmd;
	
	build_hostname(buf + 1, sizeof(buf) - 1, data, datalen, topdomain, b32);
	send_query(fd, buf);
}

static inline int
is_sending()
{
	return (outpkt.len != 0);
}

static void
send_chunk(int fd)
{
	char buf[4096];
	int avail;
	int code;
	char *p;

	p = outpkt.data;
	p += outpkt.offset;
	avail = outpkt.len - outpkt.offset;

	outpkt.sentlen = build_hostname(buf + 4, sizeof(buf) - 4, p, avail, topdomain, dataenc);

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */

	buf[0] = userid_char;		/* First byte is hex userid */
  
	code = ((outpkt.seqno & 7) << 2) | ((outpkt.fragment & 15) >> 2);
	buf[1] = b32_5to8(code); /* Second byte is 3 bits seqno, 2 upper bits fragment count */

	code = ((outpkt.fragment & 3) << 3) | (inpkt.seqno & 7);
	buf[2] = b32_5to8(code); /* Third byte is 2 bits lower fragment count, 3 bits downstream packet seqno */

	code = ((inpkt.fragment & 15) << 1) | (outpkt.sentlen == avail);
	buf[3] = b32_5to8(code); /* Fourth byte is 4 bits downstream fragment count, 1 bit last frag flag */
  
#if 0
	fprintf(stderr, "  Send: down %d/%d up %d/%d, %d bytes\n",
		inpkt.seqno, inpkt.fragment, outpkt.seqno, outpkt.fragment,
		outpkt.sentlen);
#endif

	send_query(fd, buf);
}

static void
send_ping(int fd)
{
	if (conn == CONN_DNS_NULL) {
		char data[4];
		
		data[0] = userid;
		data[1] = ((inpkt.seqno & 7) << 4) | (inpkt.fragment & 15);
		data[2] = (rand_seed >> 8) & 0xff;
		data[3] = (rand_seed >> 0) & 0xff;
		
		rand_seed++;

#if 0
		fprintf(stderr, "  Send: down %d/%d         (ping)\n",
			inpkt.seqno, inpkt.fragment);
#endif

		send_packet(fd, 'p', data, sizeof(data));
	} else {
		send_raw(fd, NULL, 0, userid, RAW_HDR_CMD_PING);
	}
}

static int
read_dns_withq(int dns_fd, int tun_fd, char *buf, int buflen, struct query *q) /* FIXME: tun_fd needed for raw handling */
{
	struct sockaddr_in from;
	char data[64*1024];
	socklen_t addrlen;
	int r;

	addrlen = sizeof(struct sockaddr);
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

		rv = dns_decode(buf, buflen, q, QR_ANSWER, data, r);
		if (rv <= 0)
			return rv;

		if (q->type == T_CNAME || q->type == T_MX || q->type == T_TXT)
		/* CNAME an also be returned from an A (or MX) question */
		{
			size_t space;

			/*
			 * buf is a hostname or txt stream that we still need to
			 * decode to binary
			 * 
			 * also update rv with the number of valid bytes
			 * 
			 * data is unused here, and will certainly hold the smaller binary
			 */

			switch (buf[0]) {
			case 'h': /* Hostname with base32 */
			case 'H':
				if (rv < 5) {
					/* 1 byte H, 3 bytes ".xy", >=1 byte data */
					rv = 0;
					break;
				}

				rv -= 3;	/* rv=strlen, strip ".xy" */
				rv = unpack_data (data, sizeof(data), buf + 1, rv - 1, b32);
				/* this also does undotify */

				rv = MIN(rv, buflen);
				memcpy(buf, data, rv);
				break;
			case 'i': /* Hostname++ with base64 */
			case 'I':
				if (rv < 5) {
					/* 1 byte H, 3 bytes ".xy", >=1 byte data */
					rv = 0;
					break;
				}

				rv -= 3;	/* rv=strlen, strip ".xy" */
				rv = unpack_data (data, sizeof(data), buf + 1, rv - 1, b64);
				/* this also does undotify */

				rv = MIN(rv, buflen);
				memcpy(buf, data, rv);
				break;
			case 't': /* plain base32(Thirty-two) from TXT */
			case 'T':
				if (rv < 2) {
					rv = 0;
					break;
				}

				space = sizeof(data);
				rv = b32->decode (data, &space, buf + 1, rv - 1);
				rv = MIN(rv, buflen);
				memcpy(buf, data, rv);
				break;
			case 's': /* plain base64(Sixty-four) from TXT */
			case 'S':
				if (rv < 2) {
					rv = 0;
					break;
				}

				space = sizeof(data);
				rv = b64->decode (data, &space, buf + 1, rv - 1);
				rv = MIN(rv, buflen);
				memcpy(buf, data, rv);
				break;
			case 'r': /* Raw binary from TXT */
			case 'R':
				rv--;			/* rv>=1 already checked */
				memmove(buf, buf+1, rv);
				break;
			default:
				warnx("Received unsupported encoding");
				rv = 0;
				break;
			}
		}

		return rv;
	} else { /* CONN_RAW_UDP */
		unsigned long datalen;
		char buf[64*1024];

		/* minimum length */
		if (r < RAW_HDR_LEN) return 0;
		/* should start with header */
		if (memcmp(data, raw_header, RAW_HDR_IDENT_LEN)) return 0;
		/* should be data packet */
		if (RAW_HDR_GET_CMD(data) != RAW_HDR_CMD_DATA) return 0;
		/* should be my user id */
		if (RAW_HDR_GET_USR(data) != userid) return 0;

		r -= RAW_HDR_LEN;
		datalen = sizeof(buf);
		if (uncompress((uint8_t*)buf, &datalen, (uint8_t*) &data[RAW_HDR_LEN], r) == Z_OK) {
			write_tun(tun_fd, buf, datalen);
		}
		return 0;
	}
}

static inline int
read_dns_namecheck(int dns_fd, int tun_fd, char *buf, int buflen, char c1, char c2)
/* Only returns >0 when the query hostname in the received packet matches
   either c1 or c2; used to tell handshake-dupes apart.
*/
{
	struct query q;
	int rv;

	rv = read_dns_withq(dns_fd, tun_fd, buf, buflen, &q);

	if (rv > 0 && q.name[0] != c1 && q.name[0] != c2)
		return 0;

	return rv;	/* may also be 0 = useless or -1 = error (printed) */
}

static int
tunnel_tun(int tun_fd, int dns_fd)
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
		send_raw_data(dns_fd);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	static long packrecv = 0;
	static long packrecv_oos = 0;
	int up_ack_seqno;
	int up_ack_fragment;
	int new_down_seqno;
	int new_down_fragment;
	struct query q;
	unsigned long datalen;
	char buf[64*1024];
	int read;
	int send_something_now = 0;

	if ((read = read_dns_withq(dns_fd, tun_fd, buf, sizeof(buf), &q)) < 2) {
		/* Maybe SERVFAIL etc. Send ping to get things back in order,
		   but wait a bit to prevent fast ping-pong loops. */
		send_ping_soon = 900;
		return -1;	/* nothing done */
	}

	/* Don't process anything that isn't data; already checked read>=2 */
	if (q.name[0] != 'P' && q.name[0] != 'p' &&
	    q.name[0] != userid_char && q.name[0] != userid_char2)
		return -1;	/* nothing done */

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
	fprintf(stderr, "					Recv: down %d/%d up %d/%d, %d bytes\n",
		new_down_seqno, new_down_fragment, up_ack_seqno,
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

	packrecv++;

	/* Don't process any non-recent stuff any further */
	if (q.id != chunkid && q.id != chunkid_prev && q.id != chunkid_prev2) {
		packrecv_oos++;
#if 0
		fprintf(stderr, "   q=%c Packs received = %8ld  Out-of-sequence = %8ld\n", q.name[0], packrecv, packrecv_oos);
#endif
		if (lazymode && packrecv < 600 && packrecv_oos == 5)
			warnx("Hmm, getting some out-of-sequence DNS replies. You may want to try -I1 or -L0 if you notice hiccups in the data traffic.");
		if (lazymode && packrecv < 600 && packrecv_oos == 15) {
			warnx("Your DNS server connection causes severe re-ordering of DNS traffic. Lazy mode doesn't work well here, switching off. Next time on this network, start with -L0.");
			lazymode = 0;
			selecttimeout = 1;
			handshake_lazyoff(dns_fd);
		}

		if (send_something_now) {
			send_ping(dns_fd);
			send_ping_soon = 0;
		}
		return -1;	/* nothing done */
	}
#if 0
	fprintf(stderr, "   q=%c Packs received = %8ld  Out-of-sequence = %8ld\n", q.name[0], packrecv, packrecv_oos);
#endif

	/* Okay, we have a recent downstream packet */
	lastdownstreamtime = time(NULL);

	/* In lazy mode, we shouldn't get much replies to our most-recent
	   query, only during heavy data transfer. Except when severe packet
	   reordering occurs, such as opendns... Since this means the server
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

		datalen = MIN(read - 2, sizeof(inpkt.data) - inpkt.len);

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
		fprintf(stderr, "Got ack for %d,%d - expecting %d,%d - id=%d cur=%d prev=%d prev2=%d\n",
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
client_tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
	int rv;
	int i;

	rv = 0;
	lastdownstreamtime = time(NULL);

	while (running) {
		tv.tv_sec = selecttimeout;
		tv.tv_usec = 0;

		if (is_sending()) {
			/* fast timeout for retransmits */
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}

		if (send_ping_soon) {
			tv.tv_sec = 0;
			tv.tv_usec = send_ping_soon * 1000;
		}

		FD_ZERO(&fds);
		if (!is_sending() || outchunkresent >= 2) {
			/* If re-sending upstream data, chances are that
			   we're several seconds behind already and TCP
			   will start filling tun buffer with (useless)
			   retransmits.
			   Get up-to-date fast by simply dropping stuff,
			   that's what TCP is designed to handle. */
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);

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

			if (FD_ISSET(tun_fd, &fds)) {
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets send_ping_soon=0. */
			}
			if (FD_ISSET(dns_fd, &fds)) {
				if (tunnel_dns(tun_fd, dns_fd) <= 0)
					continue;
			} 
		}
	}

	return rv;
}

static void
send_login(int fd, char *login, int len)
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
send_fragsize_probe(int fd, int fragsize)
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
	build_hostname(buf + 4, sizeof(buf) - 4, probedata, sizeof(probedata), topdomain, dataenc);

	fragsize &= 2047;

	buf[0] = 'r'; /* Probe downstream fragsize packet */
	buf[1] = b32_5to8((userid << 1) | ((fragsize >> 10) & 1));
	buf[2] = b32_5to8((fragsize >> 5) & 31);
	buf[3] = b32_5to8(fragsize & 31);

	send_query(fd, buf);
}

static void
send_set_downstream_fragsize(int fd, int fragsize)
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
send_version(int fd, uint32_t version)
{
	char data[6];
 
	data[0] = (version >> 24) & 0xff;
	data[1] = (version >> 16) & 0xff;
	data[2] = (version >> 8) & 0xff;
	data[3] = (version >> 0) & 0xff;

	data[4] = (rand_seed >> 8) & 0xff;
	data[5] = (rand_seed >> 0) & 0xff;
	
	rand_seed++;

	send_packet(fd, 'V', data, sizeof(data));
}

static void
send_ip_request(int fd, int userid)
{
	char buf[512] = "I____.";
	buf[1] = b32_5to8(userid);
	
	buf[2] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[3] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[4] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
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
send_case_check(int fd)
{
	/* The '+' plus character is not allowed according to RFC. 
	 * Expect to get SERVFAIL or similar if it is rejected.
	 */
	char buf[512] = "zZ+-aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyY1234.";

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, buf);
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
	send_query(fd, buf);
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
	send_query(fd, buf);
}

static void
send_lazy_switch(int fd, int userid)
{
	char buf[512] = "o__.";
	buf[1] = b32_5to8(userid);

	if (lazymode)
		buf[2] = 'l';
	else
		buf[2] = 'i';

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, buf);
}

static int
handshake_version(int dns_fd, int *seed)
{
	char hex[] = "0123456789abcdef";
	char hex2[] = "0123456789ABCDEF";
	struct timeval tv;
	char in[4096];
	fd_set fds;
	uint32_t payload;
	int i;
	int r;
	int read;

	for (i = 0; running && i < 5; i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_version(dns_fd, VERSION);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'v', 'V');

			if(read <= 0)
				continue;

			if (read >= 9) {
				payload =  (((in[4] & 0xff) << 24) |
						((in[5] & 0xff) << 16) |
						((in[6] & 0xff) << 8) |
						((in[7] & 0xff)));

				if (strncmp("VACK", in, 4) == 0) {
					*seed = payload;
					userid = in[8];
					userid_char = hex[userid & 15];
					userid_char2 = hex2[userid & 15];

					fprintf(stderr, "Version ok, both using protocol v 0x%08x. You are user #%d\n", VERSION, userid);
					return 0;
				} else if (strncmp("VNAK", in, 4) == 0) {
					warnx("You use protocol v 0x%08x, server uses v 0x%08x. Giving up", 
							VERSION, payload);
					return 1;
				} else if (strncmp("VFUL", in, 4) == 0) {
					warnx("Server full, all %d slots are taken. Try again later", payload);
					return 1;
				}
			} else 
				warnx("did not receive proper login challenge");
		}
		
		fprintf(stderr, "Retrying version check...\n");
	}
	warnx("couldn't connect to server (maybe other -T options will work)");
	return 1;
}

static int
handshake_login(int dns_fd, int seed)
{
	struct timeval tv;
	char in[4096];
	char login[16];
	char server[65];
	char client[65];
	int mtu;
	fd_set fds;
	int i;
	int r;
	int read;

	login_calculate(login, 16, password, seed);
	
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_login(dns_fd, login, 16);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'l', 'L');

			if(read <= 0)
				continue;

			if (read > 0) {
				int netmask;
				if (strncmp("LNAK", in, 4) == 0) {
					fprintf(stderr, "Bad password\n");
					return 1;
				} else if (sscanf(in, "%64[^-]-%64[^-]-%d-%d", 
					server, client, &mtu, &netmask) == 4) {
					
					server[64] = 0;
					client[64] = 0;
					if (tun_setip(client, netmask) == 0 && 
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
	unsigned remoteaddr = 0;
	struct in_addr server;

	fprintf(stderr, "Testing raw UDP data to the server (skip with -r)\n");
	for (i=0; running && i<3 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_ip_request(dns_fd, userid);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			len = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'i', 'I');
			if (len == 5 && in[0] == 'I') {
				/* Received IP address */
				remoteaddr = (in[1] & 0xff);
				remoteaddr <<= 8;
				remoteaddr |= (in[2] & 0xff);
				remoteaddr <<= 8;
				remoteaddr |= (in[3] & 0xff);
				remoteaddr <<= 8;
				remoteaddr |= (in[4] & 0xff);
				server.s_addr = ntohl(remoteaddr);
				break;
			}
		} else {
			fprintf(stderr, ".");
			fflush(stderr);
		}
	}
	
	if (!remoteaddr) {
		fprintf(stderr, "Failed to get raw server IP, will use DNS mode.\n");
		return 0;
	}
	fprintf(stderr, "Server is at %s, trying raw login: ", inet_ntoa(server));
	fflush(stderr);

	/* Store address to iodined server */
	memset(&raw_serv, 0, sizeof(raw_serv));
	raw_serv.sin_family = AF_INET;
	raw_serv.sin_port = htons(53);
	raw_serv.sin_addr = server;

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
handshake_case_check(int dns_fd)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;
	int case_preserved;

	case_preserved = 0;
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_case_check(dns_fd);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'z', 'Z');
			
			if (read > 0) {
				if (read < (27 * 2)) {
					fprintf(stderr, "Received short case check reply. Will use base32 encoder\n");
					return case_preserved;
				} else {
					int k;

					/* TODO enhance this, base128 is probably also possible */
					case_preserved = 1;
					for (k = 0; k < 27 && case_preserved; k += 2) {
						if (in[k] == in[k+1]) {
							/* test string: zZ+-aAbBcCdDeE... */
							case_preserved = 0;
						}
					}
					return case_preserved;
				}
			} else {
				fprintf(stderr, "Got error on case check, will use base32\n");
				return case_preserved;
			}
		}

		fprintf(stderr, "Retrying case check...\n");
	}

	fprintf(stderr, "No reply on case check, continuing\n");
	return case_preserved;
}

static void
handshake_switch_codec(int dns_fd)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;

	dataenc = get_base64_encoder();
	fprintf(stderr, "Switching upstream to %s codec\n", dataenc->name);
	/* Send to server that this user will use base64 from now on */
	for (i=0; running && i<5 ;i++) {
		int bits;
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		bits = 6; /* base64 = 6 bits per byte */

		send_codec_switch(dns_fd, userid, bits);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 's', 'S');
			
			if (read > 0) {
				if (strncmp("BADLEN", in, 6) == 0) {
					fprintf(stderr, "Server got bad message length. ");
					goto codec_revert;
				} else if (strncmp("BADIP", in, 5) == 0) {
					fprintf(stderr, "Server rejected sender IP address. ");
					goto codec_revert;
				} else if (strncmp("BADCODEC", in, 8) == 0) {
					fprintf(stderr, "Server rejected the selected codec. ");
					goto codec_revert;
				}
				in[read] = 0; /* zero terminate */
				fprintf(stderr, "Server switched upstream to codec %s\n", in);
				return;
			}
		}
		fprintf(stderr, "Retrying codec switch...\n");
	}
	fprintf(stderr, "No reply from server on codec switch. ");

codec_revert: 
	fprintf(stderr, "Falling back to base32\n");
	dataenc = get_base32_encoder();
}

static void
handshake_switch_downenc(int dns_fd)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;
	char *dname;

	dname = "Base32";
	if (downenc == 'S')
		dname = "Base64";
	else if (downenc == 'R')
		dname = "Raw";

	fprintf(stderr, "Switching downstream to codec %s\n", dname);
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_downenc_switch(dns_fd, userid);

		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'o', 'O');

			if (read > 0) {
				if (strncmp("BADLEN", in, 6) == 0) {
					fprintf(stderr, "Server got bad message length. ");
					goto codec_revert;
				} else if (strncmp("BADIP", in, 5) == 0) {
					fprintf(stderr, "Server rejected sender IP address. ");
					goto codec_revert;
				} else if (strncmp("BADCODEC", in, 8) == 0) {
					fprintf(stderr, "Server rejected the selected codec. ");
					goto codec_revert;
				}
				in[read] = 0; /* zero terminate */
				fprintf(stderr, "Server switched downstream to codec %s\n", in);
				return;
			}
		}
		fprintf(stderr, "Retrying codec switch...\n");
	}
	fprintf(stderr, "No reply from server on codec switch. ");

codec_revert: 
	fprintf(stderr, "Falling back to base32\n");
}

static void
handshake_try_lazy(int dns_fd)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;

	fprintf(stderr, "Switching to lazy mode for low-latency\n");
	for (i=0; running && i<3; i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_lazy_switch(dns_fd, userid);

		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'o', 'O');

			if (read > 0) {
				if (strncmp("BADLEN", in, 6) == 0) {
					fprintf(stderr, "Server got bad message length. ");
					goto codec_revert;
				} else if (strncmp("BADIP", in, 5) == 0) {
					fprintf(stderr, "Server rejected sender IP address. ");
					goto codec_revert;
				} else if (strncmp("BADCODEC", in, 8) == 0) {
					fprintf(stderr, "Server rejected lazy mode. ");
					goto codec_revert;
				} else if (strncmp("Lazy", in, 4) == 0) {
					fprintf(stderr, "Server switched to lazy mode\n");
					lazymode = 1;
					return;
				}
			}
		}
		fprintf(stderr, "Retrying lazy mode switch...\n");
	}
	fprintf(stderr, "No reply from server on lazy switch, probably old server version. ");

codec_revert: 
	fprintf(stderr, "Falling back to legacy mode\n");
	lazymode = 0;
	selecttimeout = 1;
}

static void
handshake_lazyoff(int dns_fd)
/* Used in the middle of data transfer, timing is different and no error msgs */
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;

	for (i=0; running && i<5; i++) {
		tv.tv_sec = 0;
		tv.tv_usec = 500000;

		send_lazy_switch(dns_fd, userid);

		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'o', 'O');

			if (read > 0) {
				if (read == 4 && strncmp("Immediate", in, 9) == 0) {
					fprintf(stderr, "Server switched back to legacy mode.\n");
					lazymode = 0;
					selecttimeout = 1;
					return;
				}
			}
		}
	}
}

static int
fragsize_check(char *in, int read, int proposed_fragsize, int *max_fragsize)
/* Returns: 0: keep checking, 1: break loop (either okay or definitely wrong) */
{
	int acked_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff);
	static int nocheck_warned = 0;

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

	/* Check for corruption */
	if ((in[2] & 0xff) == 107) {
		int okay = 1;
		int i;
		unsigned int v = in[3] & 0xff;

		for (i = 3; i < read; i++, v += 107)
			if ((in[i] & 0xff) != (v & 0xff)) {
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
				fflush(stderr);
			}
			return 1;
		}
	}		/* always returns */

	/* here when uncheckable, so assume correct */

	if (read >= 3 && nocheck_warned == 0) {
		fprintf(stderr, "(Old server version, cannot check for corruption)\n");
		fflush(stderr);
		nocheck_warned = 1;
	}
	fprintf(stderr, "%d ok.. ", acked_fragsize);
	fflush(stderr);
	*max_fragsize = acked_fragsize;
	return 1;
}


static int
handshake_autoprobe_fragsize(int dns_fd)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;
	int proposed_fragsize = 768;
	int range = 768;
	int max_fragsize;

	max_fragsize = 0;
	fprintf(stderr, "Autoprobing max downstream fragment size... (skip with -m fragsize)\n"); 
	while (running && range > 0 && (range >= 8 || max_fragsize < 300)) {
		/* stop the slow probing early when we have enough bytes anyway */
		for (i=0; running && i<3 ;i++) {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			send_fragsize_probe(dns_fd, proposed_fragsize);

			FD_ZERO(&fds);
			FD_SET(dns_fd, &fds);

			r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

			if(r > 0) {
				read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'r', 'R');
				
				if (read > 0) {
					/* We got a reply */
					if (fragsize_check(in, read, proposed_fragsize, &max_fragsize) == 1)
						break;
				}
			}
			fprintf(stderr, ".");
			fflush(stderr);
		}
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
		fprintf(stderr, "\n");
		warnx("stopped while autodetecting fragment size (Try setting manually with -m)");
		return 0;
	}
	if (max_fragsize <= 2) {
		/* Tried all the way down to 2 and found no good size */
		fprintf(stderr, "\n");
		warnx("found no accepted fragment size. (Try forcing with -m, or try other -T or -O options)");
		return 0;
	}
	/* data header adds 2 bytes */
	fprintf(stderr, "will use %d-2=%d\n", max_fragsize, max_fragsize - 2);

	if (do_qtype != T_NULL && downenc == ' ')
		fprintf(stderr, "(Maybe other -O options will increase throughput)\n");

	return max_fragsize - 2;
}

static void
handshake_set_fragsize(int dns_fd, int fragsize)
{
	struct timeval tv;
	char in[4096];
	fd_set fds;
	int i;
	int r;
	int read;

	fprintf(stderr, "Setting downstream fragment size to max %d...\n", fragsize);
	for (i=0; running && i<5 ;i++) {
		tv.tv_sec = i + 1;
		tv.tv_usec = 0;

		send_set_downstream_fragsize(dns_fd, fragsize);
		
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);

		r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

		if(r > 0) {
			read = read_dns_namecheck(dns_fd, 0, in, sizeof(in), 'n', 'N');
			
			if (read > 0) {
				int accepted_fragsize;

				if (strncmp("BADFRAG", in, 7) == 0) {
					fprintf(stderr, "Server rejected fragsize. Keeping default.");
					return;
				} else if (strncmp("BADIP", in, 5) == 0) {
					fprintf(stderr, "Server rejected sender IP address.\n");
					return;
				}

				accepted_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff);
				return;
			}
		}
		fprintf(stderr, "Retrying set fragsize...\n");
	}
	fprintf(stderr, "No reply from server when setting fragsize. Keeping default.\n");
}

int
client_handshake(int dns_fd, int raw_mode, int autodetect_frag_size, int fragsize)
{
	int seed;
	int case_preserved;
	int r;

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
			fprintf(stderr, "Skipping raw mode\n");
		}
		case_preserved = handshake_case_check(dns_fd);

		if (case_preserved) {
			handshake_switch_codec(dns_fd);
		}

		if (downenc != ' ') {
			handshake_switch_downenc(dns_fd);
		}

		if (lazymode) {
			handshake_try_lazy(dns_fd);
		}

		if (autodetect_frag_size) {
			fragsize = handshake_autoprobe_fragsize(dns_fd);
			if (!fragsize) {
				return 1;
			}
		}

		handshake_set_fragsize(dns_fd, fragsize);
	}

	return 0;
}

