/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
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

#include "common.h"

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#define _XPG4_2
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <grp.h>
#include <sys/uio.h>
#include <pwd.h>
#include <netdb.h>
#include <syslog.h>
#endif

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
#include "version.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#endif

#define PASSWORD_ENV_VAR "IODINED_PASS"

static int running = 1;
static char *topdomain;
static char password[33];
static struct encoder *b32;
static struct encoder *b64;
static struct encoder *b64u;
static struct encoder *b128;
static int created_users;

static int check_ip;
static int my_mtu;
static in_addr_t my_ip;
static int netmask;

static in_addr_t ns_ip;

static int bind_port;
static int debug;

#if !defined(BSD) && !defined(__GLIBC__)
static char *__progname;
#endif

static int read_dns(int, int, struct query *);
static void write_dns(int, struct query *, char *, int, char);
static void handle_full_packet(int, int, int);

/* Ask externalip.net webservice to get external ip */
static int get_external_ip(struct in_addr *ip)
{
	int sock;
	struct addrinfo *addr;
	int res;
	const char *getstr = "GET /ip/ HTTP/1.0\r\n"
		/* HTTP 1.0 to avoid chunked transfer coding */
		"Host: api.externalip.net\r\n\r\n";
	char buf[512];
	char *b;
	int len;

	res = getaddrinfo("api.externalip.net", "80", NULL, &addr);
	if (res < 0) return 1;

	sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (sock < 0) {
		freeaddrinfo(addr);
		return 2;
	}

	res = connect(sock, addr->ai_addr, addr->ai_addrlen);
	freeaddrinfo(addr);
	if (res < 0) return 3;

	res = write(sock, getstr, strlen(getstr));
	if (res != strlen(getstr)) return 4;

	/* Zero buf before receiving, leave at least one zero at the end */
	memset(buf, 0, sizeof(buf));
	res = read(sock, buf, sizeof(buf) - 1);
	if (res < 0) return 5;
	len = res;

	res = close(sock);
	if (res < 0) return 6;

	b = buf;
	while (len > 9) {
		/* Look for split between headers and data */
		if (strncmp("\r\n\r\n", b, 4) == 0) break;
		b++;
		len--;
	}
	if (len < 10) return 7;
	b += 4;

	res = inet_aton(b, ip);
	return (res == 0);
}

static void
sigint(int sig)
{
	running = 0;
}

#ifdef WINDOWS32
#define	LOG_EMERG	0
#define	LOG_ALERT	1
#define	LOG_CRIT	2
#define	LOG_ERR		3
#define	LOG_WARNING	4
#define	LOG_NOTICE	5
#define	LOG_INFO	6
#define	LOG_DEBUG	7
static void
syslog(int a, const char *str, ...)
{
	/* TODO: implement (add to event log), move to common.c */
	;
}
#endif

/* This will not check that user has passed login challenge */
static int
check_user_and_ip(int userid, struct query *q)
{
	struct sockaddr_in *tempin;

	/* Note: duplicate in handle_raw_login() except IP-address check */

	if (userid < 0 || userid >= created_users ) {
		return 1;
	}
	if (!users[userid].active || users[userid].disabled) {
		return 1;
	}
	if (users[userid].last_pkt + 60 < time(NULL)) {
		return 1;
	}

	/* return early if IP checking is disabled */
	if (!check_ip) {
		return 0;
	}

	tempin = (struct sockaddr_in *) &(q->from);
	return memcmp(&(users[userid].host), &(tempin->sin_addr), sizeof(struct in_addr));
}

/* This checks that user has passed normal (non-raw) login challenge */
static int
check_authenticated_user_and_ip(int userid, struct query *q)
{
	int res = check_user_and_ip(userid, q);
	if (res)
		return res;

	if (!users[userid].authenticated)
		return 1;

	return 0;
}

static void
send_raw(int fd, char *buf, int buflen, int user, int cmd, struct query *q)
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

	if (debug >= 2) {
		fprintf(stderr, "TX-raw: client %s, cmd %d, %d bytes\n",
			format_addr(&q->from, q->fromlen), cmd, len);
	}

	sendto(fd, packet, len, 0, (struct sockaddr *) &q->from, q->fromlen);
}


static void
start_new_outpacket(int userid, char *data, int datalen)
/* Copies data to .outpacket and resets all counters.
   data is expected to be compressed already. */
{
	datalen = MIN(datalen, sizeof(users[userid].outpacket.data));
	memcpy(users[userid].outpacket.data, data, datalen);
	users[userid].outpacket.len = datalen;
	users[userid].outpacket.offset = 0;
	users[userid].outpacket.sentlen = 0;
	users[userid].outpacket.seqno = (users[userid].outpacket.seqno + 1) & 7;
	users[userid].outpacket.fragment = 0;
	users[userid].outfragresent = 0;
}

#ifdef OUTPACKETQ_LEN

static int
save_to_outpacketq(int userid, char *data, int datalen)
/* Find space in outpacket-queue and store data (expected compressed already).
   Returns: 1 = okay, 0 = no space. */
{
	int fill;

	if (users[userid].outpacketq_filled >= OUTPACKETQ_LEN)
		/* no space */
		return 0;

	fill = users[userid].outpacketq_nexttouse +
	       users[userid].outpacketq_filled;
	if (fill >= OUTPACKETQ_LEN)
		fill -= OUTPACKETQ_LEN;

	datalen = MIN(datalen, sizeof(users[userid].outpacketq[fill].data));
	memcpy(users[userid].outpacketq[fill].data, data, datalen);
	users[userid].outpacketq[fill].len = datalen;

	users[userid].outpacketq_filled++;

	if (debug >= 3)
		fprintf(stderr, "    Qstore, now %d\n",
			users[userid].outpacketq_filled);

	return 1;
}

static int
get_from_outpacketq(int userid)
/* Starts new outpacket from queue, if any.
   Returns: 1 = okay, 0 = no packets were waiting. */
{
	int use;

	if (users[userid].outpacketq_filled <= 0)
		/* no packets */
		return 0;

	use = users[userid].outpacketq_nexttouse;

	start_new_outpacket(userid, users[userid].outpacketq[use].data,
			    users[userid].outpacketq[use].len);

	use++;
	if (use >= OUTPACKETQ_LEN)
		use = 0;
	users[userid].outpacketq_nexttouse = use;
	users[userid].outpacketq_filled--;

	if (debug >= 3)
		fprintf(stderr, "    Qget, now %d\n",
			users[userid].outpacketq_filled);

	return 1;
}

#endif /* OUTPACKETQ_LEN */

#ifdef DNSCACHE_LEN

/* On the DNS cache:

   This cache is implemented to better handle the aggressively impatient DNS
   servers that very quickly re-send requests when we choose to not
   immediately answer them in lazy mode. This cache works much better than
   pruning(=dropping) the improper requests, since the DNS server will
   actually get an answer instead of silence.

   Because of the CMC in both ping and upstream data, unwanted cache hits
   are prevented. Data-CMC is only 36 counts, so our cache length should
   not exceed 36/2=18 packets. (This quick rule assumes all packets are
   otherwise equal, which they arent: up/downstream seq/frag, tcp sequence
   number, and of course data.)
*/

static void
save_to_dnscache(int userid, struct query *q, char *answer, int answerlen)
/* Store answer in our little DNS cache. */
{
	int fill;

	if (answerlen > sizeof(users[userid].dnscache_answer[fill]))
		return;  /* can't store this */

	fill = users[userid].dnscache_lastfilled + 1;
	if (fill >= DNSCACHE_LEN)
		fill = 0;

	memcpy(&(users[userid].dnscache_q[fill]), q, sizeof(struct query));
	memcpy(users[userid].dnscache_answer[fill], answer, answerlen);
	users[userid].dnscache_answerlen[fill] = answerlen;

	users[userid].dnscache_lastfilled = fill;
}

static int
answer_from_dnscache(int dns_fd, int userid, struct query *q)
/* Checks cache and sends repeated answer if we alreay saw this query recently.
   Returns: 1 = answer sent, drop this query, 0 = no answer sent, this is
   a new query. */
{
	int i;
	int use;

	for (i = 0; i < DNSCACHE_LEN ; i++) {
		/* Try cache most-recent-first */
		use = users[userid].dnscache_lastfilled - i;
		if (use < 0)
			use += DNSCACHE_LEN;

		if (users[userid].dnscache_q[use].id == 0)
			continue;
		if (users[userid].dnscache_answerlen[use] <= 0)
			continue;

		if (users[userid].dnscache_q[use].type != q->type ||
		    strcmp(users[userid].dnscache_q[use].name, q->name))
			continue;

		/* okay, match */
		if (debug >= 1)
			fprintf(stderr, "OUT  user %d %s from dnscache\n", userid, q->name);

		write_dns(dns_fd, q, users[userid].dnscache_answer[use],
			  users[userid].dnscache_answerlen[use],
			  users[userid].downenc);

		q->id = 0;	/* this query was used */
		return 1;
	}

	/* here only when no match found */
	return 0;
}

#endif /* DNSCACHE_LEN */

static inline void
save_to_qmem(unsigned char *qmem_cmc, unsigned short *qmem_type, int qmem_len,
	     int *qmem_lastfilled, unsigned char *cmc_to_add,
	     unsigned short type_to_add)
/* Remember query to check for duplicates */
{
	int fill;

	fill = *qmem_lastfilled + 1;
	if (fill >= qmem_len)
		fill = 0;

	memcpy(qmem_cmc + fill * 4, cmc_to_add, 4);
	qmem_type[fill] = type_to_add;
	*qmem_lastfilled = fill;
}

static inline void
save_to_qmem_pingordata(int userid, struct query *q)
{
	/* Our CMC is a bit more than the "official" CMC; we store 4 bytes
	   just because we can, and because it may prevent some false matches.
	   For ping, we save the 4 decoded bytes: userid + seq/frag + CMC.
	   For data, we save the 4 _un_decoded chars in lowercase: seq/frag's
	   + 1 char CMC; that last char is non-Base32.
	 */

	char cmc[8];
	int i;

	if (q->name[0] == 'P' || q->name[0] == 'p') {
		/* Ping packet */

		size_t cmcsize = sizeof(cmc);
		char *cp = strchr(q->name, '.');

		if (cp == NULL)
			return;  /* illegal hostname; shouldn't happen */

		/* We already unpacked in handle_null_request(), but that's
		   lost now... Note: b32 directly, we want no undotify here! */
		i = b32->decode(cmc, &cmcsize, q->name + 1, (cp - q->name) - 1);

		if (i < 4)
			return;	 /* illegal ping; shouldn't happen */

		save_to_qmem(users[userid].qmemping_cmc,
			     users[userid].qmemping_type, QMEMPING_LEN,
			     &users[userid].qmemping_lastfilled,
			     (void *) cmc, q->type);
	} else {
		/* Data packet, hopefully not illegal */
		if (strlen(q->name) < 5)
			return;

		/* We store CMC in lowercase; if routing via multiple parallel
		   DNS servers, one may do case-switch and another may not,
		   and we still want to detect duplicates.
		   Data-header is always base32, so case-swap won't hurt.
		 */
		for (i = 0; i < 4; i++)
			if (q->name[i+1] >= 'A' && q->name[i+1] <= 'Z')
				cmc[i] = q->name[i+1] + ('a' - 'A');
			else
				cmc[i] = q->name[i+1];

		save_to_qmem(users[userid].qmemdata_cmc,
			     users[userid].qmemdata_type, QMEMDATA_LEN,
			     &users[userid].qmemdata_lastfilled,
			     (void *) cmc, q->type);
	}
}

static int
answer_from_qmem(int dns_fd, struct query *q, unsigned char *qmem_cmc,
		 unsigned short *qmem_type, int qmem_len,
		 unsigned char *cmc_to_check)
/* Checks query memory and sends an (illegal) answer if this is a duplicate.
   Returns: 1 = answer sent, drop this query, 0 = no answer sent, this is
   not a duplicate. */
{
	int i;

	for (i = 0; i < qmem_len ; i++) {

		if (qmem_type[i] == T_UNSET)
			continue;
		if (qmem_type[i] != q->type)
			continue;
		if (memcmp(qmem_cmc + i * 4, cmc_to_check, 4))
			continue;

		/* okay, match */
		if (debug >= 1)
			fprintf(stderr, "OUT  from qmem for %s == duplicate, sending illegal reply\n", q->name);

		write_dns(dns_fd, q, "x", 1, 'T');

		q->id = 0;	/* this query was used */
		return 1;
	}

	/* here only when no match found */
	return 0;
}

static inline int
answer_from_qmem_data(int dns_fd, int userid, struct query *q)
/* Quick helper function to keep handle_null_request() clean */
{
	char cmc[4];
	int i;

	for (i = 0; i < 4; i++)
		if (q->name[i+1] >= 'A' && q->name[i+1] <= 'Z')
			cmc[i] = q->name[i+1] + ('a' - 'A');
		else
			cmc[i] = q->name[i+1];

	return answer_from_qmem(dns_fd, q, users[userid].qmemdata_cmc,
				users[userid].qmemdata_type, QMEMDATA_LEN,
				(void *) cmc);
}

static int
send_chunk_or_dataless(int dns_fd, int userid, struct query *q)
/* Sends current fragment to user, or dataless packet if there is no
   current fragment available (-> normal "quiet" ping reply).
   Does not update anything, except:
   - discards q always (query is used)
   - forgets entire users[userid].outpacket if it was sent in one go,
     and then tries to get new packet from outpacket-queue
   Returns: 1 = can call us again immediately, new packet from queue;
   0 = don't call us again for now.
*/
{
	char pkt[4096];
	int datalen = 0;
	int last = 0;

	/* If re-sent too many times, drop entire packet */
	if (users[userid].outpacket.len > 0 &&
	    users[userid].outfragresent > 5) {
		users[userid].outpacket.len = 0;
		users[userid].outpacket.offset = 0;
		users[userid].outpacket.sentlen = 0;
		users[userid].outfragresent = 0;

#ifdef OUTPACKETQ_LEN
		/* Maybe more in queue, use immediately */
		get_from_outpacketq(userid);
#endif
	}

	if (users[userid].outpacket.len > 0) {
		datalen = MIN(users[userid].fragsize, users[userid].outpacket.len - users[userid].outpacket.offset);
		datalen = MIN(datalen, sizeof(pkt)-2);

		memcpy(&pkt[2], users[userid].outpacket.data + users[userid].outpacket.offset, datalen);
		users[userid].outpacket.sentlen = datalen;
		last = (users[userid].outpacket.len == users[userid].outpacket.offset + datalen);

		users[userid].outfragresent++;
	}

	/* Build downstream data header (see doc/proto_xxxxxxxx.txt) */

	/* First byte is 1 bit compression flag, 3 bits upstream seqno, 4 bits upstream fragment */
	pkt[0] = (1<<7) | ((users[userid].inpacket.seqno & 7) << 4) |
		(users[userid].inpacket.fragment & 15);
	/* Second byte is 3 bits downstream seqno, 4 bits downstream fragment, 1 bit last flag */
	pkt[1] = ((users[userid].outpacket.seqno & 7) << 5) |
		((users[userid].outpacket.fragment & 15) << 1) | (last & 1);

	if (debug >= 1) {
		fprintf(stderr, "OUT  pkt seq# %d, frag %d (last=%d), offset %d, fragsize %d, total %d, to user %d\n",
			users[userid].outpacket.seqno & 7, users[userid].outpacket.fragment & 15,
			last, users[userid].outpacket.offset, datalen, users[userid].outpacket.len, userid);
	}
	write_dns(dns_fd, q, pkt, datalen + 2, users[userid].downenc);

	if (q->id2 != 0) {
		q->id = q->id2;
		q->fromlen = q->fromlen2;
		memcpy(&(q->from), &(q->from2), q->fromlen2);
		if (debug >= 1)
			fprintf(stderr, "OUT  again to last duplicate\n");
		write_dns(dns_fd, q, pkt, datalen + 2, users[userid].downenc);
	}

	save_to_qmem_pingordata(userid, q);

#ifdef DNSCACHE_LEN
	save_to_dnscache(userid, q, pkt, datalen + 2);
#endif

	q->id = 0;			/* this query is used */

	if (datalen > 0 && datalen == users[userid].outpacket.len) {
		/* Whole packet was sent in one chunk, dont wait for ack */
		users[userid].outpacket.len = 0;
		users[userid].outpacket.offset = 0;
		users[userid].outpacket.sentlen = 0;
		users[userid].outfragresent = 0;

#ifdef OUTPACKETQ_LEN
		/* Maybe more in queue, prepare for next time */
		if (get_from_outpacketq(userid) == 1) {
			if (debug >= 3)
				fprintf(stderr, "    Chunk & fromqueue: callagain\n");
			return 1;	/* call us again */
		}
#endif
	}

	return 0;	/* don't call us again */
}

static int
tunnel_tun(int tun_fd, int dns_fd)
{
	unsigned long outlen;
	struct ip *header;
	char out[64*1024];
	char in[64*1024];
	int userid;
	int read;

	if ((read = read_tun(tun_fd, in, sizeof(in))) <= 0)
		return 0;

	/* find target ip in packet, in is padded with 4 bytes TUN header */
	header = (struct ip*) (in + 4);
	userid = find_user_by_ip(header->ip_dst.s_addr);
	if (userid < 0)
		return 0;

	outlen = sizeof(out);
	compress2((uint8_t*)out, &outlen, (uint8_t*)in, read, 9);

	if (users[userid].conn == CONN_DNS_NULL) {
#ifdef OUTPACKETQ_LEN
		/* If a packet is being sent, try storing the new one in the queue.
		   If the queue is full, drop the packet. TCP will hopefully notice
		   and reduce the packet rate. */
		if (users[userid].outpacket.len > 0) {
			save_to_outpacketq(userid, out, outlen);
			return 0;
		}
#endif

		start_new_outpacket(userid, out, outlen);

		/* Start sending immediately if query is waiting */
		if (users[userid].q_sendrealsoon.id != 0)
			send_chunk_or_dataless(dns_fd, userid, &users[userid].q_sendrealsoon);
		else if (users[userid].q.id != 0)
			send_chunk_or_dataless(dns_fd, userid, &users[userid].q);

		return outlen;
	} else { /* CONN_RAW_UDP */
		send_raw(dns_fd, out, outlen, userid, RAW_HDR_CMD_DATA, &users[userid].q);
		return outlen;
	}
}

typedef enum {
	VERSION_ACK,
	VERSION_NACK,
	VERSION_FULL
} version_ack_t;

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

static void
process_downstream_ack(int userid, int down_seq, int down_frag)
/* Process acks from downstream fragments.
   After this, .offset and .fragment are updated (if ack correct),
   or .len is set to zero when all is done.
*/
{
	if (users[userid].outpacket.len <= 0)
		/* No packet to apply acks to */
		return;

	if (users[userid].outpacket.seqno != down_seq ||
	    users[userid].outpacket.fragment != down_frag)
		/* Not the ack we're waiting for; probably duplicate of old
		   ack, happens a lot with ping packets */
		return;

	/* Received proper ack */
	users[userid].outpacket.offset += users[userid].outpacket.sentlen;
	users[userid].outpacket.sentlen = 0;
	users[userid].outpacket.fragment++;
	users[userid].outfragresent = 0;

	/* Is packet done? */
	if (users[userid].outpacket.offset >= users[userid].outpacket.len) {
		users[userid].outpacket.len = 0;
		users[userid].outpacket.offset = 0;
		users[userid].outpacket.fragment--;	/* unneeded ++ above */
		/* ^keep last seqno/frag, are always returned on pings */
		/* users[userid].outfragresent = 0; already above */

#ifdef OUTPACKETQ_LEN
		/* Possibly get new packet from queue */
		get_from_outpacketq(userid);
#endif
	}
}

static void
handle_null_request(int tun_fd, int dns_fd, struct query *q, int domain_len)
{
	struct in_addr tempip;
	char in[512];
	char logindata[16];
	char out[64*1024];
	char unpacked[64*1024];
	char *tmp[2];
	int userid;
	int read;

	userid = -1;

	/* Everything here needs at least two chars in the name */
	if (domain_len < 2)
		return;

	memcpy(in, q->name, MIN(domain_len, sizeof(in)));

	if(in[0] == 'V' || in[0] == 'v') {
		int version = 0;

		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);
		/* Version greeting, compare and send ack/nak */
		if (read > 4) {
			/* Received V + 32bits version */
			version = (((unpacked[0] & 0xff) << 24) |
					   ((unpacked[1] & 0xff) << 16) |
					   ((unpacked[2] & 0xff) << 8) |
					   ((unpacked[3] & 0xff)));
		}

		if (version == VERSION) {
			userid = find_available_user();
			if (userid >= 0) {
				int i;
				struct sockaddr_in *tempin;

				users[userid].seed = rand();
				/* Store remote IP number */
				tempin = (struct sockaddr_in *) &(q->from);
				memcpy(&(users[userid].host), &(tempin->sin_addr), sizeof(struct in_addr));

				memcpy(&(users[userid].q), q, sizeof(struct query));
				users[userid].encoder = get_base32_encoder();
				users[userid].downenc = 'T';
				send_version_response(dns_fd, VERSION_ACK, users[userid].seed, userid, q);
				syslog(LOG_INFO, "accepted version for user #%d from %s",
					userid, format_addr(&q->from, q->fromlen));
				users[userid].q.id = 0;
				users[userid].q.id2 = 0;
				users[userid].q_sendrealsoon.id = 0;
				users[userid].q_sendrealsoon.id2 = 0;
				users[userid].q_sendrealsoon_new = 0;
				users[userid].outpacket.len = 0;
				users[userid].outpacket.offset = 0;
				users[userid].outpacket.sentlen = 0;
				users[userid].outpacket.seqno = 0;
				users[userid].outpacket.fragment = 0;
				users[userid].outfragresent = 0;
				users[userid].inpacket.len = 0;
				users[userid].inpacket.offset = 0;
				users[userid].inpacket.seqno = 0;
				users[userid].inpacket.fragment = 0;
				users[userid].fragsize = 100; /* very safe */
				users[userid].conn = CONN_DNS_NULL;
				users[userid].lazy = 0;
#ifdef OUTPACKETQ_LEN
				users[userid].outpacketq_nexttouse = 0;
				users[userid].outpacketq_filled = 0;
#endif
#ifdef DNSCACHE_LEN
				{
					for (i = 0; i < DNSCACHE_LEN; i++) {
					        users[userid].dnscache_q[i].id = 0;
					        users[userid].dnscache_answerlen[i] = 0;
					}
				}
				users[userid].dnscache_lastfilled = 0;
#endif
				for (i = 0; i < QMEMPING_LEN; i++)
				        users[userid].qmemping_type[i] = T_UNSET;
				users[userid].qmemping_lastfilled = 0;
				for (i = 0; i < QMEMDATA_LEN; i++)
				        users[userid].qmemdata_type[i] = T_UNSET;
				users[userid].qmemdata_lastfilled = 0;
			} else {
				/* No space for another user */
				send_version_response(dns_fd, VERSION_FULL, created_users, 0, q);
				syslog(LOG_INFO, "dropped user from %s, server full",
					format_addr(&q->from, q->fromlen));
			}
		} else {
			send_version_response(dns_fd, VERSION_NACK, VERSION, 0, q);
			syslog(LOG_INFO, "dropped user from %s, sent bad version %08X",
				format_addr(&q->from, q->fromlen), version);
		}
		return;
	} else if(in[0] == 'L' || in[0] == 'l') {
		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);
		if (read < 17) {
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Login phase, handle auth */
		userid = unpacked[0];

		if (check_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			syslog(LOG_WARNING, "dropped login request from user #%d from unexpected source %s",
				userid, format_addr(&q->from, q->fromlen));
			return;
		} else {
			users[userid].last_pkt = time(NULL);
			login_calculate(logindata, 16, password, users[userid].seed);

			if (read >= 18 && (memcmp(logindata, unpacked+1, 16) == 0)) {
				/* Store login ok */
				users[userid].authenticated = 1;

				/* Send ip/mtu/netmask info */
				tempip.s_addr = my_ip;
				tmp[0] = strdup(inet_ntoa(tempip));
				tempip.s_addr = users[userid].tun_ip;
				tmp[1] = strdup(inet_ntoa(tempip));

				read = snprintf(out, sizeof(out), "%s-%s-%d-%d",
						tmp[0], tmp[1], my_mtu, netmask);

				write_dns(dns_fd, q, out, read, users[userid].downenc);
				q->id = 0;
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
	} else if(in[0] == 'I' || in[0] == 'i') {
		/* Request for IP number */
		in_addr_t replyaddr;
		unsigned addr;
		char reply[5];

		userid = b32_8to5(in[1]);
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		if (ns_ip != INADDR_ANY) {
			/* If set, use assigned external ip (-n option) */
			replyaddr = ns_ip;
		} else {
			/* otherwise return destination ip from packet */
			memcpy(&replyaddr, &q->destination.s_addr, sizeof(in_addr_t));
		}

		addr = htonl(replyaddr);
		reply[0] = 'I';
		reply[1] = (addr >> 24) & 0xFF;
		reply[2] = (addr >> 16) & 0xFF;
		reply[3] = (addr >>  8) & 0xFF;
		reply[4] = (addr >>  0) & 0xFF;
		write_dns(dns_fd, q, reply, sizeof(reply), 'T');
	} else if(in[0] == 'Z' || in[0] == 'z') {
		/* Check for case conservation and chars not allowed according to RFC */

		/* Reply with received hostname as data */
		/* No userid here, reply with lowest-grade downenc */
		write_dns(dns_fd, q, in, domain_len, 'T');
		return;
	} else if(in[0] == 'S' || in[0] == 's') {
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
			enc = get_base32_encoder();
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 6: /* 6 bits per byte = base64 */
			enc = get_base64_encoder();
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 26: /* "2nd" 6 bits per byte = base64u, with underscore */
			enc = get_base64u_encoder();
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		case 7: /* 7 bits per byte = base128 */
			enc = get_base128_encoder();
			user_switch_codec(userid, enc);
			write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
			break;
		default:
			write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
			break;
		}
		return;
	} else if(in[0] == 'O' || in[0] == 'o') {
		if (domain_len < 3) { /* len at least 3, example: "O1T" */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		userid = b32_8to5(in[1]);

		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		switch (in[2]) {
		case 'T':
		case 't':
			users[userid].downenc = 'T';
			write_dns(dns_fd, q, "Base32", 6, users[userid].downenc);
			break;
		case 'S':
		case 's':
			users[userid].downenc = 'S';
			write_dns(dns_fd, q, "Base64", 6, users[userid].downenc);
			break;
		case 'U':
		case 'u':
			users[userid].downenc = 'U';
			write_dns(dns_fd, q, "Base64u", 7, users[userid].downenc);
			break;
		case 'V':
		case 'v':
			users[userid].downenc = 'V';
			write_dns(dns_fd, q, "Base128", 7, users[userid].downenc);
			break;
		case 'R':
		case 'r':
			users[userid].downenc = 'R';
			write_dns(dns_fd, q, "Raw", 3, users[userid].downenc);
			break;
		case 'L':
		case 'l':
			users[userid].lazy = 1;
			write_dns(dns_fd, q, "Lazy", 4, users[userid].downenc);
			break;
		case 'I':
		case 'i':
			users[userid].lazy = 0;
			write_dns(dns_fd, q, "Immediate", 9, users[userid].downenc);
			break;
		default:
			write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
			break;
		}
		return;
	} else if(in[0] == 'Y' || in[0] == 'y') {
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

		switch (in[1]) {
		case 'T':
		case 't':
			if (q->type == T_TXT ||
			    q->type == T_SRV || q->type == T_MX ||
			    q->type == T_CNAME || q->type == T_A) {
				write_dns(dns_fd, q, datap, datalen, 'T');
				return;
			}
			break;
		case 'S':
		case 's':
			if (q->type == T_TXT ||
			    q->type == T_SRV || q->type == T_MX ||
			    q->type == T_CNAME || q->type == T_A) {
				write_dns(dns_fd, q, datap, datalen, 'S');
				return;
			}
			break;
		case 'U':
		case 'u':
			if (q->type == T_TXT ||
			    q->type == T_SRV || q->type == T_MX ||
			    q->type == T_CNAME || q->type == T_A) {
				write_dns(dns_fd, q, datap, datalen, 'U');
				return;
			}
			break;
		case 'V':
		case 'v':
			if (q->type == T_TXT ||
			    q->type == T_SRV || q->type == T_MX ||
			    q->type == T_CNAME || q->type == T_A) {
				write_dns(dns_fd, q, datap, datalen, 'V');
				return;
			}
			break;
		case 'R':
		case 'r':
			if (q->type == T_NULL || q->type == T_TXT) {
				write_dns(dns_fd, q, datap, datalen, 'R');
				return;
			}
			break;
		}

		/* if still here, then codec not available */
		write_dns(dns_fd, q, "BADCODEC", 8, 'T');
		return;

	} else if(in[0] == 'R' || in[0] == 'r') {
		int req_frag_size;

		if (domain_len < 16) {  /* we'd better have some chars for data... */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Downstream fragsize probe packet */
		userid = (b32_8to5(in[1]) >> 1) & 15;
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		req_frag_size = ((b32_8to5(in[1]) & 1) << 10) | ((b32_8to5(in[2]) & 31) << 5) | (b32_8to5(in[3]) & 31);
		if (req_frag_size < 2 || req_frag_size > 2047) {
			write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
		} else {
			char buf[2048];
			int i;
			unsigned int v = ((unsigned int) rand()) & 0xff ;

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
	} else if(in[0] == 'N' || in[0] == 'n') {
		int max_frag_size;

		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);

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

		max_frag_size = ((unpacked[1] & 0xff) << 8) | (unpacked[2] & 0xff);
		if (max_frag_size < 2) {
			write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
		} else {
			users[userid].fragsize = max_frag_size;
			write_dns(dns_fd, q, &unpacked[1], 2, users[userid].downenc);
		}
		return;
	} else if(in[0] == 'P' || in[0] == 'p') {
		int dn_seq;
		int dn_frag;
		int didsend = 0;

		/* We can't handle id=0, that's "no packet" to us. So drop
		   request completely. Note that DNS servers rewrite the id.
		   We'll drop 1 in 64k times. If DNS server retransmits with
		   different id, then all okay.
		   Else client won't retransmit, and we'll just keep the
		   previous ping in cache, no problem either. */
		if (q->id == 0)
			return;

		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);
		if (read < 4)
			return;

		/* Ping packet, store userid */
		userid = unpacked[0];
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

#ifdef DNSCACHE_LEN
		/* Check if cached */
		if (answer_from_dnscache(dns_fd, userid, q))
			return;
#endif

		/* Check if duplicate (and not in full dnscache any more) */
		if (answer_from_qmem(dns_fd, q, users[userid].qmemping_cmc,
				     users[userid].qmemping_type, QMEMPING_LEN,
				     (void *) unpacked))
			return;

		/* Check if duplicate of waiting queries; impatient DNS relays
		   like to re-try early and often (with _different_ .id!)  */
		if (users[userid].q.id != 0 &&
		    q->type == users[userid].q.type &&
		    !strcmp(q->name, users[userid].q.name) &&
		    users[userid].lazy) {
			/* We have this ping already, and it's waiting to be
			   answered. Always keep the last duplicate, since the
			   relay may have forgotten its first version already.
			   Our answer will go to both.
			   (If we already sent an answer, qmem/cache will
			   have triggered.) */
			if (debug >= 2) {
				fprintf(stderr, "PING pkt from user %d = dupe from impatient DNS server, remembering\n",
					userid);
			}
			users[userid].q.id2 = q->id;
			users[userid].q.fromlen2 = q->fromlen;
			memcpy(&(users[userid].q.from2), &(q->from), q->fromlen);
			return;
		}

		if (users[userid].q_sendrealsoon.id != 0 &&
		    q->type == users[userid].q_sendrealsoon.type &&
		    !strcmp(q->name, users[userid].q_sendrealsoon.name)) {
			/* Outer select loop will send answer immediately,
			   to both queries. */
			if (debug >= 2) {
				fprintf(stderr, "PING pkt from user %d = dupe from impatient DNS server, remembering\n",
					userid);
			}
			users[userid].q_sendrealsoon.id2 = q->id;
			users[userid].q_sendrealsoon.fromlen2 = q->fromlen;
			memcpy(&(users[userid].q_sendrealsoon.from2),
			       &(q->from), q->fromlen);
			return;
		}

		dn_seq = unpacked[1] >> 4;
		dn_frag = unpacked[1] & 15;

		if (debug >= 1) {
			fprintf(stderr, "PING pkt from user %d, ack for downstream %d/%d\n",
				userid, dn_seq, dn_frag);
		}

		process_downstream_ack(userid, dn_seq, dn_frag);

		if (debug >= 3) {
			fprintf(stderr, "PINGret (if any) will ack upstream %d/%d\n",
				users[userid].inpacket.seqno, users[userid].inpacket.fragment);
		}

		/* If there is a query that must be returned real soon, do it.
		   May contain new downstream data if the ping had a new ack.
		   Otherwise, may also be re-sending old data. */
		if (users[userid].q_sendrealsoon.id != 0) {
			send_chunk_or_dataless(dns_fd, userid, &users[userid].q_sendrealsoon);
		}

		/* We need to store a new query, so if there still is an
		   earlier query waiting, always send a reply to finish it.
		   May contain new downstream data if the ping had a new ack.
		   Otherwise, may also be re-sending old data.
		   (This is duplicate data if we had q_sendrealsoon above.) */
		if (users[userid].q.id != 0) {
			didsend = 1;
			if (send_chunk_or_dataless(dns_fd, userid, &users[userid].q) == 1)
				/* new packet from queue, send immediately */
				didsend = 0;
		}

		/* Save new query and time info */
		memcpy(&(users[userid].q), q, sizeof(struct query));
		users[userid].last_pkt = time(NULL);

		/* If anything waiting and we didn't already send above, send
		   it now. And always send immediately if we're not lazy
		   (then above won't have sent at all). */
		if ((!didsend && users[userid].outpacket.len > 0) ||
		    !users[userid].lazy)
			send_chunk_or_dataless(dns_fd, userid, &users[userid].q);

	} else if((in[0] >= '0' && in[0] <= '9')
			|| (in[0] >= 'a' && in[0] <= 'f')
			|| (in[0] >= 'A' && in[0] <= 'F')) {
		int up_seq, up_frag, dn_seq, dn_frag, lastfrag;
		int upstream_ok = 1;
		int didsend = 0;
		int code = -1;

		/* Need 5char header + >=1 char data */
		if (domain_len < 6)
			return;

		/* We can't handle id=0, that's "no packet" to us. So drop
		   request completely. Note that DNS servers rewrite the id.
		   We'll drop 1 in 64k times. If DNS server retransmits with
		   different id, then all okay.
		   Else client doesn't get our ack, and will retransmit in
		   1 second. */
		if (q->id == 0)
			return;

		if ((in[0] >= '0' && in[0] <= '9'))
			code = in[0] - '0';
		if ((in[0] >= 'a' && in[0] <= 'f'))
			code = in[0] - 'a' + 10;
		if ((in[0] >= 'A' && in[0] <= 'F'))
			code = in[0] - 'A' + 10;

		userid = code;
		/* Check user and sending ip number */
		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

#ifdef DNSCACHE_LEN
		/* Check if cached */
		if (answer_from_dnscache(dns_fd, userid, q))
			return;
#endif

		/* Check if duplicate (and not in full dnscache any more) */
		if (answer_from_qmem_data(dns_fd, userid, q))
			return;

		/* Check if duplicate of waiting queries; impatient DNS relays
		   like to re-try early and often (with _different_ .id!)  */
		if (users[userid].q.id != 0 &&
		    q->type == users[userid].q.type &&
		    !strcmp(q->name, users[userid].q.name) &&
		    users[userid].lazy) {
			/* We have this packet already, and it's waiting to be
			   answered. Always keep the last duplicate, since the
			   relay may have forgotten its first version already.
			   Our answer will go to both.
			   (If we already sent an answer, qmem/cache will
			   have triggered.) */
			if (debug >= 2) {
				fprintf(stderr, "IN   pkt from user %d = dupe from impatient DNS server, remembering\n",
					userid);
			}
			users[userid].q.id2 = q->id;
			users[userid].q.fromlen2 = q->fromlen;
			memcpy(&(users[userid].q.from2), &(q->from), q->fromlen);
			return;
		}

		if (users[userid].q_sendrealsoon.id != 0 &&
		    q->type == users[userid].q_sendrealsoon.type &&
		    !strcmp(q->name, users[userid].q_sendrealsoon.name)) {
			/* Outer select loop will send answer immediately,
			   to both queries. */
			if (debug >= 2) {
				fprintf(stderr, "IN   pkt from user %d = dupe from impatient DNS server, remembering\n",
					userid);
			}
			users[userid].q_sendrealsoon.id2 = q->id;
			users[userid].q_sendrealsoon.fromlen2 = q->fromlen;
			memcpy(&(users[userid].q_sendrealsoon.from2),
			       &(q->from), q->fromlen);
			return;
		}


		/* Decode data header */
		up_seq = (b32_8to5(in[1]) >> 2) & 7;
		up_frag = ((b32_8to5(in[1]) & 3) << 2) | ((b32_8to5(in[2]) >> 3) & 3);
		dn_seq = (b32_8to5(in[2]) & 7);
		dn_frag = b32_8to5(in[3]) >> 1;
		lastfrag = b32_8to5(in[3]) & 1;

		process_downstream_ack(userid, dn_seq, dn_frag);

		if (up_seq == users[userid].inpacket.seqno &&
			up_frag <= users[userid].inpacket.fragment) {
			/* Got repeated old packet _with data_, probably
			   because client didn't receive our ack. So re-send
			   our ack(+data) immediately to keep things flowing
			   fast.
			   If it's a _really_ old frag, it's a nameserver
			   that tries again, and sending our current (non-
			   matching) fragno won't be a problem. */
			if (debug >= 1) {
				fprintf(stderr, "IN   pkt seq# %d, frag %d, dropped duplicate frag\n",
					up_seq, up_frag);
			}
			upstream_ok = 0;
		}
		else if (up_seq != users[userid].inpacket.seqno &&
			 recent_seqno(users[userid].inpacket.seqno, up_seq)) {
			/* Duplicate of recent upstream data packet; probably
			   need to answer this to keep DNS server happy */
			if (debug >= 1) {
				fprintf(stderr, "IN   pkt seq# %d, frag %d, dropped duplicate recent seqno\n",
					up_seq, up_frag);
 			}
			upstream_ok = 0;
		}
		else if (up_seq != users[userid].inpacket.seqno) {
			/* Really new packet has arrived, no recent duplicate */
			/* Forget any old packet, even if incomplete */
			users[userid].inpacket.seqno = up_seq;
			users[userid].inpacket.fragment = up_frag;
			users[userid].inpacket.len = 0;
			users[userid].inpacket.offset = 0;
		} else {
			/* seq is same, frag is higher; don't care about
			   missing fragments, TCP checksum will fail */
  			users[userid].inpacket.fragment = up_frag;
		}

		if (debug >= 3) {
			fprintf(stderr, "INpack with upstream %d/%d, we are going to ack upstream %d/%d\n",
				up_seq, up_frag,
				users[userid].inpacket.seqno, users[userid].inpacket.fragment);
		}

		if (upstream_ok) {
			/* decode with this user's encoding */
			read = unpack_data(unpacked, sizeof(unpacked), &(in[5]), domain_len - 5,
					   users[userid].encoder);

			/* copy to packet buffer, update length */
			read = MIN(read, sizeof(users[userid].inpacket.data) - users[userid].inpacket.offset);
			memcpy(users[userid].inpacket.data + users[userid].inpacket.offset, unpacked, read);
			users[userid].inpacket.len += read;
			users[userid].inpacket.offset += read;

			if (debug >= 1) {
				fprintf(stderr, "IN   pkt seq# %d, frag %d (last=%d), fragsize %d, total %d, from user %d\n",
					up_seq, up_frag, lastfrag, read, users[userid].inpacket.len, userid);
			}
		}

		if (upstream_ok && lastfrag) { /* packet is complete */
			handle_full_packet(tun_fd, dns_fd, userid);
		}

		/* If there is a query that must be returned real soon, do it.
		   Includes an ack of the just received upstream fragment,
		   may contain new data. */
		if (users[userid].q_sendrealsoon.id != 0) {
			didsend = 1;
			if (send_chunk_or_dataless(dns_fd, userid, &users[userid].q_sendrealsoon) == 1)
				/* new packet from queue, send immediately */
				didsend = 0;
		}

		/* If we already have an earlier query waiting, we need to
		   get rid of it to store the new query.
		   - If we have new data waiting and not yet sent above,
		     send immediately.
		   - If this wasn't the last upstream fragment, then we expect
		     more, so ack immediately if we didn't already.
		   - If we are in non-lazy mode, there should be no query
		     waiting, but if there is, send immediately.
		   - In all other cases (mostly the last-fragment cases),
		     we can afford to wait just a tiny little while for the
		     TCP ack to arrive from our tun. Note that this works best
		     when there is only one client.
		 */
		if (users[userid].q.id != 0) {
			if ((users[userid].outpacket.len > 0 && !didsend) ||
			    (upstream_ok && !lastfrag && !didsend) ||
			    (!upstream_ok && !didsend) ||
			    !users[userid].lazy) {
				didsend = 1;
				if (send_chunk_or_dataless(dns_fd, userid, &users[userid].q) == 1)
					/* new packet from queue, send immediately */
					didsend = 0;
			} else {
				memcpy(&(users[userid].q_sendrealsoon),
				       &(users[userid].q),
				       sizeof(struct query));
				users[userid].q_sendrealsoon_new = 1;
				users[userid].q.id = 0;  /* used */
				didsend = 1;
			}
		}

		/* Save new query and time info */
		memcpy(&(users[userid].q), q, sizeof(struct query));
		users[userid].last_pkt = time(NULL);

		/* If we still need to ack this upstream frag, do it to keep
		   upstream flowing.
		   - If we have new data waiting and not yet sent above,
		     send immediately.
		   - If this wasn't the last upstream fragment, then we expect
		     more, so ack immediately if we didn't already or are
		     in non-lazy mode.
		   - If this was the last fragment, and we didn't ack already
		     or are in non-lazy mode, send the ack after just a tiny
		     little while so that the TCP ack may have arrived from
		     our tun device.
		   - In all other cases, don't send anything now.
		*/
		if (users[userid].outpacket.len > 0 && !didsend)
			send_chunk_or_dataless(dns_fd, userid, &users[userid].q);
		else if (!didsend || !users[userid].lazy) {
			if (upstream_ok && lastfrag) {
				memcpy(&(users[userid].q_sendrealsoon),
				       &(users[userid].q),
				       sizeof(struct query));
				users[userid].q_sendrealsoon_new = 1;
				users[userid].q.id = 0;  /* used */
			} else {
				send_chunk_or_dataless(dns_fd, userid, &users[userid].q);
			}
		}
	}
}

static void
handle_ns_request(int dns_fd, struct query *q)
/* Mostly identical to handle_a_request() below */
{
	char buf[64*1024];
	int len;

	if (ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		memcpy(&q->destination.s_addr, &ns_ip, sizeof(in_addr_t));
	}

	len = dns_encode_ns_response(buf, sizeof(buf), q, topdomain);
	if (len < 1) {
		warnx("dns_encode_ns_response doesn't fit");
		return;
	}

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s, type %d, name %s, %d bytes NS reply\n",
			format_addr(&q->from, q->fromlen), q->type, q->name, len);
	}
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("ns reply send error");
	}
}

static void
handle_a_request(int dns_fd, struct query *q, int fakeip)
/* Mostly identical to handle_ns_request() above */
{
	char buf[64*1024];
	int len;

	if (fakeip) {
		in_addr_t ip = inet_addr("127.0.0.1");
		memcpy(&q->destination.s_addr, &ip, sizeof(in_addr_t));

	} else if (ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		memcpy(&q->destination.s_addr, &ns_ip, sizeof(in_addr_t));
	}

	len = dns_encode_a_response(buf, sizeof(buf), q);
	if (len < 1) {
		warnx("dns_encode_a_response doesn't fit");
		return;
	}

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s, type %d, name %s, %d bytes A reply\n",
			format_addr(&q->from, q->fromlen), q->type, q->name, len);
	}
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("a reply send error");
	}
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

	if (debug >= 2) {
		fprintf(stderr, "TX: NS reply \n");
	}

	if (sendto(bind_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("forward query error");
	}
}

static int
tunnel_bind(int bind_fd, int dns_fd)
{
	char packet[64*1024];
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct fw_query *query;
	unsigned short id;
	int r;

	fromlen = sizeof(struct sockaddr);
	r = recvfrom(bind_fd, packet, sizeof(packet), 0,
		(struct sockaddr*)&from, &fromlen);

	if (r <= 0)
		return 0;

	id = dns_get_id(packet, r);

	if (debug >= 2) {
		fprintf(stderr, "RX: Got response on query %u from DNS\n", (id & 0xFFFF));
	}

	/* Get sockaddr from id */
	fw_query_get(id, &query);
	if (!query) {
		if (debug >= 2) {
			fprintf(stderr, "Lost sender of id %u, dropping reply\n", (id & 0xFFFF));
		}
		return 0;
	}

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s id %u, %d bytes\n",
			format_addr(&query->addr, query->addrlen), (id & 0xffff), r);
	}

	if (sendto(dns_fd, packet, r, 0, (const struct sockaddr *) &(query->addr),
		query->addrlen) <= 0) {
		warn("forward reply error");
	}

	return 0;
}

static int
tunnel_dns(int tun_fd, int dns_fd, int bind_fd)
{
	struct query q;
	int read;
	int domain_len;
	int inside_topdomain = 0;

	if ((read = read_dns(dns_fd, tun_fd, &q)) <= 0)
		return 0;

	if (debug >= 2) {
		fprintf(stderr, "RX: client %s, type %d, name %s\n",
			format_addr(&q.from, q.fromlen), q.type, q.name);
	}

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
			handle_null_request(tun_fd, dns_fd, &q, domain_len);
			break;
		case T_NS:
			handle_ns_request(dns_fd, &q);
			break;
		default:
			break;
		}
	} else {
		/* Forward query to other port ? */
		if (bind_fd) {
			forward_query(bind_fd, &q);
		}
	}
	return 0;
}

static int
tunnel(int tun_fd, int dns_fd, int bind_fd, int max_idle_time)
{
	struct timeval tv;
	fd_set fds;
	int i;
	int userid;
	time_t last_action = time(NULL);

	while (running) {
		int maxfd;
		tv.tv_sec = 10;			/* doesn't really matter */
		tv.tv_usec = 0;

		/* Adjust timeout if there is anything to send realsoon.
		   Clients won't be sending new data until we send our ack,
		   so don't keep them waiting long. This only triggers at
		   final upstream fragments, which is about once per eight
		   requests during heavy upstream traffic.
		   20msec: ~8 packs every 1/50sec = ~400 DNSreq/sec,
		   or ~1200bytes every 1/50sec = ~0.5 Mbit/sec upstream */
		for (userid = 0; userid < created_users; userid++) {
			if (users[userid].active && !users[userid].disabled &&
			    users[userid].last_pkt + 60 > time(NULL)) {
				users[userid].q_sendrealsoon_new = 0;
				if (users[userid].q_sendrealsoon.id != 0) {
					tv.tv_sec = 0;
					tv.tv_usec = 20000;
				}
			}
		}

		FD_ZERO(&fds);

		FD_SET(dns_fd, &fds);
		maxfd = dns_fd;

		if (bind_fd) {
			/* wait for replies from real DNS */
			FD_SET(bind_fd, &fds);
			maxfd = MAX(bind_fd, maxfd);
		}

		/* Don't read from tun if no users can accept data anyway;
		   tun queue/TCP buffers are larger than our outpacket-queues */
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

		if (i==0) {
			if (max_idle_time) {
				/* only trigger the check if that's worth ( ie, no need to loop over if there
				is something to send */
				if (last_action + max_idle_time < time(NULL)) {
					for (userid = 0; userid < created_users; userid++) {
						last_action = ( users[userid].last_pkt > last_action ) ? users[userid].last_pkt : last_action;
					}
					if (last_action + max_idle_time < time(NULL)) {
						fprintf(stderr, "Idling since too long, shutting down...\n");
						running = 0;
					}
				}
			}
 		} else {
 			if (FD_ISSET(tun_fd, &fds)) {
 				tunnel_tun(tun_fd, dns_fd);
 			}
 			if (FD_ISSET(dns_fd, &fds)) {
 				tunnel_dns(tun_fd, dns_fd, bind_fd);
 			}
			if (FD_ISSET(bind_fd, &fds)) {
				tunnel_bind(bind_fd, dns_fd);
			}
		}

		/* Send realsoon's if tun or dns didn't already */
		for (userid = 0; userid < created_users; userid++)
			if (users[userid].active && !users[userid].disabled &&
			    users[userid].last_pkt + 60 > time(NULL) &&
			    users[userid].q_sendrealsoon.id != 0 &&
			    users[userid].conn == CONN_DNS_NULL &&
			    !users[userid].q_sendrealsoon_new)
				send_chunk_or_dataless(dns_fd, userid, &users[userid].q_sendrealsoon);
	}

	return 0;
}

static void
handle_full_packet(int tun_fd, int dns_fd, int userid)
{
	unsigned long outlen;
	char out[64*1024];
	int touser;
	int ret;

	outlen = sizeof(out);
	ret = uncompress((uint8_t*)out, &outlen,
		   (uint8_t*)users[userid].inpacket.data, users[userid].inpacket.len);

	if (ret == Z_OK) {
		struct ip *hdr;

		hdr = (struct ip*) (out + 4);
		touser = find_user_by_ip(hdr->ip_dst.s_addr);

		if (touser == -1) {
			/* send the uncompressed packet to tun device */
			write_tun(tun_fd, out, outlen);
		} else {
			/* send the compressed(!) packet to other client */
			if (users[touser].conn == CONN_DNS_NULL) {
				if (users[touser].outpacket.len == 0) {
					start_new_outpacket(touser,
						users[userid].inpacket.data,
						users[userid].inpacket.len);

					/* Start sending immediately if query is waiting */
					if (users[touser].q_sendrealsoon.id != 0)
						send_chunk_or_dataless(dns_fd, touser, &users[touser].q_sendrealsoon);
					else if (users[touser].q.id != 0)
						send_chunk_or_dataless(dns_fd, touser, &users[touser].q);
#ifdef OUTPACKETQ_LEN
				} else {
					save_to_outpacketq(touser,
						users[userid].inpacket.data,
						users[userid].inpacket.len);
#endif
				}
			} else{ /* CONN_RAW_UDP */
				send_raw(dns_fd, users[userid].inpacket.data,
					 users[userid].inpacket.len, touser,
					 RAW_HDR_CMD_DATA, &users[touser].q);
			}
		}
	} else {
		if (debug >= 1)
			fprintf(stderr, "Discarded data, uncompress() result: %d\n", ret);
	}

	/* This packet is done */
	users[userid].inpacket.len = 0;
	users[userid].inpacket.offset = 0;
}

static void
handle_raw_login(char *packet, int len, struct query *q, int fd, int userid)
{
	char myhash[16];

	if (len < 16) return;

	/* can't use check_authenticated_user_and_ip() since IP address will be different,
	   so duplicate here except IP address */
	if (userid < 0 || userid >= created_users) return;
	if (!users[userid].active || users[userid].disabled) return;
	if (!users[userid].authenticated) return;
	if (users[userid].last_pkt + 60 < time(NULL)) return;

	if (debug >= 1) {
		fprintf(stderr, "IN   login raw, len %d, from user %d\n",
			len, userid);
	}

	/* User sends hash of seed + 1 */
	login_calculate(myhash, 16, password, users[userid].seed + 1);
	if (memcmp(packet, myhash, 16) == 0) {
		struct sockaddr_in *tempin;

		/* Update query and time info for user */
		users[userid].last_pkt = time(NULL);
		memcpy(&(users[userid].q), q, sizeof(struct query));

		/* Store remote IP number */
		tempin = (struct sockaddr_in *) &(q->from);
		memcpy(&(users[userid].host), &(tempin->sin_addr), sizeof(struct in_addr));

		/* Correct hash, reply with hash of seed - 1 */
		user_set_conn_type(userid, CONN_RAW_UDP);
		login_calculate(myhash, 16, password, users[userid].seed - 1);
		send_raw(fd, myhash, 16, userid, RAW_HDR_CMD_LOGIN, q);

		users[userid].authenticated_raw = 1;
	}
}

static void
handle_raw_data(char *packet, int len, struct query *q, int dns_fd, int tun_fd, int userid)
{
	if (check_authenticated_user_and_ip(userid, q) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update query and time info for user */
	users[userid].last_pkt = time(NULL);
	memcpy(&(users[userid].q), q, sizeof(struct query));

	/* copy to packet buffer, update length */
	users[userid].inpacket.offset = 0;
	memcpy(users[userid].inpacket.data, packet, len);
	users[userid].inpacket.len = len;

	if (debug >= 1) {
		fprintf(stderr, "IN   pkt raw, total %d, from user %d\n",
			users[userid].inpacket.len, userid);
	}

	handle_full_packet(tun_fd, dns_fd, userid);
}

static void
handle_raw_ping(struct query *q, int dns_fd, int userid)
{
	if (check_authenticated_user_and_ip(userid, q) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update query and time info for user */
	users[userid].last_pkt = time(NULL);
	memcpy(&(users[userid].q), q, sizeof(struct query));

	if (debug >= 1) {
		fprintf(stderr, "IN   ping raw, from user %d\n", userid);
	}

	/* Send ping reply */
	send_raw(dns_fd, NULL, 0, userid, RAW_HDR_CMD_PING, q);
}

static int
raw_decode(char *packet, int len, struct query *q, int dns_fd, int tun_fd)
{
	int raw_user;

	/* minimum length */
	if (len < RAW_HDR_LEN) return 0;
	/* should start with header */
	if (memcmp(packet, raw_header, RAW_HDR_IDENT_LEN)) return 0;

	raw_user = RAW_HDR_GET_USR(packet);
	switch (RAW_HDR_GET_CMD(packet)) {
	case RAW_HDR_CMD_LOGIN:
		/* Login challenge */
		handle_raw_login(&packet[RAW_HDR_LEN], len - RAW_HDR_LEN, q, dns_fd, raw_user);
		break;
	case RAW_HDR_CMD_DATA:
		/* Data packet */
		handle_raw_data(&packet[RAW_HDR_LEN], len - RAW_HDR_LEN, q, dns_fd, tun_fd, raw_user);
		break;
	case RAW_HDR_CMD_PING:
		/* Keepalive packet */
		handle_raw_ping(q, dns_fd, raw_user);
		break;
	default:
		warnx("Unhandled raw command %02X from user %d", RAW_HDR_GET_CMD(packet), raw_user);
		break;
	}
	return 1;
}

static int
read_dns(int fd, int tun_fd, struct query *q) /* FIXME: tun_fd is because of raw_decode() below */
{
	struct sockaddr_in from;
	socklen_t addrlen;
	char packet[64*1024];
	int r;
#ifndef WINDOWS32
	char address[96];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;

	addrlen = sizeof(struct sockaddr);
	iov.iov_base = packet;
	iov.iov_len = sizeof(packet);

	msg.msg_name = (caddr_t) &from;
	msg.msg_namelen = (unsigned) addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = address;
	msg.msg_controllen = sizeof(address);
	msg.msg_flags = 0;

	r = recvmsg(fd, &msg, 0);
#else
	addrlen = sizeof(struct sockaddr);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);
#endif /* !WINDOWS32 */

	if (r > 0) {
		memcpy((struct sockaddr*)&q->from, (struct sockaddr*)&from, addrlen);
		q->fromlen = addrlen;

		/* TODO do not handle raw packets here! */
		if (raw_decode(packet, r, q, fd, tun_fd)) {
			return 0;
		}
		if (dns_decode(NULL, 0, q, QR_QUERY, packet, r) < 0) {
			return 0;
		}

#ifndef WINDOWS32
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {

			if (cmsg->cmsg_level == IPPROTO_IP &&
				cmsg->cmsg_type == DSTADDR_SOCKOPT) {

				q->destination = *dstaddr(cmsg);
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
write_dns_nameenc(char *buf, size_t buflen, char *data, int datalen, char downenc)
/* Returns #bytes of data that were encoded */
{
	static int td1 = 0;
	static int td2 = 0;
	size_t space;
	char *b;

	/* Make a rotating topdomain to prevent filtering */
	td1+=3;
	td2+=7;
	if (td1>=26) td1-=26;
	if (td2>=25) td2-=25;

	/* encode data,datalen to CNAME/MX answer
	   (adapted from build_hostname() in encoding.c)
	 */

	space = MIN(0xFF, buflen) - 4 - 2;
	/* -1 encoding type, -3 ".xy", -2 for safety */

	memset(buf, 0, buflen);

	if (downenc == 'S') {
		buf[0] = 'i';
		if (!b64->places_dots())
			space -= (space / 57);	/* space for dots */
		b64->encode(buf+1, &space, data, datalen);
		if (!b64->places_dots())
			inline_dotify(buf, buflen);
	} else if (downenc == 'U') {
		buf[0] = 'j';
		if (!b64u->places_dots())
			space -= (space / 57);	/* space for dots */
		b64u->encode(buf+1, &space, data, datalen);
		if (!b64u->places_dots())
			inline_dotify(buf, buflen);
	} else if (downenc == 'V') {
		buf[0] = 'k';
		if (!b128->places_dots())
			space -= (space / 57);	/* space for dots */
		b128->encode(buf+1, &space, data, datalen);
		if (!b128->places_dots())
			inline_dotify(buf, buflen);
	} else {
		buf[0] = 'h';
		if (!b32->places_dots())
			space -= (space / 57);	/* space for dots */
		b32->encode(buf+1, &space, data, datalen);
		if (!b32->places_dots())
			inline_dotify(buf, buflen);
	}

	/* Add dot (if it wasn't there already) and topdomain */
	b = buf;
	b += strlen(buf) - 1;
	if (*b != '.')
		*++b = '.';
        b++;

	*b = 'a' + td1;
	b++;
	*b = 'a' + td2;
	b++;
	*b = '\0';

	return space;
}

static void
write_dns(int fd, struct query *q, char *data, int datalen, char downenc)
{
	char buf[64*1024];
	int len = 0;

	if (q->type == T_CNAME || q->type == T_A) {
		char cnamebuf[1024];		/* max 255 */

		write_dns_nameenc(cnamebuf, sizeof(cnamebuf),
				  data, datalen, downenc);

		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, cnamebuf,
				 sizeof(cnamebuf));
	} else if (q->type == T_MX || q->type == T_SRV) {
		char mxbuf[64*1024];
		char *b = mxbuf;
		int offset = 0;
		int res;

		while (1) {
			res = write_dns_nameenc(b, sizeof(mxbuf) - (b - mxbuf),
						data + offset,
						datalen - offset, downenc);
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
		char txtbuf[64*1024];
		size_t space = sizeof(txtbuf) - 1;;

		memset(txtbuf, 0, sizeof(txtbuf));

		if (downenc == 'S') {
			txtbuf[0] = 's';	/* plain base64(Sixty-four) */
			len = b64->encode(txtbuf+1, &space, data, datalen);
		}
		else if (downenc == 'U') {
			txtbuf[0] = 'u';	/* Base64 with Underscore */
			len = b64u->encode(txtbuf+1, &space, data, datalen);
		}
		else if (downenc == 'V') {
			txtbuf[0] = 'v';	/* Base128 */
			len = b128->encode(txtbuf+1, &space, data, datalen);
		}
		else if (downenc == 'R') {
			txtbuf[0] = 'r';	/* Raw binary data */
			len = MIN(datalen, sizeof(txtbuf) - 1);
			memcpy(txtbuf + 1, data, len);
		} else {
			txtbuf[0] = 't';	/* plain base32(Thirty-two) */
			len = b32->encode(txtbuf+1, &space, data, datalen);
		}
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, txtbuf, len+1);
	} else {
		/* Normal NULL-record encode */
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, data, datalen);
	}

	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s, type %d, name %s, %d bytes data\n",
			format_addr(&q->from, q->fromlen), q->type, q->name, datalen);
	}

	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

static void
usage() {
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-v] [-h] [-c] [-s] [-f] [-D] [-u user] "
		"[-t chrootdir] [-d device] [-m mtu] [-z context] "
		"[-l ip address to listen on] [-p port] [-n external ip] "
		"[-b dnsport] [-P password] [-F pidfile] [-i max idle time] "
		"tunnel_ip[/netmask] topdomain\n", __progname);
	exit(2);
}

static void
help() {
	extern char *__progname;

	fprintf(stderr, "iodine IP over DNS tunneling server\n");
	fprintf(stderr, "Usage: %s [-v] [-h] [-c] [-s] [-f] [-D] [-u user] "
		"[-t chrootdir] [-d device] [-m mtu] [-z context] "
		"[-l ip address to listen on] [-p port] [-n external ip] [-b dnsport] [-P password] "
		"[-F pidfile] tunnel_ip[/netmask] topdomain\n", __progname);
	fprintf(stderr, "  -v to print version info and exit\n");
	fprintf(stderr, "  -h to print this help and exit\n");
	fprintf(stderr, "  -c to disable check of client IP/port on each request\n");
	fprintf(stderr, "  -s to skip creating and configuring the tun device, "
		"which then has to be created manually\n");
	fprintf(stderr, "  -f to keep running in foreground\n");
	fprintf(stderr, "  -D to increase debug level\n");
	fprintf(stderr, "     (using -DD in UTF-8 terminal: \"LC_ALL=C luit iodined -DD ...\")\n");
	fprintf(stderr, "  -u name to drop privileges and run as user 'name'\n");
	fprintf(stderr, "  -t dir to chroot to directory dir\n");
	fprintf(stderr, "  -d device to set tunnel device name\n");
	fprintf(stderr, "  -m mtu to set tunnel device mtu\n");
	fprintf(stderr, "  -z context to apply SELinux context after initialization\n");
	fprintf(stderr, "  -l ip address to listen on for incoming dns traffic "
		"(default 0.0.0.0)\n");
	fprintf(stderr, "  -p port to listen on for incoming dns traffic (default 53)\n");
	fprintf(stderr, "  -n ip to respond with to NS queries\n");
	fprintf(stderr, "  -b port to forward normal DNS queries to (on localhost)\n");
	fprintf(stderr, "  -P password used for authentication (max 32 chars will be used)\n");
	fprintf(stderr, "  -F pidfile to write pid to a file\n");
	fprintf(stderr, "  -i maximum idle time before shutting down\n");
	fprintf(stderr, "tunnel_ip is the IP number of the local tunnel interface.\n");
	fprintf(stderr, "   /netmask sets the size of the tunnel network.\n");
	fprintf(stderr, "topdomain is the FQDN that is delegated to this server.\n");
	exit(0);
}

static void
version() {
	fprintf(stderr, "iodine IP over DNS tunneling server\n");
	fprintf(stderr, "version: 0.7.0 from 2014-06-16\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	extern char *__progname;
	char *listen_ip;
	char *errormsg;
#ifndef WINDOWS32
	struct passwd *pw;
#endif
	int foreground;
	char *username;
	char *newroot;
	char *context;
	char *device;
	char *pidfile;
	int dnsd_fd;
	int tun_fd;

	/* settings for forwarding normal DNS to
	 * local real DNS server */
	int bind_fd;
	int bind_enable;

	int choice;
	int port;
	int mtu;
	int skipipconfig;
	char *netsize;
	int ns_get_externalip;
	int retval;
	int max_idle_time = 0;
	struct sockaddr_storage dnsaddr;
	int dnsaddr_len;
#ifdef HAVE_SYSTEMD
	int nb_fds;
#endif

#ifndef WINDOWS32
	pw = NULL;
#endif
	errormsg = NULL;
	username = NULL;
	newroot = NULL;
	context = NULL;
	device = NULL;
	foreground = 0;
	bind_enable = 0;
	bind_fd = 0;
	mtu = 1130;	/* Very many relays give fragsize 1150 or slightly
			   higher for NULL; tun/zlib adds ~17 bytes. */
	listen_ip = NULL;
	port = 53;
	ns_ip = INADDR_ANY;
	ns_get_externalip = 0;
	check_ip = 1;
	skipipconfig = 0;
	debug = 0;
	netmask = 27;
	pidfile = NULL;

	b32 = get_base32_encoder();
	b64 = get_base64_encoder();
	b64u = get_base64u_encoder();
	b128 = get_base128_encoder();

	retval = 0;

#ifdef WINDOWS32
	WSAStartup(req_version, &wsa_data);
#endif

#if !defined(BSD) && !defined(__GLIBC__)
	__progname = strrchr(argv[0], '/');
	if (__progname == NULL)
		__progname = argv[0];
	else
		__progname++;
#endif

	memset(password, 0, sizeof(password));
	srand(time(NULL));
	fw_query_init();

	while ((choice = getopt(argc, argv, "vcsfhDu:t:d:m:l:p:n:b:P:z:F:i:")) != -1) {
		switch(choice) {
		case 'v':
			version();
			break;
		case 'c':
			check_ip = 0;
			break;
		case 's':
			skipipconfig = 1;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			help();
			break;
		case 'D':
			debug++;
			break;
		case 'u':
			username = optarg;
			break;
		case 't':
			newroot = optarg;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mtu = atoi(optarg);
			break;
		case 'l':
			listen_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			if (optarg && strcmp("auto", optarg) == 0) {
				ns_get_externalip = 1;
			} else {
				ns_ip = inet_addr(optarg);
			}
			break;
		case 'b':
			bind_enable = 1;
			bind_port = atoi(optarg);
			break;
		case 'F':
			pidfile = optarg;
			break;
		case 'i':
			max_idle_time = atoi(optarg);
			break;
		case 'P':
			strncpy(password, optarg, sizeof(password));
			password[sizeof(password)-1] = 0;

			/* XXX: find better way of cleaning up ps(1) */
			memset(optarg, 0, strlen(optarg));
			break;
		case 'z':
			context = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	check_superuser(usage);

	if (argc != 2)
		usage();

	netsize = strchr(argv[0], '/');
	if (netsize) {
		*netsize = 0;
		netsize++;
		netmask = atoi(netsize);
	}

	my_ip = inet_addr(argv[0]);

	if (my_ip == INADDR_NONE) {
		warnx("Bad IP address to use inside tunnel.");
		usage();
	}

	topdomain = strdup(argv[1]);
	if(check_topdomain(topdomain, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	if (username != NULL) {
#ifndef WINDOWS32
		if ((pw = getpwnam(username)) == NULL) {
			warnx("User %s does not exist!", username);
			usage();
		}
#endif
	}

	if (mtu <= 0) {
		warnx("Bad MTU given.");
		usage();
	}

	if(port < 1 || port > 65535) {
		warnx("Bad port number given.");
		usage();
	}

	if (port != 53) {
		fprintf(stderr, "ALERT! Other dns servers expect you to run on port 53.\n");
		fprintf(stderr, "You must manually forward port 53 to port %d for things to work.\n", port);
	}

	if (debug) {
		fprintf(stderr, "Debug level %d enabled, will stay in foreground.\n", debug);
		fprintf(stderr, "Add more -D switches to set higher debug level.\n");
		foreground = 1;
	}

	dnsaddr_len = get_addr(listen_ip, port, AF_INET, AI_PASSIVE | AI_NUMERICHOST, &dnsaddr);
	if (dnsaddr_len < 0) {
		warnx("Bad IP address to listen on.");
		usage();
	}

	if(bind_enable) {
		in_addr_t dns_ip = ((struct sockaddr_in *) &dnsaddr)->sin_addr.s_addr;
		if (bind_port < 1 || bind_port > 65535) {
			warnx("Bad DNS server port number given.");
			usage();
			/* NOTREACHED */
		}
		/* Avoid forwarding loops */
		if (bind_port == port && (dns_ip == INADDR_ANY || dns_ip == htonl(0x7f000001L))) {
			warnx("Forward port is same as listen port (%d), will create a loop!", bind_port);
			fprintf(stderr, "Use -l to set listen ip to avoid this.\n");
			usage();
			/* NOTREACHED */
		}
		fprintf(stderr, "Requests for domains outside of %s will be forwarded to port %d\n",
			topdomain, bind_port);
	}

	if (ns_get_externalip) {
		struct in_addr extip;
		int res = get_external_ip(&extip);
		if (res) {
			fprintf(stderr, "Failed to get external IP via web service.\n");
			exit(3);
		}
		ns_ip = extip.s_addr;
		fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(extip));
	}

	if (ns_ip == INADDR_NONE) {
		warnx("Bad IP address to return as nameserver.");
		usage();
	}
	if (netmask > 30 || netmask < 8) {
		warnx("Bad netmask (%d bits). Use 8-30 bits.", netmask);
		usage();
	}

	if (strlen(password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(password, sizeof(password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(password, sizeof(password));
	}

	created_users = init_users(my_ip, netmask);

	if ((tun_fd = open_tun(device)) == -1) {
		retval = 1;
		goto cleanup0;
	}
	if (!skipipconfig) {
		const char *other_ip = users_get_first_ip();
		if (tun_setip(argv[0], other_ip, netmask) != 0 || tun_setmtu(mtu) != 0) {
			retval = 1;
			free((void*) other_ip);
			goto cleanup1;
		}
		free((void*) other_ip);
	}
#ifdef HAVE_SYSTEMD
	nb_fds = sd_listen_fds(0);
	if (nb_fds > 1) {
		retval = 1;
		warnx("Too many file descriptors received!\n");
		goto cleanup1;
	} else if (nb_fds == 1) {
		dnsd_fd = SD_LISTEN_FDS_START;
	} else {
#endif
		if ((dnsd_fd = open_dns(&dnsaddr, dnsaddr_len)) < 0) {
			retval = 1;
			goto cleanup2;
		}
#ifdef HAVE_SYSTEMD
	}
#endif
	if (bind_enable) {
		if ((bind_fd = open_dns_from_host(NULL, 0, AF_INET, 0)) < 0) {
			retval = 1;
			goto cleanup3;
		}
	}

	my_mtu = mtu;

	if (created_users < USERS) {
		fprintf(stderr, "Limiting to %d simultaneous users because of netmask /%d\n",
			created_users, netmask);
	}
	fprintf(stderr, "Listening to dns for domain %s\n", topdomain);

	if (foreground == 0)
		do_detach();

	if (pidfile != NULL)
		do_pidfile(pidfile);

#ifdef FREEBSD
	tzsetwall();
#endif
#ifndef WINDOWS32
	openlog( __progname, LOG_NDELAY, LOG_DAEMON );
#endif

	if (newroot != NULL)
		do_chroot(newroot);

	signal(SIGINT, sigint);
	if (username != NULL) {
#ifndef WINDOWS32
		gid_t gids[1];
		gids[0] = pw->pw_gid;
		if (setgroups(1, gids) < 0 || setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			warnx("Could not switch to user %s!\n", username);
			usage();
		}
#endif
	}

	if (context != NULL)
		do_setcon(context);

	syslog(LOG_INFO, "started, listening on port %d", port);

	tunnel(tun_fd, dnsd_fd, bind_fd, max_idle_time);

	syslog(LOG_INFO, "stopping");
cleanup3:
	close_dns(bind_fd);
cleanup2:
	close_dns(dnsd_fd);
cleanup1:
	close_tun(tun_fd);
cleanup0:

	return retval;
}
