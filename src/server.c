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
#include <err.h>

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
#include "server.h"
#include "window.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
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
send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd, struct query *q)
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

int
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

/* INLINE FUNCTION DEFINITIONS */
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

	warnx("save_to_qmem_pingordata deprecated! use something else instead!");
	uint8_t cmc[8];
	int i;

	if (q->name[0] == 'P' || q->name[0] == 'p') {
		/* Ping packet */

		size_t cmcsize = sizeof(cmc);
		char *cp = strchr(q->name, '.');

		if (cp == NULL)
			return;  /* illegal hostname; shouldn't happen */

		/* We already unpacked in handle_null_request(), but that's
		   lost now... Note: b32 directly, we want no undotify here! */
		i = b32->decode(cmc, &cmcsize, (uint8_t *)q->name + 1, (cp - q->name) - 1);

		if (i < 4)
			return;	 /* illegal ping; shouldn't happen */

		/*save_to_qmem(users[userid].qmemping_cmc,
			     users[userid].qmemping_type, QMEMPING_LEN,
			     &users[userid].qmemping_lastfilled,
			     (void *) cmc, q->type);*/
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

		/*save_to_qmem(users[userid].qmemdata_cmc,
			     users[userid].qmemdata_type, QMEMDATA_LEN,
			     &users[userid].qmemdata_lastfilled,
			     (void *) cmc, q->type);*/
	}
}

static inline int
answer_from_qmem_data(int dns_fd, int userid, struct query *q)
/* Quick helper function to keep handle_null_request() clean */
{
	warnx("answer_from_qmem_data deprecated! use something else");
	/*char cmc[4];
	int i;

	for (i = 0; i < 4; i++)
		if (q->name[i+1] >= 'A' && q->name[i+1] <= 'Z')
			cmc[i] = q->name[i+1] + ('a' - 'A');
		else
			cmc[i] = q->name[i+1];

	return answer_from_qmem(dns_fd, q, users[userid].qmemdata_cmc,
				users[userid].qmemdata_type, QMEMDATA_LEN,
				(void *) cmc);*/
	return 0;
}
/* END INLINE FUNCTION DEFINITIONS */

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
   otherwise equal, which they arent: up/downstream seq, TCP/IP headers and
   the actual data
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

	if (debug >= 2) {
		fprintf(stderr, "TX: NS reply \n");
	}

	if (sendto(bind_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("forward query error");
	}
}

static int
send_frag_or_dataless(int dns_fd, int userid, struct query *q, int ping)
/* Sends current fragment to user, or a ping if no data available.
   Does not update anything, except:
   - discards q always (query is used)
   - forgets entire users[userid].outpacket if it was sent in one go,
     and then tries to get new packet from outpacket-queue
   Returns: 1 = can call us again immediately, new packet from queue;
   0 = don't call us again for now.
*/
{
	static uint8_t pkt[MAX_FRAGSIZE + DOWNSTREAM_PING_HDR];
	size_t datalen, headerlen;
	fragment *f;
	struct frag_buffer *out, *in;

	in = users[userid].incoming;
	out = users[userid].outgoing;

	f = window_get_next_sending_fragment(out, &users[userid].next_upstream_ack);
	if (!f) {
		/* No data, may as well send data/ping header (with extra info) */
		ping = 1;
		datalen = 0;
		pkt[0] = 0; /* Pings don't need seq IDs unless they have data */
		pkt[1] = users[userid].next_upstream_ack & 0xFF;
		pkt[2] = (1 << 5) | ((users[userid].next_upstream_ack < 0 ? 0 : 1) << 3);
		/* TODO: resend ACKs in pings? */
		users[userid].next_upstream_ack = -1;
	} else {
		datalen = f->len;
		pkt[0] = f->seqID & 0xFF;
		pkt[1] = f->ack_other & 0xFF;
		pkt[2] = ((f->compressed & 1) << 4) | ((f->ack_other < 0 ? 0 : 1) << 3) |
			(f->is_nack << 2) | (f->start << 1) | f->end;
		headerlen = DOWNSTREAM_HDR;
	}

	/* Build downstream data/ping header (see doc/proto_xxxxxxxx.txt) for details */

	if (ping) { /* TODO: pings with downstream data */
		pkt[3] = out->windowsize & 0xFF;
		pkt[4] = in->windowsize & 0xFF;
		pkt[5] = out->start_seq_id & 0xFF;
		pkt[6] = in->start_seq_id & 0xFF;
		headerlen = DOWNSTREAM_PING_HDR;
	}
	if (datalen + headerlen > sizeof(pkt)) {
		warnx("send_frag_or_dataless: fragment too large to send! (%lu)", datalen);
		return 0;
	}
	if (f) memcpy(pkt + headerlen, f->data, datalen);
	write_dns(dns_fd, q, (char *)pkt, datalen + headerlen, users[userid].downenc);

	/* TODO: reply to any duplicates (q.id2 etc) */

//	save_to_qmem_pingordata(userid, q);

#ifdef DNSCACHE_LEN
	save_to_dnscache(userid, q, (char *)pkt, datalen + 2);
#endif
	/* this query has been used */
	q->id = 0;
	window_tick(out);

	/* call again if we have more things to send */
	return users[userid].outgoing->numitems > 0;
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

	// TODO: use htonl for compatibility with big-endian systems
	out[4] = ((payload >> 24) & 0xff);
	out[5] = ((payload >> 16) & 0xff);
	out[6] = ((payload >> 8) & 0xff);
	out[7] = ((payload) & 0xff);
	out[8] = userid & 0xff;

	write_dns(fd, q, out, sizeof(out), users[userid].downenc);
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
	unsigned long outlen;
	struct ip *header;
	static uint8_t out[64*1024];
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

	outlen = sizeof(out);
	compress2(out, &outlen, in, read, 9);

	if (users[userid].conn == CONN_DNS_NULL) {

		window_add_outgoing_data(users[userid].outgoing, out, outlen, 1);

		/* TODO: Start sending immediately if query is waiting
		 * Need to get incoming query handling done first. */

		return outlen;
	} else { /* CONN_RAW_UDP */
		int dns_fd = get_dns_fd(dns_fds, &users[userid].q.from);
		send_raw(dns_fd, out, outlen, userid, RAW_HDR_CMD_DATA, &users[userid].q);
		return outlen;
	}
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

	if (debug >= 2) {
		fprintf(stderr, "RX: client %s ID %5d, type %d, name %s\n",
			format_addr(&q.from, q.fromlen), q.id, q.type, q.name);
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
		if (debug >= 3) {
			fprintf(stderr, "Requested domain outside our topdomain.\n");
		}
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
	time_t last_action = time(NULL);

	while (running) {
		int maxfd;
		tv.tv_sec = 5; /* TODO: adjust time based on query timeouts (lazy mode) */
		tv.tv_usec = 0;

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

		if (i == 0) {
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
handle_full_packet(int tun_fd, struct dnsfd *dns_fds, int userid, uint8_t *data, size_t len)
{
	size_t outlen;
	uint8_t out[64*1024];
	struct ip *hdr;
	int touser;
	int ret; // TODO: optional upstream compression flag
	outlen = sizeof(out);
	if ((ret = uncompress(out, &outlen, data, len)) == Z_OK) {
		hdr = (struct ip*) (out + 4);
		touser = find_user_by_ip(hdr->ip_dst.s_addr);
		if (debug >= 3)
			fprintf(stderr, "FULL PKT: %lu bytes from user %d (touser %d)\n", len, userid, touser);
		if (touser == -1) {
			/* send the uncompressed packet to tun device */
			write_tun(tun_fd, out, outlen);
		} else {
			/* send the compressed (!) packet to other client */
			if (users[touser].conn == CONN_DNS_NULL) {
				window_add_outgoing_data(users[touser].outgoing, data, len, 1);
				/* TODO: send immediately if query waiting */
			} else{ /* CONN_RAW_UDP */
				int dns_fd = get_dns_fd(dns_fds, &users[touser].q.from);
				send_raw(dns_fd, data, len, touser, RAW_HDR_CMD_DATA, &users[touser].q);
			}
		}
	} else {
		if (debug >= 1)
			fprintf(stderr, "Discarded data, uncompress() result: %d\n", ret);
	}
}

static void
handle_raw_login(uint8_t *packet, size_t len, struct query *q, int fd, int userid)
{
	char myhash[16];

	if (len < 16) return;

	/* can't use check_authenticated_user_and_ip() since IP address will be different,
	   so duplicate here except IP address */
	if (userid < 0 || userid >= created_users) return;
	if (!check_authenticated_user_and_ip(userid, q)) return;

	if (debug >= 1) {
		fprintf(stderr, "IN   login raw, len %lu, from user %d\n", len, userid);
	}

	/* User sends hash of seed + 1 */
	login_calculate(myhash, 16, password, users[userid].seed + 1);
	if (memcmp(packet, myhash, 16) == 0) {
		/* Update query and time info for user */
		users[userid].last_pkt = time(NULL);
		memcpy(&(users[userid].q), q, sizeof(struct query));

		/* Store remote IP number */
		memcpy(&(users[userid].host), &(q->from), q->fromlen);
		users[userid].hostlen = q->fromlen;

		/* Correct hash, reply with hash of seed - 1 */
		user_set_conn_type(userid, CONN_RAW_UDP);
		login_calculate(myhash, 16, password, users[userid].seed - 1);
		send_raw(fd, (uint8_t *)myhash, 16, userid, RAW_HDR_CMD_LOGIN, q);

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

	/* Update query and time info for user */
	users[userid].last_pkt = time(NULL);
	memcpy(&(users[userid].q), q, sizeof(struct query));

	/* copy to packet buffer, update length TODO fix the raw UDP protocol */

	if (debug >= 1) {
		fprintf(stderr, "IN   pkt raw, total %lu, from user %d\n", len, userid);
	}

	handle_full_packet(tun_fd, dns_fds, userid, packet, len);
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
raw_decode(uint8_t *packet, size_t len, struct query *q, int dns_fd, struct dnsfd *dns_fds, int tun_fd)
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
		handle_raw_data(&packet[RAW_HDR_LEN], len - RAW_HDR_LEN, q, dns_fds, tun_fd, raw_user);
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
		memcpy((struct sockaddr*)&q->from, (struct sockaddr*)&from, addrlen);
		q->fromlen = addrlen;

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
	static int td1 = 0;
	static int td2 = 0;
	size_t space;
	uint8_t *b;

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
	b += strlen((char *)buf) - 1;
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

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s ID %5d, %lu bytes data, type %d, name '%10s'\n",
			format_addr(&q->from, q->fromlen), q->id, datalen, q->type, q->name);
	}

	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

void
send_data_or_ping_response(int tun_fd, int dns_fd, struct dnsfd *dns_fds, int userid, struct query *q, int ping) {
	uint8_t unpacked[64*1024];
	size_t read;

	/* if waiting for an ACK to be sent back upstream (on incoming buffer) */
	if (users[userid].next_upstream_ack < 0) {
		users[userid].next_upstream_ack = window_get_next_ack(users[userid].incoming);
	}
	window_tick(users[userid].outgoing);

	read = window_reassemble_data(users[userid].incoming, unpacked, sizeof(unpacked), NULL);
	window_tick(users[userid].incoming);

	if (read > 0) { /* Data reassembled successfully + cleared out of buffer */
		handle_full_packet(tun_fd, dns_fds, userid, unpacked, read);
	}

	send_frag_or_dataless(dns_fd, userid, q, ping);

	/* Save new query and time info */
	memcpy(&(users[userid].q), q, sizeof(struct query));
	users[userid].last_pkt = time(NULL);
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

	if (debug >= 3) {
		fprintf(stderr, "NULL request length %d/%lu, command '%c'\n", domain_len, sizeof(in), in[0]);
	}

	if(in[0] == 'V' || in[0] == 'v') { /* Version request */
		int version = 0;

		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);
		/* Version greeting, compare and send ack/nak */
		if (read > 4) {
			/* Received V + 32bits version */
			// TODO htonl/ntohl for portability
			version = (((unpacked[0] & 0xff) << 24) |
					   ((unpacked[1] & 0xff) << 16) |
					   ((unpacked[2] & 0xff) << 8) |
					   ((unpacked[3] & 0xff)));
		}

		if (version == PROTOCOL_VERSION) {
			userid = find_available_user();
			if (userid >= 0) {
				int i;
				struct tun_user *u = &users[userid];
				u->seed = rand();
				/* Store remote IP number */
				memcpy(&(u->host), &(q->from), q->fromlen);
				u->hostlen = q->fromlen;

				memcpy(&(u->q), q, sizeof(struct query));
				u->encoder = get_base32_encoder();
				u->downenc = 'T';
				u->downenc_bits = 5;
				send_version_response(dns_fd, VERSION_ACK, u->seed, userid, q);
				syslog(LOG_INFO, "accepted version for user #%d from %s",
					userid, format_addr(&q->from, q->fromlen));
				u->q.id = 0;
				u->q.id2 = 0;
				u->fragsize = 100; /* very safe */
				u->conn = CONN_DNS_NULL;
				u->lazy = 0;
				// TODO: client specified window size
				u->incoming = window_buffer_init(INFRAGBUF_LEN, 10, MAX_FRAGSIZE, WINDOW_RECVING);
				u->outgoing = window_buffer_init(OUTFRAGBUF_LEN, 10,
							u->encoder->get_raw_length(u->fragsize) - DOWNSTREAM_PING_HDR, WINDOW_SENDING);
				u->next_upstream_ack = -1;
#ifdef DNSCACHE_LEN
				{
					for (i = 0; i < DNSCACHE_LEN; i++) {
						u->dnscache_q[i].id = 0;
						u->dnscache_answerlen[i] = 0;
					}
				}
				u->dnscache_lastfilled = 0;
#endif
				/*for (i = 0; i < QMEMPING_LEN; i++)
				        u->qmemping_type[i] = T_UNSET;
				u->qmemping_lastfilled = 0;
				for (i = 0; i < QMEMDATA_LEN; i++)
				        u->qmemdata_type[i] = T_UNSET;
				u->qmemdata_lastfilled = 0;*/
				if (debug >= 1)
					fprintf(stderr, "User %d connected with correct version from %s.\n",
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
		read = unpack_data(unpacked, sizeof(unpacked), &(in[1]), domain_len - 1, b32);
		if (read < 17) {
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		/* Login phase, handle auth */
		userid = unpacked[0];
		if (debug >= 3)
			fprintf(stderr, "Received login request for user %d from %s.\n",
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
	} else if(in[0] == 'Z' || in[0] == 'z') {
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
	} else if(in[0] == 'O' || in[0] == 'o') { /* Protocol options */
		if (domain_len < 3) { /* len at least 3, example: "O1T" */
			write_dns(dns_fd, q, "BADLEN", 6, 'T');
			return;
		}

		userid = b32_8to5(in[1]);

		if (check_authenticated_user_and_ip(userid, q) != 0) {
			write_dns(dns_fd, q, "BADIP", 5, 'T');
			return; /* illegal id */
		}

		int bits = 0;
		switch (in[2]) {
		case 'T':
		case 't':
			users[userid].downenc = 'T';
			write_dns(dns_fd, q, "Base32", 6, users[userid].downenc);
			bits = 5;
			break;
		case 'S':
		case 's':
			users[userid].downenc = 'S';
			write_dns(dns_fd, q, "Base64", 6, users[userid].downenc);
			bits = 6;
			break;
		case 'U':
		case 'u':
			users[userid].downenc = 'U';
			write_dns(dns_fd, q, "Base64u", 7, users[userid].downenc);
			bits = 6;
			break;
		case 'V':
		case 'v':
			users[userid].downenc = 'V';
			write_dns(dns_fd, q, "Base128", 7, users[userid].downenc);
			bits = 7;
			break;
		case 'R':
		case 'r':
			users[userid].downenc = 'R';
			write_dns(dns_fd, q, "Raw", 3, users[userid].downenc);
			bits = 8;
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
		if (bits) {
			int f = users[userid].fragsize;
			users[userid].outgoing->maxfraglen = (bits * f) / 8 - DOWNSTREAM_PING_HDR;
			if (debug >= 1)
				warnx("Setting max downstream data length to %u bytes for user %d; bits %d (%c)",
					  users[userid].outgoing->maxfraglen, userid, bits, users[userid].downenc);
			users[userid].downenc_bits = bits;
		}
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

	} else if(in[0] == 'R' || in[0] == 'r') { /* Downstream fragsize probe */
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
		if (debug >= 3) {
			fprintf(stderr, "Got downstream fragsize probe from user %d, required fragsize %d\n", userid, req_frag_size);
		}

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
	} else if(in[0] == 'N' || in[0] == 'n') { /* Downstream fragsize (NS.topdomain A-type reply) */
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
			users[userid].outgoing->maxfraglen = (users[userid].downenc_bits * max_frag_size) /
				8 - DOWNSTREAM_PING_HDR;
			write_dns(dns_fd, q, (char *) unpacked + 1, 2, users[userid].downenc);

			if (debug >= 1)
				warnx("Setting max downstream data length to %u bytes for user %d; bits %d (%c)",
					  users[userid].outgoing->maxfraglen, userid, users[userid].downenc_bits, users[userid].downenc);
		}
		return;
	} else if(in[0] == 'P' || in[0] == 'p') { /* Ping request */
		int dn_seq, up_seq, dn_wins, up_wins, dn_ack;
		int respond;

		/* We can't handle id=0, that's "no packet" to us. So drop
		   request completely. Note that DNS servers rewrite the id.
		   We'll drop 1 in 64k times. If DNS server retransmits with
		   different id, then all okay.
		   Else client won't retransmit, and we'll just keep the
		   previous ping in cache, no problem either. */
		if (q->id == 0)
			return;

		read = unpack_data(unpacked, sizeof(unpacked), in + 1, domain_len - 1, b32);
		if (read < UPSTREAM_PING) {
			if (debug >= 1) warnx("Invalid ping! Length %lu", read);
			return;
		}

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
		/* TODO: incoming query handling for lazy mode */
		/* Check if duplicate (and not in full dnscache any more) * /
		if (answer_from_qmem(dns_fd, q, users[userid].qmemping_cmc,
				     users[userid].qmemping_type, QMEMPING_LEN,
				     (void *) unpacked))
			return; */

		dn_ack = ((unpacked[6] >> 2) & 1) ? unpacked[1] : -1;
		up_wins = unpacked[2];
		dn_wins = unpacked[3];
		dn_seq = unpacked[4];
		up_seq = unpacked[5];
		respond = unpacked[6] & 1;

		/* TODO: Use ping to re-sync window buffer */
		if (debug >= 2) {
			fprintf(stderr, "PING pkt from user %d, down %d/%d, up %d/%d, ACK %d\n", userid, dn_seq, dn_wins, up_seq, up_wins, dn_ack);
		}

		window_ack(users[userid].outgoing, dn_ack);

		send_data_or_ping_response(tun_fd, dns_fd, dns_fds, userid, q, respond);

	} else if((in[0] >= '0' && in[0] <= '9') /* Upstream data packet */
			|| (in[0] >= 'a' && in[0] <= 'f')
			|| (in[0] >= 'A' && in[0] <= 'F')) {
		int code = -1;
		static fragment f;
		size_t len;

		/* Need 6 char header + >=1 char data */
		if (domain_len < 7)
			return;

		/* We can't handle id=0, that's "no packet" to us. So drop
		   request completely. Note that DNS servers rewrite the id.
		   We'll drop 1 in 64k times. If DNS server retransmits with
		   different id, then all okay.
		   Else client doesn't get our ack, and will retransmit in
		   1 second. */
		if (q->id == 0) {
			warnx("Query with ID 0!");
			return;
		}

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
		/* TODO: incoming query buffer/handling for lazy mode */

		/* TODO: Check if duplicate of waiting queries (ping and data) */

		/* Decode upstream data header - see docs/proto_XXXXXXXX.txt */
		/* First byte (after userid) = CMC (ignored) */
//		f.seqID = (b32_8to5(in[2]) << 2) | (b32_8to5(in[3]) >> 2);
//		f.ack_other = (b32_8to5(in[5]) & 8) ? ((b32_8to5(in[3]) & 3) << 6)
//			| (b32_8to5(in[4]) << 1) | ((b32_8to5(in[5]) >> 4) & 1) : -1;
//		f.is_nack = (b32_8to5(in[5]) >> 2) & 1;
//		f.start = (b32_8to5(in[5]) >> 1) & 1;
//		f.end = b32_8to5(in[5]) & 1;
		len = sizeof(unpacked);
		read = b32->decode(unpacked, &len, in + 2, 5);
		f.seqID = unpacked[0];
		unpacked[2] >>= 4; /* Lower 4 bits are unused */
		f.ack_other = ((unpacked[2] >> 3) & 1) ? unpacked[1] : -1;
		f.is_nack = (unpacked[2] >> 2) & 1;
		f.start = (unpacked[2] >> 1) & 1;
		f.end = unpacked[2] & 1;

		/* Decode remainder of data with user encoding */
		read = unpack_data(unpacked, sizeof(unpacked), in + UPSTREAM_HDR,
							domain_len - UPSTREAM_HDR, users[userid].encoder);
		if (debug >= 4) warnx("++++ UNPACKED %d bytes into %lu using %s with header len %d",
							  domain_len, read, users[userid].encoder->name, UPSTREAM_HDR);

		f.len = MIN(read, MAX_FRAGSIZE);
		memcpy(f.data, unpacked, f.len);

		window_process_incoming_fragment(users[userid].incoming, &f);

		window_ack(users[userid].outgoing, f.ack_other);

		send_data_or_ping_response(tun_fd, dns_fd, dns_fds, userid, q, 0);
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

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s ID %5d, type %d, name %s, %d bytes NS reply\n",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	}
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

	if (debug >= 2) {
		fprintf(stderr, "TX: client %s ID %5d, type %d, name %s, %d bytes A reply\n",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	}
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("a reply send error");
	}
}
