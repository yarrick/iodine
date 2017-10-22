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

#ifndef __USER_H__
#define __USER_H__

#define USERS 16

#define OUTPACKETQ_LEN 4		/* Note: 16 users * 1 packet = 1MB */
/* Undefine to have no queue for packets coming in from tun device, which may
   lead to massive dropping in multi-user situations with high traffic. */

#define DNSCACHE_LEN 4
/* Undefine to disable. Should be less than 18; also see comments in iodined.c */


#define QMEMPING_LEN 30
/* Max advisable: 64k/2 = 32000. Total mem usage: QMEMPING_LEN * USERS * 6 bytes */

#define QMEMDATA_LEN 15
/* Max advisable: 36/2 = 18. Total mem usage: QMEMDATA_LEN * USERS * 6 bytes */

struct tun_user {
	char id;
	int active;
	int authenticated;
	int authenticated_raw;
	int options_locked;
	int disabled;
	time_t last_pkt;
	int seed;
	in_addr_t tun_ip;
	struct sockaddr_storage host;
	socklen_t hostlen;
	struct query q;
	struct query q_sendrealsoon;
	int q_sendrealsoon_new;
	struct packet inpacket;
	struct packet outpacket;
	int outfragresent;
	const struct encoder *encoder;
	char downenc;
	int out_acked_seqno;
	int out_acked_fragment;
	int fragsize;
	enum connection conn;
	int lazy;
	unsigned char qmemping_cmc[QMEMPING_LEN * 4];
	unsigned short qmemping_type[QMEMPING_LEN];
	int qmemping_lastfilled;
	unsigned char qmemdata_cmc[QMEMDATA_LEN * 4];
	unsigned short qmemdata_type[QMEMDATA_LEN];
	int qmemdata_lastfilled;
#ifdef OUTPACKETQ_LEN
	struct packet outpacketq[OUTPACKETQ_LEN];
	int outpacketq_nexttouse;
	int outpacketq_filled;
#endif
#ifdef DNSCACHE_LEN
	struct query dnscache_q[DNSCACHE_LEN];
	char dnscache_answer[DNSCACHE_LEN][4096];
	int dnscache_answerlen[DNSCACHE_LEN];
	int dnscache_lastfilled;
#endif
};

extern struct tun_user *users;

int init_users(in_addr_t, int);
const char* users_get_first_ip(void);
int find_user_by_ip(uint32_t);
int all_users_waiting_to_send(void);
int find_available_user(void);
void user_switch_codec(int userid, const struct encoder *enc);
void user_set_conn_type(int userid, enum connection c);

#endif
