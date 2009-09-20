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

#ifndef __USER_H__
#define __USER_H__

#define USERS 16

#define OUTPACKETQ_LEN 4		/* Note: 16 users * 1 packet = 1MB */
/* Undefine to have no queue for packets coming in from tun device, which may
   lead to massive dropping in multi-user situations with high traffic. */

#define DNSCACHE_LEN 4
/* Undefine to disable. MUST be less than 7; also see comments in iodined.c */

struct user {
	char id;
	int active;
	int disabled;
	time_t last_pkt;
	int seed;
	in_addr_t tun_ip;
	struct in_addr host;
	struct query q;
	struct query q_prev;
	struct query q_sendrealsoon;
	int q_sendrealsoon_new;
	struct packet inpacket;
	struct packet outpacket;
	int outfragresent;
	struct encoder *encoder;
	char downenc;
	int out_acked_seqno;
	int out_acked_fragment;
	int fragsize;
	enum connection conn;
	int lazy;
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

extern struct user users[USERS];

int init_users(in_addr_t, int);
int users_waiting_on_reply();
int find_user_by_ip(uint32_t);
int all_users_waiting_to_send();
int find_available_user();
void user_switch_codec(int userid, struct encoder *enc);
void user_set_conn_type(int userid, enum connection c);

#endif
