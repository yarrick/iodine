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

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "window.h"

extern int debug;
extern int stats;

#define PENDING_QUERIES_LENGTH (MAX(this.windowsize_up, this.windowsize_down) * 4)
#define INSTANCE this

struct client_instance {
	int max_downstream_frag_size;
	int autodetect_frag_size;
	int hostname_maxlen;
	int raw_mode;
	int foreground;
	char password[33];

	/* DNS nameserver info */
	char **nameserv_hosts;
	size_t nameserv_hosts_len;
	struct sockaddr_storage *nameserv_addrs;
	size_t nameserv_addrs_len;
	int current_nameserver;
	struct sockaddr_storage raw_serv;
	int raw_serv_len;
	char *topdomain;

	/* Remote TCP forwarding stuff (for -R) */
	struct sockaddr_storage remote_forward_addr;
	int use_remote_forward; /* 0 if no forwarding used */
	int remote_forward_connected;

	int tun_fd;
	int dns_fd;

#ifdef OPENBSD
	int rtable;
#endif
	int running;

	/* Output flags for debug and time between stats update */
	int debug;
	int stats;

	uint16_t rand_seed;

	/* Current up/downstream window data */
	struct frag_buffer *outbuf;
	struct frag_buffer *inbuf;
	size_t windowsize_up;
	size_t windowsize_down;
	size_t maxfragsize_up;

	/* Next downstream seqID to be ACK'd (-1 if none pending) */
	int next_downstream_ack;

	/* Remembering queries we sent for tracking purposes */
	struct query_tuple *pending_queries;
	size_t num_pending;
	time_t max_timeout_ms;
	time_t send_interval_ms;
	time_t min_send_interval_ms;

	/* Server response timeout in ms and downstream window timeout */
	time_t server_timeout_ms;
	time_t downstream_timeout_ms;
	int autodetect_server_timeout;

	/* Cumulative Round-Trip-Time in ms */
	time_t rtt_total_ms;
	size_t num_immediate;

	/* Connection statistics */
	size_t num_timeouts;
	size_t num_untracked;
	size_t num_servfail;
	size_t num_badip;
	size_t num_sent;
	size_t num_recv;
	size_t send_query_sendcnt;
	size_t send_query_recvcnt;
	size_t num_frags_sent;
	size_t num_frags_recv;
	size_t num_pings;

	/* My userid at the server */
	char userid;
	char userid_char;		/* used when sending (lowercase) */
	char userid_char2;		/* also accepted when receiving (uppercase) */

	uint16_t chunkid;

	/* Base32 encoder used for non-data packets and replies */
	struct encoder *b32;
	/* Base64 etc encoders for replies */
	struct encoder *b64;
	struct encoder *b64u;
	struct encoder *b128;

	/* The encoder used for data packets
	 * Defaults to Base32, can be changed after handshake */
	struct encoder *dataenc;

	/* Upstream/downstream compression flags */
	int compression_up;
	int compression_down;

	/* The encoder to use for downstream data */
	char downenc;

	/* set query type to send */
	uint16_t do_qtype;

	/* My connection mode */
	enum connection conn;
	int connected;

	int lazymode;
	long send_ping_soon;
	time_t lastdownstreamtime;
};

struct query_tuple {
	int id; /* DNS query / response ID */
	struct timeval time; /* time sent or 0 if cleared */
};

extern struct client_instance this;

void client_init();
void client_stop();

enum connection client_get_conn();
const char *client_get_raw_addr();

void client_rotate_nameserver();
int client_set_qtype(char *qtype);
char *format_qtype();
char parse_encoding(char *encoding);
void client_set_hostname_maxlen(size_t i);

int client_handshake();
int client_tunnel();

int parse_data(uint8_t *data, size_t len, fragment *f, int *immediate, int*);
int handshake_waitdns(char *buf, size_t buflen, char cmd, int timeout);
void handshake_switch_options(int lazy, int compression, char denc);
int send_ping(int ping_response, int ack, int timeout, int);

#endif
