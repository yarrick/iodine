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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
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
#include <arpa/nameser8_compat.h>
#endif
#include <sys/socket.h>
#include <err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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

#define PING_TIMEOUT(t) ((t) >= (conn == CONN_DNS_NULL ? 1 : 20))

static int running;
static const char *password;

static struct sockaddr_in nameserv;
static struct sockaddr_in raw_serv;
static const char *topdomain;

static uint16_t rand_seed;
static int downstream_seqno;
static int downstream_fragment;
static int down_ack_seqno;
static int down_ack_fragment;

/* Current up/downstream IP packet */
static struct packet outpkt;
static struct packet inpkt;

/* My userid at the server */
static char userid;

/* DNS id for next packet */
static uint16_t chunkid;

/* Base32 encoder used for non-data packets */
static struct encoder *b32;

/* The encoder used for data packets
 * Defaults to Base32, can be changed after handshake */
static struct encoder *dataenc;

/* My connection mode */
static enum connection conn;

void
client_init()
{
	running = 1;
	outpkt.seqno = 0;
	inpkt.len = 0;
	downstream_seqno = 0;
	downstream_fragment = 0;
	down_ack_seqno = 0;
	down_ack_fragment = 0;
	chunkid = 0;
	b32 = get_base32_encoder();
	dataenc = get_base32_encoder();
	rand_seed = rand();
	conn = CONN_DNS_NULL;
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
client_set_nameserver(const char *cp) 
{
	struct in_addr addr;

	if (inet_aton(cp, &addr) != 1)
		errx(1, "error parsing nameserver address: '%s'", cp);

	memset(&nameserv, 0, sizeof(nameserv));
	nameserv.sin_family = AF_INET;
	nameserv.sin_port = htons(53);
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

	q.id = ++chunkid;
	q.type = T_NULL;

	len = dns_encode(packet, sizeof(packet), &q, QR_QUERY, hostname, strlen(hostname));

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
}

static int
build_hostname(char *buf, size_t buflen, 
		const char *data, const size_t datalen, 
		const char *topdomain, struct encoder *encoder)
{
	int encsize;
	size_t space;
	char *b;

	space = MIN(0xFF, buflen) - strlen(topdomain) - 7;
	if (!encoder->places_dots())
		space -= (space / 57); /* space for dots */

	memset(buf, 0, buflen);
	
	encsize = encoder->encode(buf, &space, data, datalen);

	if (!encoder->places_dots())
		inline_dotify(buf, buflen);

	b = buf;
	b += strlen(buf);

	if (*b != '.') 
		*b++ = '.';

	strncpy(b, topdomain, strlen(topdomain)+1);

	return space;
}

static void
send_packet(int fd, char cmd, const char *data, const size_t datalen)
{
	char buf[4096];

	buf[0] = cmd;
	
	build_hostname(buf + 1, sizeof(buf) - 1, data, datalen, topdomain, b32);
	send_query(fd, buf);
}

static int
is_sending()
{
	return (outpkt.len != 0);
}

static void
send_chunk(int fd)
{
	char hex[] = "0123456789ABCDEF";
	char buf[4096];
	int avail;
	int code;
	char *p;

	p = outpkt.data;
	p += outpkt.offset;
	avail = outpkt.len - outpkt.offset;

	outpkt.sentlen = build_hostname(buf + 4, sizeof(buf) - 4, p, avail, topdomain, dataenc);

	/* Build upstream data header (see doc/proto_xxxxxxxx.txt) */

	buf[0] = hex[userid & 15]; /* First byte is 4 bits userid */

	code = ((outpkt.seqno & 7) << 2) | ((outpkt.fragment & 15) >> 2);
	buf[1] = b32_5to8(code); /* Second byte is 3 bits seqno, 2 upper bits fragment count */

	code = ((outpkt.fragment & 3) << 3) | (downstream_seqno & 7);
	buf[2] = b32_5to8(code); /* Third byte is 2 bits lower fragment count, 3 bits downstream packet seqno */

	code = ((downstream_fragment & 15) << 1) | (outpkt.sentlen == avail);
	buf[3] = b32_5to8(code); /* Fourth byte is 4 bits downstream fragment count, 1 bit last frag flag */

	down_ack_seqno = downstream_seqno;
	down_ack_fragment = downstream_fragment;

	outpkt.fragment++;
	send_query(fd, buf);
}

static void
send_ping(int fd)
{
	if (conn == CONN_DNS_NULL) {
		char data[4];
		
		if (is_sending()) {
			outpkt.sentlen = 0;
			outpkt.offset = 0;
			outpkt.len = 0;
		}

		data[0] = userid;
		data[1] = ((downstream_seqno & 7) << 4) | (downstream_fragment & 15);
		data[2] = (rand_seed >> 8) & 0xff;
		data[3] = (rand_seed >> 0) & 0xff;
		
		down_ack_seqno = downstream_seqno;
		down_ack_fragment = downstream_fragment;
		
		rand_seed++;

		send_packet(fd, 'P', data, sizeof(data));
	} else {
		send_raw(fd, NULL, 0, userid, RAW_HDR_CMD_PING);
	}
}

static int
read_dns(int dns_fd, int tun_fd, char *buf, int buflen) /* FIXME: tun_fd needed for raw handling */
{
	struct sockaddr_in from;
	char data[64*1024];
	socklen_t addrlen;
	struct query q;
	int r;

	addrlen = sizeof(struct sockaddr);
	if ((r = recvfrom(dns_fd, data, sizeof(data), 0, 
			  (struct sockaddr*)&from, &addrlen)) == -1) {
		warn("recvfrom");
		return 0;
	}

	if (conn == CONN_DNS_NULL) {
		int rv;

		rv = dns_decode(buf, buflen, &q, QR_ANSWER, data, r);

		/* decode the data header, update seqno and frag before next request */
		if (rv >= 2) {
			downstream_seqno = (buf[1] >> 5) & 7;
			downstream_fragment = (buf[1] >> 1) & 15;
		}


		if (is_sending()) {
			if (chunkid == q.id) {
				/* Got ACK on sent packet */
				outpkt.offset += outpkt.sentlen;
				if (outpkt.offset == outpkt.len) {
					/* Packet completed */
					outpkt.offset = 0;
					outpkt.len = 0;
					outpkt.sentlen = 0;

					/* If the ack contains unacked frag number but no data, 
					 * send a ping to ack the frag number and get more data*/
					if (rv == 2 && (
						downstream_seqno != down_ack_seqno ||
						downstream_fragment != down_ack_fragment
						)) {
						
						send_ping(dns_fd);
					}
				} else {
					/* More to send */
					send_chunk(dns_fd);
				}
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

	outlen = sizeof(out);
	inlen = read;
	compress2((uint8_t*)out, &outlen, (uint8_t*)in, inlen, 9);

	memcpy(outpkt.data, out, MIN(outlen, sizeof(outpkt.data)));
	outpkt.sentlen = 0;
	outpkt.offset = 0;
	outpkt.len = outlen;
	outpkt.seqno++;
	outpkt.fragment = 0;

	if (conn == CONN_DNS_NULL) {
		send_chunk(dns_fd);
	} else {
		send_raw_data(dns_fd);
	}

	return read;
}

static int
tunnel_dns(int tun_fd, int dns_fd)
{
	unsigned long datalen;
	char buf[64*1024];
	size_t read;

	if ((read = read_dns(dns_fd, tun_fd, buf, sizeof(buf))) <= 2) 
		return -1;

	if (downstream_seqno != inpkt.seqno) {
		/* New packet */
		inpkt.seqno = downstream_seqno;
		inpkt.fragment = downstream_fragment;
		inpkt.len = 0;
	} else if (downstream_fragment <= inpkt.fragment) {
		/* Duplicate fragment */
		return -1;
	}
	inpkt.fragment = downstream_fragment;

	datalen = MIN(read - 2, sizeof(inpkt.data) - inpkt.len);

	/* Skip 2 byte data header and append to packet */
	memcpy(&inpkt.data[inpkt.len], &buf[2], datalen);
	inpkt.len += datalen;

	if (buf[1] & 1) { /* If last fragment flag is set */
		/* Uncompress packet and send to tun */
		datalen = sizeof(buf);
		if (uncompress((uint8_t*)buf, &datalen, (uint8_t*) inpkt.data, inpkt.len) == Z_OK) {
			write_tun(tun_fd, buf, datalen);
		}
		inpkt.len = 0;
	}

	/* If we have nothing to send, send a ping to get more data */
	if (!is_sending()) 
		send_ping(dns_fd);
	
	return read;
}

int
client_tunnel(int tun_fd, int dns_fd)
{
	struct timeval tv;
	fd_set fds;
	int rv;
	int i;
	int seconds;

	rv = 0;
	seconds = 0;

	while (running) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;


		FD_ZERO(&fds);
		if ((!is_sending()) || conn == CONN_RAW_UDP) {
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);
		
		if (running == 0)
			break;

		if (i < 0) 
			err(1, "select");

		if (i == 0) { /* timeout */
			seconds++;
		} else {
			if (FD_ISSET(tun_fd, &fds)) {
				seconds = 0;
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
			}
			if (FD_ISSET(dns_fd, &fds)) {
				if (tunnel_dns(tun_fd, dns_fd) <= 0)
					continue;
			} 
		}

		if (PING_TIMEOUT(seconds)) {
			send_ping(dns_fd);
			seconds = 0;
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

	send_packet(fd, 'L', data, sizeof(data));
}

static void
send_fragsize_probe(int fd, int fragsize)
{
	char probedata[256];
	char buf[4096];

	/* build a large query domain which is random and maximum size */
	memset(probedata, MIN(1, rand_seed & 0xff), sizeof(probedata));
	probedata[1] = MIN(1, (rand_seed >> 8) & 0xff);
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

	send_packet(fd, 'N', data, sizeof(data));
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
	char buf[512] = "S_____.";
	buf[1] = b32_5to8(userid);
	buf[2] = b32_5to8(bits);
	
	buf[3] = b32_5to8((rand_seed >> 10) & 0x1f);
	buf[4] = b32_5to8((rand_seed >> 5) & 0x1f);
	buf[5] = b32_5to8((rand_seed ) & 0x1f);
	rand_seed++;

	strncat(buf, topdomain, 512 - strlen(buf));
	send_query(fd, buf);
}
	
static int
handshake_version(int dns_fd, int *seed)
{
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
			read = read_dns(dns_fd, 0, in, sizeof(in));
			
			if(read <= 0) {
				if (read == 0) {
					warn("handshake read");
				}
				/* if read < 0 then warning has been printed already */
				continue;
			}

			if (read >= 9) {
				payload =  (((in[4] & 0xff) << 24) |
						((in[5] & 0xff) << 16) |
						((in[6] & 0xff) << 8) |
						((in[7] & 0xff)));

				if (strncmp("VACK", in, 4) == 0) {
					*seed = payload;
					userid = in[8];

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
	warnx("couldn't connect to server");
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
			read = read_dns(dns_fd, 0, in, sizeof(in));
			
			if(read <= 0) {
				warn("read");
				continue;
			}

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
			len = read_dns(dns_fd, 0, in, sizeof(in));
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
			read = read_dns(dns_fd, 0, in, sizeof(in));
			
			if (read > 0) {
				if (in[0] == 'z' || in[0] == 'Z') {
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
					fprintf(stderr, "Received bad case check reply\n");
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
	fprintf(stderr, "Switching to %s codec\n", dataenc->name);
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
			read = read_dns(dns_fd, 0, in, sizeof(in));
			
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
				fprintf(stderr, "Server switched to codec %s\n", in);
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
	int max_fragsize = 0;

	max_fragsize = 0;
	fprintf(stderr, "Autoprobing max downstream fragment size... (skip with -m fragsize)\n"); 
	while (running && range > 0 && (range >= 8 || !max_fragsize)) {
		for (i=0; running && i<3 ;i++) {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			send_fragsize_probe(dns_fd, proposed_fragsize);

			FD_ZERO(&fds);
			FD_SET(dns_fd, &fds);

			r = select(dns_fd + 1, &fds, NULL, NULL, &tv);

			if(r > 0) {
				read = read_dns(dns_fd, 0, in, sizeof(in));
				
				if (read > 0) {
					/* We got a reply */
					int acked_fragsize = ((in[0] & 0xff) << 8) | (in[1] & 0xff);
					if (acked_fragsize == proposed_fragsize) {
						if (read == proposed_fragsize) {
							fprintf(stderr, "%d ok.. ", acked_fragsize);
							fflush(stderr);
							max_fragsize = acked_fragsize;
						}
					}
					if (strncmp("BADIP", in, 5) == 0) {
						fprintf(stderr, "got BADIP.. ");
						fflush(stderr);
					}
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
		warnx("stopped while autodetecting fragment size (Try probing manually with -m)");
		return 0;
	}
	if (range == 0) {
		/* Tried all the way down to 2 and found no good size */
		fprintf(stderr, "\n");
		warnx("found no accepted fragment size. (Try probing manually with -m)");
		return 0;
	}
	fprintf(stderr, "will use %d\n", max_fragsize);
	return max_fragsize;
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
			read = read_dns(dns_fd, 0, in, sizeof(in));
			
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
	} else {
		if (raw_mode == 0) {
			fprintf(stderr, "Skipping raw mode\n");
		}
		case_preserved = handshake_case_check(dns_fd);

		if (case_preserved) {
			handshake_switch_codec(dns_fd);
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

