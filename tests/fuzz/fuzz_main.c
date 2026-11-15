/*
 * Copyright (c) 2026 Erik Ekman <yarrick@kryo.se>
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

#include "config.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_SYSLOG
#include <syslog.h>
#endif
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "src/common.h"
#include "src/compat.h"
#include "src/encoding.h"
#include "src/random.h"
#include "src/sock.h"
#include "src/tun.h"
#include "src/udp.h"
#include "src/ui.h"

#include "fuzz_main.h"

const char fuzz_password[33] = "fuzzpass";
const uint8_t *current_pkt = NULL;
size_t current_pkt_len = 0;
int suppress_send = 0;

static int quiet_output = 0;
static time_t fuzz_now = 1000000;

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT()
#endif

/* Fixed secure_random for reproducible seeds during fuzzing/testing */
void
secure_random(void *buf, size_t len)
{
	memset(buf, 0x01, len);
}

time_t
time(time_t *t)
{
	if (t != NULL)
		*t = fuzz_now;
	return fuzz_now;
}

#if HAVE_SYSLOG
void
syslog(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}
#endif

/* No-op zlib stubs so fuzzer mutates inner packet bytes without Adler-32 wall */
int ZEXPORT
compress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level)
{
	(void)level;
	if (sourceLen > *destLen)
		return Z_BUF_ERROR;
	memcpy(dest, source, sourceLen);
	*destLen = sourceLen;
	return Z_OK;
}

int ZEXPORT
uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
{
	/* Need 4B TUN header + 20B minimum IPv4 header */
	if (sourceLen < 24 || source[0] == 0xff)
		return Z_DATA_ERROR;
	if (sourceLen > *destLen)
		return Z_BUF_ERROR;
	memcpy(dest, source, sourceLen);
	*destLen = sourceLen;
	return Z_OK;
}

static void
print_packet(const char *name, const char *data, size_t len)
{
	if (quiet_output || suppress_send)
		return;

	printf("%s (%zu bytes):\n", name, len);
	for (size_t i = 0; i < len; i++) {
		printf("%02x%s", (unsigned char) data[i],
		       (i + 1 == len || (i + 1) % 16 == 0) ? "\n" : " ");
	}
}

int
send_udp(sock_t fd, const char *packet, size_t packetlen, struct udp_addr *addr)
{
	(void)fd;
	(void)addr;
	print_packet("send_udp", packet, packetlen);
	return (int) packetlen;
}

int
write_tun(sock_t tun_fd, char *data, size_t len)
{
	(void)tun_fd;
	print_packet("write_tun", data, len);
	fuzz_on_tun_write(data, len);
	return 0;
}

#define MAX_CHAIN_PKTS 32

static int
next_hex_packet(const char *hex, size_t hex_len, size_t *pos,
                uint8_t *out, size_t maxlen, int *has_more)
{
	size_t len = 0;
	int hi = -1;
	size_t i = *pos;

	*has_more = 0;
	for (; i < hex_len; i++) {
		char c = hex[i];
		int v = -1;

		if (c == '#') {
			while (i < hex_len && hex[i] != '\n')
				i++;
			continue;
		}
		if (c == ';') {
			*pos = i + 1;
			*has_more = 1;
			break;
		}
		if (c >= '0' && c <= '9')
			v = c - '0';
		else if (c >= 'a' && c <= 'f')
			v = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			v = c - 'A' + 10;
		else if (isspace((unsigned char) c))
			continue;
		else if (hi < 0 && i + 1 < hex_len && fuzz_parse_meta(c, hex[i + 1]) == 0) {
			i++;
			continue;
		} else
			return -1;

		if (v >= 0) {
			if (hi < 0) {
				hi = v;
			} else {
				if (len >= maxlen)
					return -1;
				out[len++] = (uint8_t) ((hi << 4) | v);
				hi = -1;
			}
		}
	}
	if (!*has_more)
		*pos = hex_len;
	return (hi < 0) ? (int) len : -1;
}

static void
fuzz_common_init(void)
{
	static int initialized = 0;
	char dummy[4];
	size_t dlen;

	if (initialized)
		return;
	initialized = 1;

	network_init();

	/* Pre-warm lazy codec reverse lookup tables before persistent fork */
	(void)b32_8to5('a');
	dlen = 0;
	base64_ops.decode(dummy, &dlen, "", 0);
	dlen = 0;
	base64u_ops.decode(dummy, &dlen, "", 0);
	dlen = 0;
	base128_ops.decode(dummy, &dlen, "", 0);
}

static int
run_hex_input(const char *data, size_t size)
{
	uint8_t pkt[64 * 1024];
	size_t pos = 0;
	int pkt_count = 0;
	int setup_done = 0;
	int has_more = 1;

	fuzz_now = 1000000;
	fuzz_reset_directives();

	while (has_more && pkt_count < MAX_CHAIN_PKTS) {
		int len;

		if (setup_done)
			fuzz_reset_pkt_directives();

		len = next_hex_packet(data, size, &pos, pkt, sizeof(pkt), &has_more);
		if (len < 0)
			return 1;
		if (len == 0)
			continue;

		if (!setup_done) {
			fuzz_setup();
			setup_done = 1;
		} else {
			fuzz_now += 10;
		}

		current_pkt = pkt;
		current_pkt_len = (size_t) len;

		fuzz_run_packet(pkt, (size_t) len);

		current_pkt = NULL;
		current_pkt_len = 0;
		pkt_count++;
	}

	return (pkt_count > 0) ? 0 : 1;
}

#ifdef LIBFUZZER
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	quiet_output = 1;
	fuzz_common_init();
	run_hex_input((const char *) data, size);
	return 0;
}
#else
int
main(int argc, char **argv)
{
	char buf[128 * 1024];
	int i;

	progname_init(argv[0]);
	fuzz_common_init();
	fuzz_setup();

	if (getenv("__AFL_SHM_ID") != NULL)
		quiet_output = 1;
	else
		ui_set_debuglevel(999);

	if (argc < 2) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
#ifdef __AFL_HAVE_MANUAL_CONTROL
		__AFL_INIT();
#endif
		unsigned char *afl_buf = __AFL_FUZZ_TESTCASE_BUF;
		while (__extension__ __AFL_LOOP(10000)) {
			int len = __AFL_FUZZ_TESTCASE_LEN;
			run_hex_input((const char *) afl_buf, (size_t) len);
		}
		fuzz_cleanup();
		return 0;
#else
		size_t n = fread(buf, 1, sizeof(buf), stdin);
		int ret = run_hex_input(buf, n);
		fuzz_cleanup();
		return ret;
#endif
	}

	for (i = 1; i < argc; i++) {
		FILE *fp = fopen(argv[i], "rb");
		size_t n;
		if (!fp) {
			perror(argv[i]);
			fuzz_cleanup();
			return 1;
		}
		n = fread(buf, 1, sizeof(buf), fp);
		fclose(fp);
		if (run_hex_input(buf, n) != 0) {
			fprintf(stderr, "Failed to parse hex input from %s\n", argv[i]);
			fuzz_cleanup();
			return 1;
		}
	}
	fuzz_cleanup();
	return 0;
}
#endif
