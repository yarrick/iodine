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

#ifndef __FUZZ_MAIN_H__
#define __FUZZ_MAIN_H__

#include <stddef.h>
#include <stdint.h>

#define FUZZ_TOPDOMAIN "t.kryo.se"
#define FUZZ_SEED      0x01010101

extern const char fuzz_password[33];
extern const uint8_t *current_pkt;
extern size_t current_pkt_len;
extern int suppress_send;

int fuzz_parse_meta(char cmd, char arg);
void fuzz_reset_directives(void);
void fuzz_reset_pkt_directives(void);
void fuzz_setup(void);
void fuzz_run_packet(const uint8_t *pkt, size_t len);
void fuzz_on_tun_write(const char *data, size_t len);
void fuzz_cleanup(void);

#endif /* __FUZZ_MAIN_H__ */
