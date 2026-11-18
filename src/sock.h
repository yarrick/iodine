/*
 * Copyright (c) 2006-2026 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __SOCK_H__
#define __SOCK_H__

#include <stdbool.h>
#include <stddef.h>

#include "config.h"

#ifdef WINDOWS
#include <winsock2.h>
#else
#include <sys/select.h>
#endif

int sock_select_fds(int timeout_ms, fd_set *fds, const int *list, size_t n);

#define sock_select(timeout_ms, fds, ...) \
	sock_select_fds((timeout_ms), (fds), (const int[]){__VA_ARGS__}, \
	                sizeof((const int[]){__VA_ARGS__}) / sizeof(int))

bool sock_isset(int fd, fd_set *fds);

#endif
