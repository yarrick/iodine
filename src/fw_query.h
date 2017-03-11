/*
 * Copyright (c) 2008-2014 Erik Ekman <yarrick@kryo.se>
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

#ifndef __FW_QUERY_H__
#define __FW_QUERY_H__

#include <sys/types.h>
#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#define FW_QUERY_CACHE_SIZE 16

struct fw_query {
	struct sockaddr_storage addr;
	int addrlen;
	unsigned short id;
};

void fw_query_init(void);
void fw_query_put(struct fw_query *fw_query);
void fw_query_get(unsigned short query_id, struct fw_query **fw_query);

#endif /*__FW_QUERY_H__*/

