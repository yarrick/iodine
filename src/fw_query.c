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

#include <string.h>
#include "fw_query.h"

static struct fw_query fwq[FW_QUERY_CACHE_SIZE];
static int fwq_ix;

void fw_query_init()
{
	memset(fwq, 0, sizeof(struct fw_query) * FW_QUERY_CACHE_SIZE);
	fwq_ix = 0;
}

void fw_query_put(struct fw_query *fw_query)
{
	memcpy(&(fwq[fwq_ix]), fw_query, sizeof(struct fw_query));

	++fwq_ix;
	if (fwq_ix >= FW_QUERY_CACHE_SIZE)
		fwq_ix = 0;
}

void fw_query_get(unsigned short query_id, struct fw_query **fw_query)
{
	int i;

	*fw_query = NULL;
	for (i = 0; i < FW_QUERY_CACHE_SIZE; i++) {
		if (fwq[i].id == query_id) {
			*fw_query = &(fwq[i]);
			return;
		}
	}
}
