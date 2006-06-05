/*
 * Copyright (c) 2006 Bjorn Andersson <flex@kryo.se>
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

#ifndef __MDNS_H__
#define __MDNS_H__

#include <sys/tree.h>

struct mdns_peer {
	RB_ENTRY(mdns_peer) entry;
	
	char *name;
	char *host;
	short port;
	short ttl;
};

struct mdns_service {
	RB_ENTRY(mdns_service) entry;

	char *name;
	char *net;
	char *host;
	short port;
	short ttl;
};

RB_HEAD(servicetree, mdns_service);

int mdns_open();
void mdns_query(int, char*, int);
void mdns_handle(int);

void mdns_register_service(struct mdns_service *);
void mdns_unregister_service(struct mdns_service *);

#endif
