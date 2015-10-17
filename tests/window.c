/*
 * Copyright (c) 2015 Frekk van Blagh <frekk@frekkworks.com>
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
#include <check.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "window.h"
#include "test.h"

struct frag_buffer *in, *out;
char origdata[1000] = "";

START_TEST(test_window_everything)
{
	in = window_buffer_init(1000, 10, 5, WINDOW_RECVING);
	out = window_buffer_init(1000, 10, 5, WINDOW_SENDING);
	for (unsigned i = 0; i < 20; i++) {
		char c[100] = "0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-=`';\\|][{}/?~";
		c[0] += i;
		window_add_outgoing_data(out, (uint8_t *)c, i + 1, 0);
		strncat(origdata, c, i + 1);
		//warnx(" OUT: %u available, current seq %u, new seq %u\n", window_buffer_available(out), i, out->cur_seq_id);
	}
//	printf("Original data: '%s' (%lu)\n", origdata, strlen(origdata));
//	warnx("Added data, fragmented into %lu frags, next seq %u.", out->numitems, out->cur_seq_id);
	// "send" data
	int a = -1;
	for (; out->numitems > 0;) {
		fragment *f = window_get_next_sending_fragment(out, &a);
		if (!f) {
//			warnx("Nothing to send.");
			continue;
		}
		fail_if(window_process_incoming_fragment(in, f) < 0, "Dropped fragment!");
//		warnx("Received fragment with seqid %u, remaining space %lu.", f->seqID, window_buffer_available(in));
		window_tick(in);
		window_ack(out, f->seqID);
		window_tick(out);
		fail_if(out->start_seq_id != in->start_seq_id, "in/out windows have different start IDs!");
	}
//	warnx("Added %lu fragments, reassembling into data.", in->numitems);
	uint8_t data[100];
	uint8_t newdata[1000];
	memset(newdata, 0, 1000);
	unsigned i;
	int c;
	for (i = 0; i < 50; i++) {
		memset(data, 0, 100);
		size_t len = window_reassemble_data(in, data, 100, &c);
		fail_if(c != 0, "Compression flag weird");
//		printf("Reassembled %lu bytes, num frags %lu: '", len, in->numitems);
//		for (unsigned i = 0; i < len; i++) {
//			printf("%c", data[i]);
//		}
//		printf("'\n");
		strncat((char *)newdata, (char *)data, len);
		if (in->numitems <= 0) break;
	}
//	printf("New data: '%s' (%lu)\n", newdata, strlen((char *)newdata));
	fail_if(strcmp((char *)newdata, origdata), "Reassembled data didn't match original data.");
}
END_TEST


TCase *
test_window_create_tests()
{
	TCase *tc;

	tc = tcase_create("Windowing");
	tcase_add_test(tc, test_window_everything);

	return tc;
}
