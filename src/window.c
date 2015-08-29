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

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "window.h"

struct frag_buffer *
window_buffer_init(size_t length, unsigned windowsize, unsigned fragsize, int dir)
{
	struct frag_buffer *buf;
	buf = calloc(sizeof(struct frag_buffer), 1);
	if (!buf) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}
	if (fragsize > MAX_FRAGSIZE) {
		errx(fragsize, "Fragsize too large! Please recompile with larger MAX_FRAGSIZE!");
	}

	buf->frags = calloc(length, sizeof(fragment));
	if (!buf->frags) {
		errx(1, "Failed to allocate fragment buffer!");
	}
	buf->length = length;
	buf->windowsize = windowsize;
	buf->maxfraglen = fragsize;
	buf->window_end = AFTER(buf, windowsize);
	buf->direction = dir;

	return buf;
}

void
window_buffer_resize(struct frag_buffer *w, size_t length)
{
	if (w->length == length) return;
	if (w->numitems > 0) {
		DEBUG("Resizing window buffer with things still in it! This will cause problems!");
	}
	if (w->frags) free(w->frags);
	w->frags = calloc(length, sizeof(fragment));
	if (!w->frags) {
		errx(1, "Failed to resize window buffer!");
	}
	w->length = length;
	w->numitems = 0;
	w->window_start = 0;
	w->start_seq_id = 0;
	w->cur_seq_id = 0;
	w->window_end = AFTER(w, w->windowsize);
}

void
window_buffer_destroy(struct frag_buffer *w)
{
	if (!w) return;
	if (w->frags) free(w->frags);
	free(w);
}

/* Returns number of available fragment slots (NOT BYTES) */
size_t
window_buffer_available(struct frag_buffer *w)
{
	return w->length - w->numitems;
}

/* Places a fragment in the window after the last one */
int
window_append_fragment(struct frag_buffer *w, fragment *src)
{
	if (window_buffer_available(w) < 1) return 0;
	memcpy(&w->frags[w->last_write], src, sizeof(fragment));
	w->last_write = WRAP(w->last_write + 1);
	w->numitems ++;
	return 1;
}

/* Handles fragment received from the sending side (RECV) */
int
window_process_incoming_fragment(struct frag_buffer *w, fragment *f)
{
	/* Check if packet is in window */
	unsigned startid, endid;
	fragment *fd;
	startid = w->start_seq_id;
	endid = (w->start_seq_id + w->windowsize) % MAX_SEQ_ID;
	if (!INWINDOW_SEQ(startid, endid, f->seqID)) {
		DEBUG("Dropping frag with seqID %u: not in window (%u-%u)\n", f->seqID, startid, endid);
		return 0;
	}
	/* Place fragment into correct location in buffer */
	size_t dest = WRAP(w->window_start + SEQ_OFFSET(startid, f->seqID));
	DEBUG("   Putting frag seq %u into frags[%lu + %u = %lu]", f->seqID, w->window_start, SEQ_OFFSET(startid, f->seqID), dest);
	/* Check if fragment already received */
	fd = &w->frags[dest];
	if (fd->len != 0) {
		DEBUG("Received duplicate frag, dropping. (prev %u/new %u)", fd->seqID, f->seqID);
		return 0;
	}
	memcpy(fd, f, sizeof(fragment));
	fd->retries = 0;
	fd->ack_other = -1;
	fd->acks = 0;
	w->numitems ++;
	return 1;
}

/* Reassembles first complete sequence of fragments into data. (RECV)
 * Returns length of data reassembled, or 0 if no data reassembled */
size_t
window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t maxlen, int *compression)
{
	size_t woffs, fraglen, datalen = 0;
	uint8_t *dest; //, *fdata_start;
	dest = data;
	if (w->direction != WINDOW_RECVING)
		return 0;
	if (w->frags[w->chunk_start].start == 0) {
		DEBUG("chunk_start (%lu)pointing to non-start fragment (seq %u, len %lu)!",
			  w->chunk_start, w->frags[w->chunk_start].seqID, w->frags[w->chunk_start].len);
		return 0;
	}
	if (compression) *compression = 1;

	fragment *f;
	size_t i, curseq;
	int end = 0;
	curseq = w->frags[w->chunk_start].seqID;
	for (i = 0; i < w->numitems; ++i) {
		woffs = WRAP(w->chunk_start + i);
		f = &w->frags[woffs];
		fraglen = f->len;
		if (fraglen == 0 || !f->data || f->seqID != curseq) {
			DEBUG("data missing! Not reassembling!");
			return 0;
		}

		DEBUG("   Fragment seq %u, data length %lu, data offset %lu, total len %lu, maxlen %lu",
				f->seqID, fraglen, dest - data, datalen, maxlen);
		memcpy(dest, f->data, MIN(fraglen, maxlen));
		dest += fraglen;
		datalen += fraglen;
		if (compression) {
			*compression &= f->compressed & 1;
			if (f->compressed != *compression) {
				DEBUG("Inconsistent compression flags in chunk. Not reassembling!");
				return 0;
			}
		}
		if (fraglen > maxlen) {
			DEBUG("Data buffer too small! Reassembled %lu bytes.", datalen);
			return datalen;
		}

		/* Move window along to avoid weird issues */
		window_tick(w);

		if (f->end == 1) {
			DEBUG("Found end of chunk! (seqID %u, chunk len %lu, datalen %lu)", f->seqID, i, datalen);
			end = 1;
			break;
		}

		maxlen -= fraglen;
		curseq = (curseq + 1) % MAX_SEQ_ID;
	}
	if (end == 0) { /* no end of chunk found but reached end of data */
		return 0;
	}
	DEBUG("Reassembling %lu bytes of data from %lu frags!", datalen, i + 1);
	/* Clear all used fragments */
	size_t p;
	ITER_FORWARD(w->chunk_start, WRAP(w->chunk_start + i + 1), w->length, p, {
		memset(&w->frags[p], 0, sizeof(fragment));
	});
	w->chunk_start = WRAP(woffs + 1);
	w->numitems -= i + 1;
	return datalen;
}

/* Returns next fragment to be sent or NULL if nothing (SEND)
 * This also handles packet resends, timeouts etc. */
fragment *
window_get_next_sending_fragment(struct frag_buffer *w, int *other_ack)
{
	fragment *f;
	if (*other_ack >= MAX_SEQ_ID || *other_ack < 0)
		*other_ack = -1;
	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->acks >= 1) continue;
		if (f->retries >= 1 && difftime(f->lastsent, time(NULL)) > ACK_TIMEOUT) {
			/* Fragment sent before, not ACK'd */
			DEBUG("Sending fragment %u again, %u retries so far, %u resent overall\n", f->seqID, f->retries, w->resends);
			w->resends ++;
			goto found;
		} else if (f->retries == 0 && f->len > 0) {
			/* Fragment not sent */
			goto found;
		}

	}
	DEBUG("Not sending any fragments (last frag checked: retries %u, seqid %u, len %lu)",
			f->retries, f->seqID, f->len);
	// TODO: statistics for packet loss/not sending etc
	return NULL;

	found:
	/* store other ACK into fragment so ACK is resent if fragment times out */
	if (f->ack_other == -1)
		f->ack_other = *other_ack, *other_ack = -1;
	f->is_nack &= 1;
	f->start &= 1;
	f->end &= 1;
	f->retries++;
	time(&f->lastsent);
	return f;
}

/* Gets the seqid of next fragment to be ACK'd (RECV) */
int
window_get_next_ack(struct frag_buffer *w)
{
	fragment *f;
	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->len > 0 && f->acks <= 0) {
			f->acks = 1;
			return f->seqID;
		}
	}
	return -1;
}

/* Sets the fragment with seqid to be ACK'd (SEND) */
void
window_ack(struct frag_buffer *w, int seqid)
{
	fragment *f;
	if (seqid < 0 || seqid > MAX_SEQ_ID) return;
	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[AFTER(w, i)];
		if (f->seqID == seqid && f->len > 0) { /* ACK first non-empty frag */
			if (f->acks > 0) DEBUG("ACK: %d ACKs for seqId %u", f->acks, seqid);
			f->acks ++;
			DEBUG("   ACK frag seq %u, ACKs %u, len %lu, s %u e %u", f->seqID, f->acks, f->len, f->start, f->end);
			break;
		}
	}
}

/* Function to be called after all other processing has been done
 * when anything happens (moves window etc) (SEND/RECV) */
void
window_tick(struct frag_buffer *w)
{
	for (size_t i = 0; i < w->windowsize; i++) {
		if (w->frags[w->window_start].acks >= 1) {
			DEBUG("moving window forwards 1; start = %lu-%lu, end = %lu-%lu, len = %lu",
					w->window_start, AFTER(w, 1), w->window_end, AFTER(w, w->windowsize + 1), w->length);
			if (w->direction == WINDOW_SENDING) {
				DEBUG("Clearing old fragments in SENDING window.");
				w->numitems --; /* Clear old fragments */
				memset(&w->frags[w->window_start], 0, sizeof(fragment));
			}
			w->window_start = AFTER(w, 1);
			w->start_seq_id = (w->start_seq_id + 1) % MAX_SEQ_ID;

			w->window_end = AFTER(w, w->windowsize);
		} else break;
	}
}

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int
window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, int compressed)
{
	// Split data into thingies of <= fragsize
	size_t n = ((len - 1) / w->maxfraglen) + 1;
	if (!data || n == 0 || len == 0 || n > window_buffer_available(w)) {
		DEBUG("Failed to append fragment (buffer too small!)");
		return -1;
	}
	compressed &= 1;
	size_t offset = 0;
	static fragment f;
//	DEBUG("add data len %lu, %lu frags, max fragsize %u", len, n, w->maxfraglen);
	for (size_t i = 0; i < n; i++) {
		memset(&f, 0, sizeof(f));
		f.len = MIN(len - offset, w->maxfraglen);
		memcpy(f.data, data + offset, f.len);
		f.seqID = w->cur_seq_id;
		f.start = (i == 0) ? 1 : 0;
		f.end = (i == n - 1) ? 1 : 0;
		f.compressed = compressed;
		f.ack_other = -1;
		window_append_fragment(w, &f);
		w->cur_seq_id = (w->cur_seq_id + 1) % MAX_SEQ_ID;
//		DEBUG("     a = %u, b = %u, a %% b = %u", (len - offset), (w->maxfraglen + 1), (len - offset) % (w->maxfraglen + 1));
		DEBUG("     fragment len %lu, seqID %u, s %u, end %u, dOffs %lu", f.len, f.seqID, f.start, f.end, offset);
		offset += f.len;
	}
	return n;
}
