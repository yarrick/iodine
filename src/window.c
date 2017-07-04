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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#ifndef WINDOWS32
#include <err.h>
#endif
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "util.h"
#include "window.h"

int window_debug = 0;

struct frag_buffer *
window_buffer_init(size_t length, unsigned windowsize, unsigned maxfraglen, int dir)
{
	struct frag_buffer *w;

	/* Note: window buffer DOES NOT WORK with length > MAX_SEQ_ID */
	if (length > MAX_SEQ_ID)
		errx(1, "window_buffer_init: length (%" L "u) is greater than MAX_SEQ_ID (%d)!\n");

	w = calloc(1, sizeof(struct frag_buffer));
	if (!w) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}

	window_buffer_resize(w, length, maxfraglen);

	w->windowsize = windowsize;
	w->direction = dir;
	return w;
}

void
window_buffer_resize(struct frag_buffer *w, size_t length, unsigned maxfraglen)
{
	if (w->length == length && w->maxfraglen == maxfraglen) {
		return;
	}

	if (w->numitems > 0) {
		WDEBUG("Resizing window buffer with things still in it = data loss!");
	}

	w->frags = malloc(length * sizeof(fragment));
	if (!w->frags) {
		errx(1, "Failed to allocate fragment buffer!");
	}

	w->data = malloc(length * maxfraglen);
	if (!w->data) {
		errx(1, "Failed to allocate fragment data buffer! "
				"Maybe fragsize too large (%u)?", maxfraglen);
	}

	w->length = length;
	w->maxfraglen = maxfraglen;
	window_buffer_clear(w);
}

void
window_buffer_destroy(struct frag_buffer *w)
{
	if (!w) return;
	if (w->frags) free(w->frags);
	if (w->data) free(w->data);
	free(w);
}

void
window_buffer_clear(struct frag_buffer *w)
{
	if (!w) return;
	memset(w->frags, 0, w->length * sizeof(fragment));
	memset(w->data, 0, w->length * w->maxfraglen);

	/* Fix fragment data pointers */
	for (size_t i = 0; i < w->length; i++) {
		w->frags[i].data = FRAG_DATA(w, i);
	}

	w->numitems = 0;
	w->window_start = 0;
	w->last_write = 0;
	w->chunk_start = 0;
	w->cur_seq_id = 0;
	w->start_seq_id = 0;
	w->max_retries = 0;
	w->resends = 0;
	w->oos = 0;
	w->timeout.tv_sec = 5;
	w->timeout.tv_usec = 0;
}

/* Returns number of available fragment slots (NOT BYTES) */
size_t
window_buffer_available(struct frag_buffer *w)
{
	return w->length - w->numitems;
}

ssize_t
window_process_incoming_fragment(struct frag_buffer *w, fragment *f)
/* Handles fragment received from the sending side (RECV)
 * Returns index of fragment in window or <0 if dropped
 * The next ACK MUST be for this fragment
 * Slides window forward if fragment received which is just above end seqID */
/* XXX Use whole buffer to receive and reassemble fragments
 * Old frags are "cleared" by being overwritten by newly received frags. (TODO)
 * Reassemble just starts at oldest slot (chunk_start) in window and continues until all frags
 * in buffer have been found. chunk_start incremented only if no holes found (tick).
 */
{
	/* Check if packet is in window */
	unsigned startid, endid, offset;
	int future = 0;
	fragment *fd;
	startid = w->start_seq_id;
	endid = WRAPSEQ(startid + w->length);
	offset = SEQ_OFFSET(startid, f->seqID);

	if (f->len == 0) {
		WDEBUG("got incoming frag with len 0! id=%u", f->seqID);
		return -1;
	}

	/* Place fragment into correct location in buffer, possibly overwriting
	 * an older and not-yet-reassembled fragment
	 * Note: chunk_start != window_start */
	ssize_t dest = WRAP(w->chunk_start + offset);

	if (offset > w->length - w->windowsize) {
		WDEBUG("incoming frag ahead: offs %u > %u, cs %u[%" L "u], id %u[%" L "u]",
				offset, w->length - w->windowsize, w->start_seq_id, w->chunk_start,
				f->seqID, dest);
		offset -= w->length - w->windowsize;
		window_slide(w, offset, 1);
	}

	WDEBUG("   Putting frag seq %u into frags[%" L "u + %u = %" L "u]",
		   f->seqID, w->chunk_start, offset, dest);

	/* Check if fragment already received */
	fd = &w->frags[dest];
	if (fd->len != 0 && fd->seqID == f->seqID) {
		/* use retries as counter for dupes */
		fd->retries ++;
		WDEBUG("Received duplicate frag, dropping. (prev %u/new %u, dupes %u)",
				fd->seqID, f->seqID, fd->retries);
		return -1;
	}
	fd->seqID = f->seqID;
	fd->len = MIN(f->len, w->maxfraglen);
	fd->compressed = f->compressed;
	fd->start = f->start;
	fd->end = f->end;

	memcpy(fd->data, f->data, fd->len);
	w->numitems ++;

	fd->retries = 0;
	fd->ack_other = -1;

	/* We assume this packet gets ACKed immediately on return of this function */
	fd->acks = 1;

	return dest;
}

/* Reassembles first complete sequence of fragments into data. (RECV)
 * len should be passed with max space in *data, replaced with amount filled
 * Returns 1 if should be called again for another packet, 0 otherwise */
int
window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t *len, uint8_t *compression)
{
	size_t woffs, start;
	size_t maxlen = *len;
	size_t fraglen = 0;
	uint8_t *dest; //, *fdata_start;
	*len = 0;
	dest = data;

	/* nothing to try reassembling if w is empty */
	if (w->numitems == 0) {
		WDEBUG("window buffer empty, nothing to reassemble");
		return 0;
	}
	if (compression) *compression = 1;

	fragment *f;
	unsigned curseq, consecutive_frags = 0, holes = 0, found_frags = 0;
	int end = 0, drop = 0; /* if packet is dropped */
	for (size_t i = 0; found_frags < w->numitems; i++) {
		woffs = WRAP(w->chunk_start + i);
		curseq = WRAPSEQ(w->start_seq_id + i);
		f = &w->frags[woffs];

		/* TODO Drop packets if some fragments are missing after reaching max retries
		 * or packet timeout
		 * Note: this lowers the guaranteed arrival constraint */

		/* Note: Continue reassembling full packets until none left in buffer;
		 *      several full packets are sometimes left in buffer unprocessed
		 *      so we must not just taking the oldest full packet and ignore newer ones */
		if (f->len == 0) { /* Empty fragment */
			if (holes < 2)
				WDEBUG("reassemble: hole at frag id %u [%" L "u]", curseq, woffs);
			/* reset reassembly things to start over */
			consecutive_frags = 0;
			holes++;
			continue;
		}

		found_frags++;
		if (f->seqID != curseq) {
			/* this is a serious bug. exit nastily */
			errx(1, "reassemble: frag [%" L "u] seqID mismatch: f=%u, cur=%u",
					woffs, f->seqID, curseq);
		}
		if (f->start || consecutive_frags >= 1) {
			consecutive_frags++;
			if (drop == 0) {
				/* Copy next fragment to buffer if not going to drop */
				memcpy(dest, f->data, MIN(f->len, maxlen));
			}
			if (f->len > maxlen) {
				WDEBUG("Data buffer too small: drop packet! Reassembled %" L "u bytes.", fraglen);
				drop = 1;
			}
			dest += f->len;
			fraglen += f->len;
			maxlen -= f->len;

			if (compression) {
				*compression &= f->compressed & 1;
				if (f->compressed != *compression) {
					WDEBUG("Inconsistent compression flags in chunk. Will reassemble anyway!");
				}
			}

			WDEBUG("reassemble: id %u [%" L "u], len %" L "u, offs %" \
					L "u, total %" L "u, maxlen %" L "u, found %" L "u/%" L "u, consecutive %" L "u",
					woffs, f->seqID, f->len, dest - data, *len, maxlen, found_frags, w->numitems, consecutive_frags);

			if (f->end == 1) {
				WDEBUG("Found end of chunk! (seqID %u, chunk len %" L "u, datalen %" L "u)",
						f->seqID, consecutive_frags, *len);
				end = 1;
				break;
			}
		}
	}

	if (end == 0 && drop == 0) {
		/* no end of chunk found because the window buffer has no more frags
		 * meaning they haven't been received yet. */
		return 0;
	}

	if (!drop)
		*len = fraglen;

	WDEBUG("Reassembled %" L "ub from %" L "u frags; comp=%u; holes=%u",
			*len, consecutive_frags, *compression, holes);
	/* Clear all used fragments, going backwards from last processed */
	size_t p = woffs;
	for (int n = 0; n < consecutive_frags; n++) {
		w->frags[p].len = 0;
		p = (p <= 0) ? w->length - 1 : p - 1;
	}

	w->numitems -= consecutive_frags;
	return found_frags >= consecutive_frags;
}

size_t
window_sending(struct frag_buffer *w, struct timeval *nextresend)
/* Returns number of fragments that can be sent immediately; effectively
   the same as window_get_next_sending_fragment but without doing anything.
   *nextresend is time before the next frag will be resent */
{
	struct timeval age, now, oldest;
	fragment *f;
	size_t tosend = 0;

	oldest.tv_sec = 0;
	oldest.tv_usec = 0;

	if (nextresend) {
		nextresend->tv_sec = 0;
		nextresend->tv_usec = 0;
	}

	if (w->numitems == 0) {
		return 0;
	}

	gettimeofday(&now, NULL);

	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->len == 0 || f->acks >= 1 || f->retries > w->max_retries)
			continue;

		if (f->retries < 1) {
			/* Sending frag for first time */
			tosend++;
		} else {
			/* Frag has been sent before so lastsent is a valid timestamp */
			timersub(&now, &f->lastsent, &age);

			if (!timercmp(&age, &w->timeout, <)) {
				/* ACK timeout: Frag will be resent if not to be dropped */
				tosend++;
			} else if (timercmp(&age, &oldest, >)) {
				/* Hasn't timed out yet and is oldest so far */
				oldest = age;
			}
		}
	}

	if (nextresend && w->max_retries > 0) {
		/* nextresend = time before oldest fragment (not being sent now)
		 * will be re-sent = timeout - age */
		timersub(&w->timeout, &oldest, nextresend);
	}

	return tosend;
}

/* Returns next fragment to be sent or NULL if nothing (SEND)
 * This also handles packet resends, timeouts etc. */
fragment *
window_get_next_sending_fragment(struct frag_buffer *w, int *other_ack)
{
	struct timeval age, now;
	fragment *f = NULL;

	if (*other_ack >= MAX_SEQ_ID || *other_ack < 0)
		*other_ack = -1;

	gettimeofday(&now, NULL);

	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->acks >= 1 || f->len == 0 || f->retries > w->max_retries)
			continue;

		timersub(&now, &f->lastsent, &age);

		if (f->retries >= 1 && !timercmp(&age, &w->timeout, <)) {
			/* Resending fragment due to ACK timeout */
			WDEBUG("Retrying frag %u (%ld ms old/timeout %ld ms), retries: %u/max %u/total %u",
				   f->seqID, timeval_to_ms(&age), timeval_to_ms(&w->timeout), f->retries, w->max_retries, w->resends);
			w->resends ++;
			goto found;
		} else if (f->retries == 0) {
			/* Fragment not sent */
			goto found;
		}
	}
	if (f)
		WDEBUG("Not sending any fragments (last frag checked: retries %u, seqid %u, len %" L "u)",
				f->retries, f->seqID, f->len);
	return NULL;

	found:
	/* store other ACK into fragment for sending; ignore any previous values.
	   Don't resend ACKs because by the time we do, the other end will have
	   resent the corresponding fragment so may as well not cause trouble. */
	f->ack_other = *other_ack, *other_ack = -1;
	f->start &= 1;
	f->end &= 1;
	f->retries++;
	f->lastsent.tv_sec = now.tv_sec;
	f->lastsent.tv_usec = now.tv_usec;
	return f;
}

/* Sets the fragment with seqid to be ACK'd (SEND) */
void
window_ack(struct frag_buffer *w, int seqid)
{
	fragment *f;
	if (seqid < 0 || seqid > MAX_SEQ_ID) return;
	unsigned offset = SEQ_OFFSET(w->start_seq_id, seqid);

	ssize_t dest = WRAP(w->chunk_start + offset);
	f = &w->frags[dest];
	if (f->seqID == seqid && f->len > 0) { /* increment ACK counter in frag */
		f->acks ++;
		WDEBUG("ACK frag seq %u, ACKs %u, len %" L "u, s %u e %u", f->seqID, f->acks, f->len, f->start, f->end);
	} else {
		WDEBUG("Tried to ACK nonexistent frag, id %u", seqid);
	}
}

/* Slide window forwards by given number of frags, clearing out old frags */
void
window_slide(struct frag_buffer *w, unsigned slide, int delete)
{
	WDEBUG("moving window forwards by %u; %" L "u-%" L "u (%u) to %" L "u-%" L "u (%u) len=%" L "u",
			slide, w->window_start, AFTER(w, w->windowsize), w->start_seq_id, AFTER(w, slide),
			AFTER(w, w->windowsize + slide), AFTERSEQ(w, slide), w->length);

	/* Requirements for fragment being cleared (SENDING):
	 *  (must have been sent) AND
	 *  (((must be received) AND (must be acknowledged)) OR
	 *   (not acknowledged if ACK not required))
	 *
	 * Fragments (or holes) cleared on RECEIVING must:
	 *  ((be received) AND (be ACK'd)) OR (... see window_reassemble_data)
	 */
	/* check if chunk_start has to be moved to prevent window overlapping,
	 * which results in deleting holes or frags */
	if (delete) {
		/* Clear old frags or holes */
		unsigned nfrags = 0;
		for (unsigned i = 0; i < slide; i++) {
			size_t woffs = WRAP(w->window_start + i);
			fragment *f = &w->frags[woffs];
			if (f->len != 0) {
				WDEBUG("    clear frag id %u, len %" L "u at index %" L "u",
						f->seqID, f->len, woffs);
				f->len = 0;
				nfrags ++;
			} else {
				WDEBUG("    clear hole at index %" L "u", woffs);
			}
		}

		WDEBUG("    chunk_start: %" L "u -> %" L "u", w->chunk_start, AFTER(w, slide));
		w->numitems -= nfrags;
		w->chunk_start = AFTER(w, slide);
		w->start_seq_id = AFTERSEQ(w, slide);
	}

	/* Update window status */
	w->window_start = AFTER(w, slide);
}

/* Function to be called after all other processing has been done
 * when anything happens (moves window etc) (SEND only) */
void
window_tick(struct frag_buffer *w)
{
	unsigned slide = 0;
	for (size_t i = 0; i < w->windowsize; i++) {
		fragment *f = &w->frags[WRAP(w->window_start + i)];
		if (f->len > 0 && (f->acks >= 1 || f->retries > w->max_retries)) {
			/* count consecutive fragments from start of window that are ACK'd
			 * or that have been sent/retried maximum times */
			slide++;
		} else {
			break;
		}
	}
	if (slide > 0) window_slide(w, slide, w->direction == WINDOW_SENDING);
}

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int
window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, uint8_t compressed)
{
	// Split data into thingies of <= fragsize
	size_t n = ((len - 1) / w->maxfraglen) + 1;
	if (!data || n == 0 || len == 0 || n > window_buffer_available(w)) {
		WDEBUG("Failed to append fragment (buffer too small!)");
		return -1;
	}
	compressed &= 1;
	size_t offset = 0;
	fragment *f;
	WDEBUG("add_outgoing_data: chunk len %" L "u -> %" L "u frags, max fragsize %u",
			len, n, w->maxfraglen);
	for (size_t i = 0; i < n; i++) {
		f = &w->frags[w->last_write];
		/* copy in new data and reset frag stats */
		f->len = MIN(len - offset, w->maxfraglen);
		f->seqID = w->cur_seq_id;
		f->compressed = compressed;
		f->start = (i == 0) ? 1 : 0;
		f->end = (i == n - 1) ? 1 : 0;
		f->retries = 0;
		f->acks = 0;
		f->ack_other = -1;
		f->lastsent.tv_sec = 0;
		f->lastsent.tv_usec = 0;

		WDEBUG("     frags[%" L "u]: len %" L "u, seqID %u, s %u, end %u, dOffs %" L "u",
				w->last_write, f->len, f->seqID, f->start, f->end, offset);

		memcpy(f->data, data + offset, f->len);
		w->last_write = WRAP(w->last_write + 1);
		w->cur_seq_id = WRAPSEQ(w->cur_seq_id + 1);
		w->numitems ++;
		offset += f->len;
	}
	return n;
}
