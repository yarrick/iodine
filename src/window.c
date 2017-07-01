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
	struct frag_buffer *buf;
	buf = calloc(1, sizeof(struct frag_buffer));
	if (!buf) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}

	window_buffer_resize(buf, length, maxfraglen);

	buf->windowsize = windowsize;
	buf->direction = dir;
	return buf;
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
	w->window_end = AFTER(w, w->windowsize);
	w->last_write = 0;
	w->chunk_start = 0;
	w->cur_seq_id = 0;
	w->start_seq_id = 0;
	w->max_retries = 5;
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
 * The next ACK MUST be for this fragment */
{
	/* Check if packet is in window */
	unsigned startid, endid, offset;
	fragment *fd;
	startid = w->start_seq_id;
	endid = (w->start_seq_id + w->windowsize) % MAX_SEQ_ID;
	offset = SEQ_OFFSET(startid, f->seqID);

	if (!INWINDOW_SEQ(startid, endid, f->seqID)) {
		w->oos++;
		if (offset > MIN(w->length - w->numitems, MAX_SEQ_ID / 2)) {
			/* Only drop the fragment if it is ancient */
			WDEBUG("Dropping frag with seqID %u: not in window (%u-%u)", f->seqID, startid, endid);
			return -1;
		} else {
			/* Save "new" fragments to avoid causing other end to advance
			 * when this fragment is ACK'd despite being dropped */
			WDEBUG("WARNING: Got future fragment (%u), offset %u from start %u (wsize %u).",
				   f->seqID, offset, startid, w->windowsize);
		}
	}
	/* Place fragment into correct location in buffer */
	ssize_t dest = WRAP(w->window_start + SEQ_OFFSET(startid, f->seqID));
	WDEBUG("   Putting frag seq %u into frags[%" L "u + %u = %" L "u]",
		   f->seqID, w->window_start, SEQ_OFFSET(startid, f->seqID), dest);

	/* Check if fragment already received */
	fd = &w->frags[dest];
	if (fd->len == f->len && fd->seqID == f->seqID) {
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
	if (!len) {
		errx(1, "window_reassemble_data: len pointer is NULL!");
	}

	size_t woffs, fraglen, start;
	size_t maxlen = *len;
	uint8_t *dest; //, *fdata_start;
	*len = 0;
	dest = data;
	if (w->direction != WINDOW_RECVING)
		return 0;

	/* start fragment may be missing, so only stop if w is empty */
	if (w->frags[w->chunk_start].start == 0 && w->numitems == 0) {
		WDEBUG("chunk_start (%" L "u) != start and w empty (seq %u, len %" L "u)!",
			  w->chunk_start, w->frags[w->chunk_start].seqID, w->frags[w->chunk_start].len);
		return 0;
	}
	if (compression) *compression = 1;

	fragment *f;
	size_t i;
	unsigned curseq, consecutive_frags = 0, holes = 0, found_frags = 0;
	int end = 0, drop = 0; /* if packet is dropped */
	curseq = w->start_seq_id;

	for (i = 0; i < w->numitems; ++i) {
		woffs = WRAP(w->chunk_start + i);
		f = &w->frags[woffs];
		fraglen = f->len;

		/* TODO Drop packets if some fragments are missing after reaching max retries
		 * or packet timeout
		 * Note: this lowers the guaranteed arrival constraint
		 * Note: Continue reassembling full packets until none left in buffer;
		 *      several full packets are sometimes left in buffer unprocessed
		 *      so we must not just taking the oldest full packet and ignore newer ones */
		/* Process:
		 * if buffer contains >0 frags
		 * for frag in buffer from start {
		 *  if frag empty: skip; else
		 *  	if frag.start {
		 *  		attempt reassembly as normal;
		 *  		continue from end of full packet;
		 *  	} else skip;
		 * 	endif
		 * }
		 */
		if (fraglen == 0) { /* Empty fragment */
			WDEBUG("reassemble: hole at frag %u [%" L "u]",
				   curseq, woffs, f->seqID, fraglen);

			/* reset reassembly things to start over */
			consecutive_frags = 0;
			holes++;

		} else if (f->start || consecutive_frags >= 1) {
			found_frags++;
			consecutive_frags++;
			if (drop == 0) {
				/* Copy next fragment to buffer if not going to drop */
				memcpy(dest, f->data, MIN(fraglen, maxlen));
			}
			dest += fraglen;
			*len += fraglen;
			if (compression) {
				*compression &= f->compressed & 1;
				if (f->compressed != *compression) {
					WDEBUG("Inconsistent compression flags in chunk. Will reassemble anyway!");
				}
			}
			if (fraglen > maxlen) {
				WDEBUG("Data buffer too small: drop packet! Reassembled %" L "u bytes.", *len);
				drop = 1;
			}
			WDEBUG("reassemble: id %u, len %" L "u, offs %" \
					L "u, total %" L "u, maxlen %" L "u, found %" L "u, consecutive %" L "u",
					f->seqID, fraglen, dest - data, *len, maxlen, found_frags, consecutive_frags);

			/* Move window along to avoid weird issues */
			window_tick(w);

			if (f->end == 1) {
				WDEBUG("Found end of chunk! (seqID %u, chunk len %" L "u, datalen %" L "u)",
						f->seqID, consecutive_frags, *len);
				end = 1;
				break;
			}

			if (found_frags >= w->numitems) {
				/* no point continuing if no full packets yet and no other action */
				return 0;
			}
		}

		/* Move position counters and expected next seqID */
		maxlen -= fraglen;
		curseq = (curseq + 1) % MAX_SEQ_ID;
	}

	if (end == 0 && drop == 0) {
		/* no end of chunk found because the window buffer has no more frags
		 * meaning they haven't been received yet. */
		return 0;
	}

	WDEBUG("Reassembled %" L "ub from %" L "u frags; comp=%u; holes=%u",
			*len, consecutive_frags, *compression, holes);
	/* Clear all used fragments, going backwards from last processed */
	size_t p = woffs;
	for (int n = 0; n < consecutive_frags; n++) {
		w->frags[p].len = 0;
		p = (p <= 0) ? w->length - 1 : p - 1;
	}
	if (holes == 0) {
		/* move start of window forwards only if there are no pending fragments (holes)
		 * or incomplete packets that we might have skipped */
		w->chunk_start = WRAP(woffs + 1);
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

	if (w->numitems == 0) {
		if (nextresend) {
			nextresend->tv_sec = 0;
			nextresend->tv_usec = 0;
		}
		return 0;
	}

	gettimeofday(&now, NULL);

	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->len == 0 || f->acks >= 1) continue;

		if (f->retries < 1 || f->lastsent.tv_sec == 0) {
			/* Sending frag for first time
			 * Note: if retries==0 then lastsent MUST also be 0 */
			tosend++;
		} else {
			/* Frag has been sent before so lastsent is a valid timestamp */
			timersub(&now, &f->lastsent, &age);

			if (!timercmp(&age, &w->timeout, <)) {
				/* ACK timeout: Frag will be resent */
				tosend++;
			} else if (timercmp(&age, &oldest, >)) {
				/* Hasn't timed out yet and is oldest so far */
				oldest = age;
			}
		}
	}

	if (nextresend) {
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
		if (f->acks >= 1 || f->len == 0) continue;

		timersub(&now, &f->lastsent, &age);

		if (f->retries >= 1 && !timercmp(&age, &w->timeout, <)) {
			/* Resending fragment due to ACK timeout */
			WDEBUG("Retrying frag %u (%ld ms old/timeout %ld ms), retries: %u/max %u/total %u",
				   f->seqID, timeval_to_ms(&age), timeval_to_ms(&w->timeout), f->retries, w->max_retries, w->resends);
			w->resends ++;
			goto found;
		} else if (f->retries == 0 && f->len > 0) {
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
	gettimeofday(&f->lastsent, NULL);
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
			if (f->acks > 0)
				WDEBUG("DUPE ACK: %d ACKs for seqId %u", f->acks, seqid);
			f->acks ++;
			WDEBUG("   ACK frag seq %u, ACKs %u, len %" L "u, s %u e %u", f->seqID, f->acks, f->len, f->start, f->end);
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
		// TODO are ACKs required for reduced arrival guarantee?
		/* Requirements for fragment being cleared (SENDING):
		 *  (must have been sent) AND
		 *  (((must be received) AND (must be acknowledged)) OR
		 *   (not acknowledged if ACK not required))
		 *
		 * Fragments (or holes) cleared on RECEIVING must:
		 *  ((be received) AND (be ACK'd)) OR (... see window_reassemble_data)
		 */
		fragment *f = &w->frags[w->window_start];
		if (f->len > 0 && f->acks >= 1) {
#ifdef DEBUG_BUILD
			unsigned old_start_id = w->start_seq_id;
#endif
			w->start_seq_id = (w->start_seq_id + 1) % MAX_SEQ_ID;
			WDEBUG("moving window forwards; %" L "u-%" L "u (%u) to %" L "u-%" L "u (%u) len=%" L "u",
					w->window_start, w->window_end, old_start_id, AFTER(w, 1),
					AFTER(w, w->windowsize + 1), w->start_seq_id, w->length);
			if (w->direction == WINDOW_SENDING) {
				WDEBUG("Clearing old fragments in SENDING window.");
				w->numitems --; /* Clear old fragments */
				f->len = 0;
			}
			w->window_start = AFTER(w, 1);

			w->window_end = AFTER(w, w->windowsize);
		} else break;
	}
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
	fragment *f = &w->frags[w->last_write];
	WDEBUG("add_outgoing_data: chunk len %" L "u -> %" L "u frags, max fragsize %u",
			len, n, w->maxfraglen);
	for (size_t i = 0; i < n; i++) {
		/* copy in new data and reset frag stats */
		f->len = MIN(len - offset, w->maxfraglen);
		memcpy(f->data, data + offset, f->len);
		f->seqID = w->cur_seq_id;
		f->compressed = compressed;
		f->start = (i == 0) ? 1 : 0;
		f->end = (i == n - 1) ? 1 : 0;

		f->retries = 0;
		f->acks = 0;
		f->ack_other = -1;
		f->lastsent.tv_sec = 0;
		f->lastsent.tv_usec = 0;

		w->last_write = WRAP(w->last_write + 1);
		w->numitems ++;
		w->cur_seq_id = (w->cur_seq_id + 1) % MAX_SEQ_ID;
		WDEBUG("     fragment len %" L "u, seqID %u, s %u, end %u, dOffs %" L "u",
				f->len, f->seqID, f->start, f->end, offset);
		offset += f->len;
	}
	return n;
}
