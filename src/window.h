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

#ifndef __WINDOW_H__
#define __WINDOW_H__

/* Hard-coded sequence ID and fragment size limits
 * These should match the limitations of the protocol. */
#define MAX_SEQ_ID 256
#define MAX_FRAGSIZE 4096

#define WINDOW_SENDING 1
#define WINDOW_RECVING 0

/* Generic ring-buffer macros */

/* Distance (going forwards) between a and b in window of length l */
#define DISTF(l, a, b) (((a > b) ? a-b : l-a+b-1) % l)

/* Distance backwards between a and b in window of length l */
#define DISTB(l, a, b) (((a < b) ? l-b+a-1 : a-b) % l)

/* Check if sequence ID a is within sequence range start to end */
#define INWINDOW_SEQ(start, end, a) ((start < end) ? \
		(a >= start && a <= end) : \
		((a >= start && a <= MAX_SEQ_ID - 1) || \
		(a <= end)))

/* Find the wrapped offset between sequence IDs start and a
 * Note: the maximum possible offset is MAX_SEQ_ID - 1 */
#define SEQ_OFFSET(start, a) ((a >= start) ? a - start : MAX_SEQ_ID - start + a)

struct fragment {
	size_t len;					/* Length of fragment data (0 if fragment unused) */
	unsigned seqID;				/* fragment sequence ID */
	int ack_other;				/* other way ACK seqID (>=0) or unset (<0) */
	int compressed;				/* compression flag */
	uint8_t start;				/* start of chunk flag */
	uint8_t end;				/* end of chunk flag */
	uint8_t data[MAX_FRAGSIZE];	/* fragment data */
	unsigned retries;			/* number of times has been sent or dupes recv'd */
	struct timeval lastsent;	/* timestamp of most recent send attempt */
	int acks;					/* number of times packet has been ack'd */
};

struct frag_buffer {
	struct fragment *frags;		/* pointer to array of data fragments */
	unsigned windowsize;	/* Max number of fragments in flight */
	unsigned maxfraglen;	/* Max outgoing fragment data size */
	size_t length;			/* Length of buffer */
	size_t numitems;		/* number of non-empty fragments stored in buffer */
	size_t window_start;	/* Start of window (index) */
	size_t window_end;		/* End of window (index) */
	size_t last_write;		/* Last fragment appended (index) */
	size_t chunk_start;		/* Start of current chunk of fragments (index) */
	unsigned cur_seq_id;	/* Next unused sequence ID */
	unsigned start_seq_id;	/* Start of window sequence ID */
	unsigned resends;		/* number of fragments resent or number of dupes received */
	unsigned oos;			/* Number of out-of-sequence fragments received */
	int direction;			/* WINDOW_SENDING or WINDOW_RECVING */
	struct timeval timeout;	/* Fragment ACK timeout before resend */
};

extern int window_debug;



/* Window function definitions. */


/* Window buffer creation and housekeeping */
struct frag_buffer *window_buffer_init(size_t length, unsigned windowsize, unsigned fragsize, int dir);
void window_buffer_resize(struct frag_buffer *w, size_t length);
void window_buffer_destroy(struct frag_buffer *w);

/* Clears fragments and resets window stats */
void window_buffer_clear(struct frag_buffer *w);

/* Resets window stats without clearing fragments */
void window_buffer_reset(struct frag_buffer *w);

/* Returns number of available fragment slots (NOT BYTES) */
size_t window_buffer_available(struct frag_buffer *w);

/* Places a fragment in the window after the last one */
int window_append_fragment(struct frag_buffer *w, struct fragment *src);

/* Handles fragment received from the sending side (RECV) */
ssize_t window_process_incoming_fragment(struct frag_buffer *w, struct fragment *f);

/* Reassembles first complete sequence of fragments into data. (RECV)
 * Returns length of data reassembled, or 0 if no data reassembled */
size_t window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t maxlen, int *compression);

/* Returns number of fragments to be sent */
size_t window_sending(struct frag_buffer *w, struct timeval *);

/* Returns next fragment to be sent or NULL if nothing (SEND) */
struct fragment *window_get_next_sending_fragment(struct frag_buffer *w, int *other_ack);

/* Gets the seqid of next fragment to be ACK'd (RECV) */
int window_get_next_ack(struct frag_buffer *w);

/* Sets the fragment with seqid to be ACK'd (SEND) */
void window_ack(struct frag_buffer *w, int seqid);

/* To be called after all other processing has been done
 * when anything happens (moves window etc) (SEND/RECV) */
void window_tick(struct frag_buffer *w);

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, int compressed);

#endif /* __WINDOW_H__ */
