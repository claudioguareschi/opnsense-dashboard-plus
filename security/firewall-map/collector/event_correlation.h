/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FM_EVENT_CORRELATION_H
#define FM_EVENT_CORRELATION_H
#include "aggregate.h"
#include <stdint.h>

#define FM_MAX_EVENT_QUERIES 2500
struct event_history;
struct event_sample;
struct event_query { uint16_t id; struct outside_key key; };
/* Wire values of event_match.kind (FMAGG4). */
enum event_match_kind {
  EVENT_MATCH_CURRENT = 1, /* a PF state in this sample */
  EVENT_MATCH_RECENT = 2,  /* seen within the last 10 minutes, gone now */
};
struct event_match {
  uint16_t id;
  unsigned char kind; /* enum event_match_kind */
  struct outside_key key;
  struct correlation_value value;
};

/* The recent-tuple ring (at most 20,000 tuples seen within 10 minutes) lives
 * across samples. Each sample streams its correlated tuples through an
 * event_sample, which holds only bounded state: the sample's IDS queries and
 * a 20,000-tuple window of its newest distinct tuples. Memory never depends
 * on the number of PF states.
 *
 * Semantics (CONTRACTS.md): a query matches the last state of this sample
 * with its outside tuple (ambiguous when those states disagreed about the
 * inside endpoint), else a ring entry from an earlier sample. After the
 * sample the ring holds the earlier entries this sample did not see and that
 * are under 10 minutes old, followed by this sample's distinct tuples in
 * first-seen order, keeping the newest 20,000. One documented approximation:
 * a tuple that reappears after more than 20,000 newer distinct tuples of the
 * same sample is placed again at its reappearance. */
struct event_history *event_history_create(struct fm_error *);
void event_history_destroy(struct event_history *);
/* Forgets every recent tuple (nothing consumes them while correlation is off). */
void event_history_clear(struct event_history *);
/* Recent tuples dropped by the last sample because the ring was full. */
uint64_t event_history_evicted(const struct event_history *);

/* Starts a sample with its queries (copied). The returned sample is the
 * aggregate's tuple observer argument (event_sample_observe). */
struct event_sample *event_sample_begin(struct event_history *, const struct event_query *,
                                        size_t query_count, struct fm_error *);
bool event_sample_observe(void *sample, const struct outside_key *,
                          const struct correlation_value *, struct fm_error *);
/* Commits the sample into the ring and writes one match per answered query
 * (in query order) into matches; returns the number written. */
size_t event_sample_finish(struct event_history *, struct event_sample *, double now,
                           struct event_match *matches, size_t capacity,
                           struct fm_error *);
void event_sample_destroy(struct event_sample *);

#endif
