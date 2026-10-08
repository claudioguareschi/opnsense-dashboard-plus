/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

#ifndef FM_DISCOVERY_H
#define FM_DISCOVERY_H
#include "error.h"
#include "state.h"
#include <stdint.h>

/* Bounded flow discovery (CONTRACTS.md, "Discovery"): what the collector
 * knows about flows it does not track richly.
 *
 * A summary is a weighted Space-Saving counter set over flow keys for one
 * additive primitive (byte delta, active states, new states), reset every
 * sample. It holds at most `capacity` keys. While no key was ever evicted it
 * is exact. After an eviction every estimate overcounts by at most its own
 * `error`, and any flow absent from the summary totals at most `floor`.
 * Eviction takes the smallest (count, key) entry: the result depends on the
 * stream, never on the hash key or memory layout. */
struct summary;
struct summary_entry {
  unsigned char key[FM_FLOW_KEY_SIZE];
  uint64_t count, error; /* estimate, and its overcount bound */
};
struct summary *summary_create(size_t capacity, struct fm_error *);
void summary_destroy(struct summary *);
void summary_reset(struct summary *);
/* Adds weight to key (0 is ignored); hash is index_hash(key). */
bool summary_add(struct summary *, const unsigned char key[FM_FLOW_KEY_SIZE], uint64_t hash,
                 uint64_t weight);
size_t summary_count(const struct summary *);
size_t summary_capacity(const struct summary *);
uint64_t summary_evictions(const struct summary *);
/* Upper bound of any absent key's total: 0 while exact. */
uint64_t summary_floor(const struct summary *);
uint64_t summary_total(const struct summary *);
/* The `limit` largest entries by count (ties by key), largest first;
 * returns how many were written. */
size_t summary_top(const struct summary *, struct summary_entry *, size_t limit);
const struct summary_entry *summary_find(const struct summary *,
                                         const unsigned char key[FM_FLOW_KEY_SIZE], uint64_t hash);
size_t summary_bytes(const struct summary *);

/* Distinct-flow count: HyperLogLog with 4,096 registers (standard error about
 * 1.6%), on a fixed-key hash so the estimate does not depend on the process
 * hash key. */
#define CARDINALITY_REGISTERS 4096
struct cardinality {
  unsigned char registers[CARDINALITY_REGISTERS];
};
void cardinality_reset(struct cardinality *);
void cardinality_add(struct cardinality *, const unsigned char key[FM_FLOW_KEY_SIZE]);
uint64_t cardinality_estimate(const struct cardinality *);

/* The discovery tier of one sample: Space-Saving summaries of the untracked
 * flows' byte deltas, active states and new states, and their distinct
 * count. Tracked flows are counted exactly elsewhere; the two populations
 * are disjoint, so the flow total is tracked + `flows`. */
#define DISCOVERY_BYTES_CAPACITY 65536
#define DISCOVERY_STATES_CAPACITY 32768
struct discovery {
  struct summary *bytes, *states, *created;
  struct cardinality flows;
  uint64_t untracked_states;
};
bool discovery_init(struct discovery *, struct fm_error *);
void discovery_reset(struct discovery *);
void discovery_destroy(struct discovery *);
size_t discovery_bytes(const struct discovery *);
#endif
