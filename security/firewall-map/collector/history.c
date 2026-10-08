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

#include "history.h"
#include "alloc.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* The compact state baseline (CONTRACTS.md): one open-addressed table of
 * 40-byte entries keyed by (creator, id), updated in place. An entry's epoch
 * says which sample last saw the state: the committed epoch (previous sample)
 * or the staged one (this sample). After a committed sample every entry the
 * sample did not see has departed and is removed by backward-shift deletion,
 * so the table holds no tombstones and lookups stop at the first empty slot.
 * Epoch 0 marks an empty slot. */
struct entry {
  uint64_t id, bytes_from_remote, bytes_to_remote, packets;
  uint32_t creator, epoch;
};
_Static_assert(sizeof(struct entry) == 40, "baseline entry layout");

struct history {
  struct entry *rows;
  size_t capacity, count;
  uint32_t committed, staged; /* epochs; 0 = none */
  double anchor, staged_anchor, interval;
  bool anchored, staging;
  struct history_stats stats;
};

/* Any capacity works (multiply-shift maps a hash onto it), so the table
 * stays near its target load instead of jumping between powers of two.
 * Above the maximum load it grows by half (rehash: old and new arrays coexist
 * briefly, which the accounted heap budget sees). */
#define HISTORY_MAX_LOAD_NUM 3
#define HISTORY_MAX_LOAD_DEN 4
#define HISTORY_MIN_CAPACITY 64

static uint64_t identity_hash(uint64_t id, uint32_t creator) {
  uint64_t h = id ^ ((uint64_t)creator << 32);
  h ^= h >> 30;
  h *= UINT64_C(0xbf58476d1ce4e5b9);
  h ^= h >> 27;
  h *= UINT64_C(0x94d049bb133111eb);
  return h ^ (h >> 31);
}

static size_t home(const struct history *h, uint64_t id, uint32_t creator) {
  return (size_t)(((unsigned __int128)identity_hash(id, creator) * h->capacity) >> 64);
}

static size_t next_slot(const struct history *h, size_t n) {
  return n + 1 == h->capacity ? 0 : n + 1;
}

/* Distance from slot `from` forward to slot `to`, wrapping. */
static size_t forward(const struct history *h, size_t from, size_t to) {
  return to >= from ? to - from : to + h->capacity - from;
}

/* The slot holding (id, creator), or the empty slot where it belongs. */
static size_t probe(const struct history *h, uint64_t id, uint32_t creator) {
  size_t n = home(h, id, creator);
  while (h->rows[n].epoch && (h->rows[n].id != id || h->rows[n].creator != creator))
    n = next_slot(h, n);
  return n;
}

static bool resize(struct history *h, size_t capacity, struct fm_error *error) {
  if (capacity < HISTORY_MIN_CAPACITY)
    capacity = HISTORY_MIN_CAPACITY;
  if (capacity > SIZE_MAX / sizeof(struct entry))
    return fm_error_set(error, EOVERFLOW, "baseline capacity");
  struct entry *rows = fm_calloc(capacity, sizeof(*rows));
  if (!rows)
    return fm_error_set(error, ENOMEM, "baseline allocation");
  struct history next = *h;
  next.rows = rows;
  next.capacity = capacity;
  for (size_t n = 0; n < h->capacity; n++)
    if (h->rows[n].epoch)
      rows[probe(&next, h->rows[n].id, h->rows[n].creator)] = h->rows[n];
  fm_free(h->rows);
  h->rows = rows;
  h->capacity = capacity;
  h->stats.resizes++;
  return true;
}

/* The capacity at which `entries` sit at the maximum load. */
static size_t capacity_for(size_t entries) {
  if (entries > SIZE_MAX / HISTORY_MAX_LOAD_DEN)
    return SIZE_MAX;
  size_t capacity = (entries * HISTORY_MAX_LOAD_DEN + HISTORY_MAX_LOAD_NUM - 1) / HISTORY_MAX_LOAD_NUM;
  return capacity < HISTORY_MIN_CAPACITY ? HISTORY_MIN_CAPACITY : capacity;
}

struct history *history_create(struct fm_error *error) {
  struct history *h = fm_calloc(1, sizeof(*h));
  if (!h)
    fm_error_set(error, errno, "history allocation");
  return h;
}

void history_destroy(struct history *h) {
  if (h) {
    fm_free(h->rows);
    fm_free(h);
  }
}

void history_reset(struct history *h) {
  if (!h || h->staging)
    return;
  fm_free(h->rows);
  h->rows = NULL;
  h->capacity = h->count = 0;
  h->committed = h->staged = 0;
  h->anchored = false;
}

bool history_reserve(struct history *h, size_t expected, struct fm_error *error) {
  size_t capacity = capacity_for(expected);
  return capacity <= h->capacity || resize(h, capacity, error);
}

bool history_begin(struct history *h, double anchor, struct fm_error *error) {
  if (h->staging || !isfinite(anchor) ||
      (h->anchored && anchor <= h->anchor))
    return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "history sample boundary");
  if (h->committed == UINT32_MAX) {
    /* epoch wrap: start over with a baseline sample */
    history_reset(h);
  }
  h->staged = h->committed + 1;
  h->staged_anchor = anchor;
  h->interval = h->anchored ? anchor - h->anchor : -1;
  h->staging = true;
  memset(&h->stats, 0, sizeof(h->stats));
  return true;
}

double history_interval(const struct history *h) { return h->interval; }

bool history_observe(struct history *h, const struct state *s, bool remote,
                     struct state_delta *delta, struct fm_error *error) {
  if (!h->staging)
    return fm_error_set(error, EINVAL, "history sample not begun");
  if (UINT64_MAX - s->pf_packets[0] < s->pf_packets[1])
    return fm_error_set(error, EOVERFLOW, "packet total overflow");
  if (!h->capacity || (h->count + 1) * HISTORY_MAX_LOAD_DEN > h->capacity * HISTORY_MAX_LOAD_NUM) {
    size_t grown = h->capacity + h->capacity / 2;
    if (!resize(h, grown > h->capacity ? grown : HISTORY_MIN_CAPACITY, error))
      return false;
  }
  uint64_t from = state_bytes_from_remote(s, remote), to = state_bytes_to_remote(s, remote),
           packets = s->pf_packets[0] + s->pf_packets[1];
  size_t n = probe(h, s->id, s->creator);
  struct entry *e = &h->rows[n];
  memset(delta, 0, sizeof(*delta));
  if (e->epoch) {
    /* Seen before: in the committed sample, or earlier in this one (a
     * duplicate, which then compares with that occurrence). A counter that
     * went backwards (reset or identity reuse) contributes nothing; the new
     * value becomes the next baseline. */
    delta->bytes_from_remote = from > e->bytes_from_remote ? from - e->bytes_from_remote : 0;
    delta->bytes_to_remote = to > e->bytes_to_remote ? to - e->bytes_to_remote : 0;
    delta->packets = packets > e->packets ? packets - e->packets : 0;
    if (e->epoch == h->staged)
      h->stats.duplicates++;
    else
      h->stats.surviving++;
  } else {
    /* Not in the committed sample: created since (age has whole-second
     * resolution), so all of its traffic is new; otherwise unknown. */
    if (h->interval >= 0 && s->age <= 2 * h->interval) {
      delta->bytes_from_remote = from;
      delta->bytes_to_remote = to;
      delta->packets = packets;
    }
    h->count++;
    h->stats.new_states++;
    e->id = s->id;
    e->creator = s->creator;
  }
  e->bytes_from_remote = from;
  e->bytes_to_remote = to;
  e->packets = packets;
  e->epoch = h->staged;
  return true;
}

/* Removes slot n by backward shift: entries after it in the same probe run
 * move back so every remaining entry is still reachable from its home. */
static void remove_slot(struct history *h, size_t n) {
  size_t hole = n, next = next_slot(h, n);
  while (h->rows[next].epoch) {
    size_t want = home(h, h->rows[next].id, h->rows[next].creator);
    /* move `next` into the hole unless its home lies cyclically in (hole, next] */
    if (forward(h, want, next) >= forward(h, hole, next)) {
      h->rows[hole] = h->rows[next];
      hole = next;
    }
    next = next_slot(h, next);
  }
  memset(&h->rows[hole], 0, sizeof(h->rows[hole]));
}

void history_commit(struct history *h) {
  if (!h->staging)
    return;
  /* Sweep departed states. A slot refilled by a backward shift is examined
   * again; an entry shifted from the start of the array into a later slot is
   * re-examined when the scan reaches it. */
  for (size_t n = 0; n < h->capacity;) {
    if (h->rows[n].epoch && h->rows[n].epoch != h->staged) {
      remove_slot(h, n);
      h->count--;
      h->stats.departed++;
      continue;
    }
    n++;
  }
  h->committed = h->staged;
  h->anchor = h->staged_anchor;
  h->anchored = true;
  h->staging = false;
  /* Give memory back after a burst: below a quarter full, shrink to half
   * full. A failed shrink keeps the larger table (nothing is lost). */
  if (h->capacity > HISTORY_MIN_CAPACITY && h->count * 4 < h->capacity) {
    struct fm_error ignored = {0};
    resize(h, capacity_for(h->count + h->count / 2), &ignored);
  }
}

void history_abort(struct history *h) {
  /* Counters were updated in place, so this sample cannot be undone: the
   * next sample is a baseline (CONTRACTS.md). Callers stop or refuse after
   * an aborted sample anyway. */
  h->staging = false;
  history_reset(h);
}

size_t history_bytes(const struct history *h) {
  return h->capacity * sizeof(struct entry);
}

size_t history_entries(const struct history *h) { return h->count; }

struct history_stats history_stats(const struct history *h) { return h->stats; }
