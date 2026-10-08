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

#include "event_correlation.h"
#include "index.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define RECENT_LIMIT 20000
#define RECENT_SECONDS 600.0
/* open-addressed index over the sample window: a power of two above
 * RECENT_LIMIT / 0.75 */
#define WINDOW_SLOTS 32768u

struct saved {
  struct outside_key key;
  struct correlation_value value;
  double seen;
};
struct event_history {
  struct saved rows[RECENT_LIMIT];
  size_t count;
  uint64_t evicted;
  struct map index; /* encoded key -> row (item value) */
};
struct query_slot {
  struct correlation_value value;
  bool found;
};
struct event_sample {
  struct event_history *history;
  struct map query_index; /* encoded key -> slot (item value) */
  struct query_slot *slots;
  struct event_query *queries;
  size_t query_count;
  unsigned char *old_seen; /* per ring row: seen again in this sample */
  /* this sample's newest distinct tuples, oldest first, circular */
  struct saved *window;
  size_t head, count;
  uint64_t distinct; /* distinct tuples appended (re-appearances after eviction count again) */
  uint32_t *table;   /* window index: 0 empty, else window position + 1 */
  uint64_t *hashes;  /* per window position: its key's index_hash */
};

struct event_history *event_history_create(struct fm_error *error) {
  struct event_history *history = fm_calloc(1, sizeof(*history));
  if (!history) fm_error_set(error, errno, "event history allocation");
  return history;
}

void event_history_destroy(struct event_history *history) {
  if (!history) return;
  map_clear(&history->index);
  fm_free(history);
}

void event_history_clear(struct event_history *history) {
  map_clear(&history->index);
  history->count = 0;
  history->evicted = 0;
}

uint64_t event_history_evicted(const struct event_history *history) { return history->evicted; }

static size_t window_home(uint64_t hash) { return (size_t)(hash & (WINDOW_SLOTS - 1)); }

static bool endpoint_same(const struct endpoint *a, const struct endpoint *b) {
  return a->port == b->port && a->a.af == b->a.af &&
         !memcmp(a->a.b, b->a.b, a->a.af == 4 ? 4 : 16);
}
static bool key_equal(const struct outside_key *a, const struct outside_key *b) {
  return a->protocol == b->protocol && endpoint_same(&a->public, &b->public) &&
         endpoint_same(&a->remote, &b->remote);
}

/* The index slot holding key, or the empty slot where it belongs. */
static size_t window_find(const struct event_sample *s, const struct outside_key *key,
                          uint64_t hash) {
  size_t n = window_home(hash);
  while (s->table[n] && (s->hashes[s->table[n] - 1] != hash ||
                         !key_equal(&s->window[s->table[n] - 1].key, key)))
    n = (n + 1) & (WINDOW_SLOTS - 1);
  return n;
}

/* Backward-shift deletion keeps every remaining key reachable. */
static void window_unindex(struct event_sample *s, size_t n) {
  size_t hole = n, next = (n + 1) & (WINDOW_SLOTS - 1);
  while (s->table[next]) {
    size_t want = window_home(s->hashes[s->table[next] - 1]);
    if (((next - want) & (WINDOW_SLOTS - 1)) >= ((next - hole) & (WINDOW_SLOTS - 1))) {
      s->table[hole] = s->table[next];
      hole = next;
    }
    next = (next + 1) & (WINDOW_SLOTS - 1);
  }
  s->table[hole] = 0;
}

void event_sample_destroy(struct event_sample *s) {
  if (!s) return;
  map_clear(&s->query_index);
  fm_free(s->slots);
  fm_free(s->queries);
  fm_free(s->old_seen);
  fm_free(s->window);
  fm_free(s->table);
  fm_free(s->hashes);
  fm_free(s);
}

struct event_sample *event_sample_begin(struct event_history *history,
                                        const struct event_query *queries,
                                        size_t query_count, struct fm_error *error) {
  struct event_sample *s = fm_calloc(1, sizeof(*s));
  if (!s) {
    fm_error_set(error, errno, "event sample allocation");
    return NULL;
  }
  s->history = history;
  s->query_count = query_count;
  s->queries = query_count ? fm_calloc(query_count, sizeof(*queries)) : NULL;
  s->slots = query_count ? fm_calloc(query_count, sizeof(*s->slots)) : NULL;
  s->old_seen = fm_calloc(RECENT_LIMIT, 1);
  s->window = fm_calloc(RECENT_LIMIT, sizeof(*s->window));
  s->table = fm_calloc(WINDOW_SLOTS, sizeof(*s->table));
  s->hashes = fm_calloc(RECENT_LIMIT, sizeof(*s->hashes));
  if ((query_count && (!s->queries || !s->slots)) || !s->old_seen || !s->window || !s->table ||
      !s->hashes) {
    fm_error_set(error, ENOMEM, "event sample allocation");
    event_sample_destroy(s);
    return NULL;
  }
  if (query_count) memcpy(s->queries, queries, query_count * sizeof(*queries));
  for (size_t n = 0; n < query_count; n++) {
    unsigned char encoded[OUTSIDE_KEY_SIZE];
    size_t length = outside_key_encode(encoded, queries[n].key);
    struct item *item = lookup(&s->query_index, encoded, length, true, error);
    if (!item) {
      event_sample_destroy(s);
      return NULL;
    }
    item->value = item->id; /* one slot per distinct queried tuple */
  }
  return s;
}

bool event_sample_observe(void *sample, const struct outside_key *key,
                          const struct correlation_value *value, struct fm_error *error) {
  struct event_sample *s = sample;
  if ((key->public.a.af != 4 && key->public.a.af != 6) ||
      (key->remote.a.af != 4 && key->remote.a.af != 6))
    return fm_error_set(error, EINVAL, "correlation address family");
  /* one encoding and one keyed hash serve all three lookups */
  unsigned char encoded[OUTSIDE_KEY_SIZE];
  size_t length = outside_key_encode(encoded, *key);
  uint64_t hash = index_hash(encoded, length);
  const struct item *query =
      s->query_count ? map_find_hashed(&s->query_index, encoded, length, hash) : NULL;
  if (query) {
    struct query_slot *slot = &s->slots[query->value];
    correlation_merge(&slot->value, slot->found, value);
    slot->found = true;
  }
  const struct item *old =
      s->history->count ? map_find_hashed(&s->history->index, encoded, length, hash) : NULL;
  if (old && old->value < s->history->count)
    s->old_seen[old->value] = 1;
  size_t n = window_find(s, key, hash);
  if (s->table[n]) {
    struct saved *row = &s->window[s->table[n] - 1];
    correlation_merge(&row->value, true, value);
    return true;
  }
  if (s->count == RECENT_LIMIT) {
    /* the window keeps the newest distinct tuples: drop the oldest */
    window_unindex(s, window_find(s, &s->window[s->head].key, s->hashes[s->head]));
    s->head = (s->head + 1) % RECENT_LIMIT;
    s->count--;
    n = window_find(s, key, hash);
  }
  size_t position = (s->head + s->count) % RECENT_LIMIT;
  struct saved *row = &s->window[position];
  memset(row, 0, sizeof(*row));
  row->key = *key;
  s->hashes[position] = hash;
  correlation_merge(&row->value, false, value);
  s->table[n] = (uint32_t)position + 1;
  s->count++;
  s->distinct++;
  return true;
}

size_t event_sample_finish(struct event_history *history, struct event_sample *s, double now,
                           struct event_match *matches, size_t capacity,
                           struct fm_error *error) {
  struct saved *next = fm_calloc(RECENT_LIMIT, sizeof(*next));
  if (!next) {
    fm_error_set(error, errno, "event history sample");
    return 0;
  }
  /* earlier entries this sample did not see, still recent, oldest first */
  size_t kept = 0;
  for (size_t n = 0; n < history->count; n++)
    kept += now - history->rows[n].seen <= RECENT_SECONDS && !s->old_seen[n];
  uint64_t appended = kept + s->distinct;
  size_t room = RECENT_LIMIT - s->count, skip = kept > room ? kept - room : 0, count = 0;
  for (size_t n = 0, k = 0; n < history->count; n++) {
    if (!(now - history->rows[n].seen <= RECENT_SECONDS && !s->old_seen[n]))
      continue;
    if (k++ >= skip)
      next[count++] = history->rows[n];
  }
  for (size_t n = 0; n < s->count; n++) {
    next[count] = s->window[(s->head + n) % RECENT_LIMIT];
    next[count++].seen = now;
  }
  memcpy(history->rows, next, count * sizeof(*next));
  fm_free(next);
  history->count = count;
  history->evicted = appended > RECENT_LIMIT ? appended - RECENT_LIMIT : 0;
  map_clear(&history->index);
  for (size_t n = 0; n < count; n++) {
    unsigned char key[OUTSIDE_KEY_SIZE];
    struct item *item = lookup(&history->index, key, outside_key_encode(key, history->rows[n].key),
                               true, error);
    if (!item) return 0;
    item->value = n;
  }
  size_t found = 0;
  for (size_t n = 0; n < s->query_count; n++) {
    unsigned char encoded[OUTSIDE_KEY_SIZE];
    size_t length = outside_key_encode(encoded, s->queries[n].key);
    const struct item *query = map_find(&s->query_index, encoded, length);
    struct correlation_value value;
    unsigned char kind;
    if (query && s->slots[query->value].found) {
      value = s->slots[query->value].value;
      kind = EVENT_MATCH_CURRENT;
    } else {
      const struct item *item = map_find(&history->index, encoded, length);
      if (!item || item->value >= history->count) continue;
      value = history->rows[item->value].value;
      kind = EVENT_MATCH_RECENT;
    }
    if (found == capacity) {
      fm_error_set(error, EOVERFLOW, "event match capacity");
      return 0;
    }
    matches[found++] = (struct event_match){s->queries[n].id, kind, s->queries[n].key, value};
  }
  return found;
}
