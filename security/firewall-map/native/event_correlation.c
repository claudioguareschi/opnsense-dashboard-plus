/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
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
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define RECENT_LIMIT 20000
#define RECENT_SECONDS 600.0

struct saved {
  struct outside_key key;
  struct correlation_value value;
  double seen;
};
struct event_history {
  struct saved rows[RECENT_LIMIT];
  size_t count;
  struct map index;
};

static size_t encode(unsigned char out[39], struct outside_key key) {
  unsigned char *p = out;
  *p++ = key.protocol;
  const struct endpoint *endpoints[] = {&key.public, &key.remote};
  for (size_t n = 0; n < 2; n++) {
    *p++ = endpoints[n]->a.af;
    memcpy(p, endpoints[n]->a.b, 16); p += 16;
    uint16_t port = htons(endpoints[n]->port);
    memcpy(p, &port, 2); p += 2;
  }
  return (size_t)(p - out);
}

static void append(struct saved rows[RECENT_LIMIT], size_t *head,
                   size_t *count, struct saved value) {
  size_t slot;
  if (*count < RECENT_LIMIT) {
    slot = (*head + *count) % RECENT_LIMIT;
    (*count)++;
  } else {
    slot = *head;
    *head = (*head + 1) % RECENT_LIMIT;
  }
  rows[slot] = value;
}

struct event_history *event_history_create(struct fm_error *error) {
  struct event_history *history = calloc(1, sizeof(*history));
  if (!history) fm_error_set(error, errno, "event history allocation");
  return history;
}

void event_history_destroy(struct event_history *history) {
  if (!history) return;
  map_clear(&history->index);
  free(history);
}

bool event_history_update(struct event_history *history,
                          const struct aggregate *aggregate, double now,
                          struct fm_error *error) {
  struct saved *next = calloc(RECENT_LIMIT, sizeof(*next));
  if (!next) return fm_error_set(error, errno, "event history sample");
  size_t count = 0, head = 0;
  /* Keep recent keys that are not in the current sample, then append current
   * keys in PF insertion order. This matches the Python recent-entry order. */
  for (size_t n = 0; n < history->count; n++) {
    struct saved old = history->rows[n];
    struct correlation_value current;
    if (now - old.seen <= RECENT_SECONDS &&
        !aggregate_correlation_lookup(aggregate, old.key, &current))
      append(next, &head, &count, old);
  }
  for (size_t n = 0; n < aggregate_correlation_count(aggregate); n++) {
    struct outside_key key;
    struct correlation_value value;
    if (!aggregate_correlation(aggregate, n, &key, &value)) {
      free(next);
      return fm_error_set(error, EINVAL, "event history current key");
    }
    append(next, &head, &count, (struct saved){key, value, now});
  }
  for (size_t n = 0; n < count; n++)
    history->rows[n] = next[(head + n) % RECENT_LIMIT];
  history->count = count;
  free(next);
  map_clear(&history->index);
  for (size_t n = 0; n < count; n++) {
    unsigned char key[39];
    struct item *item = lookup(&history->index, key, encode(key, history->rows[n].key),
                               true, error);
    if (!item) return false;
    item->value = n;
  }
  return true;
}

size_t event_history_match(const struct event_history *history,
                           const struct aggregate *aggregate,
                           const struct event_query *queries, size_t query_count,
                           struct event_match *matches, size_t capacity,
                           struct fm_error *error) {
  size_t found = 0;
  for (size_t n = 0; n < query_count; n++) {
    struct correlation_value value;
    unsigned char kind;
    if (aggregate_correlation_lookup(aggregate, queries[n].key, &value)) {
      kind = 1;
    } else {
      unsigned char encoded[39];
      struct item *item = lookup((struct map *)&history->index, encoded,
                                 encode(encoded, queries[n].key), false, NULL);
      if (!item || item->value >= history->count) continue;
      const struct saved *saved = &history->rows[item->value];
      value = saved->value;
      kind = 2;
    }
    if (found == capacity) {
      fm_error_set(error, EOVERFLOW, "event match capacity");
      return 0;
    }
    matches[found++] = (struct event_match){queries[n].id, kind, queries[n].key, value};
  }
  return found;
}
