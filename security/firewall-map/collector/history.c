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

#include "history.h"
#include "alloc.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
struct counter {
  uint64_t id, bytes_from_remote, bytes_to_remote, packets;
  uint32_t creator;
};
struct table {
  struct counter *rows;
  unsigned char *used;
  size_t capacity, count;
};
struct history {
  struct table previous, current;
  double anchor, staged_anchor, interval;
  bool anchored, staging;
};
static uint64_t identity_hash(uint64_t id, uint32_t creator) {
  uint64_t h = id ^ ((uint64_t)creator << 32);
  h ^= h >> 30;
  h *= UINT64_C(0xbf58476d1ce4e5b9);
  h ^= h >> 27;
  h *= UINT64_C(0x94d049bb133111eb);
  return h ^ (h >> 31);
}
static void clear(struct table *t) {
  fm_free(t->rows);
  fm_free(t->used);
  memset(t, 0, sizeof(*t));
}
static size_t slot(const struct table *t, uint64_t id, uint32_t creator) {
  size_t n = identity_hash(id, creator) & (t->capacity - 1);
  while (t->used[n] && (t->rows[n].id != id || t->rows[n].creator != creator))
    n = (n + 1) & (t->capacity - 1);
  return n;
}
static bool grow(struct table *t, struct fm_error *error) {
  size_t capacity = t->capacity ? t->capacity * 2 : 64;
  if (capacity < t->capacity || capacity > SIZE_MAX / sizeof(*t->rows))
    return fm_error_set(error, EOVERFLOW, "history capacity");
  struct table next = {.capacity = capacity, .count = t->count};
  next.rows = fm_calloc(capacity, sizeof(*next.rows));
  next.used = fm_calloc(capacity, 1);
  if (!next.rows || !next.used) {
    clear(&next);
    return fm_error_set(error, ENOMEM, "history allocation");
  }
  for (size_t n = 0; n < t->capacity; n++)
    if (t->used[n]) {
      size_t target = slot(&next, t->rows[n].id, t->rows[n].creator);
      next.rows[target] = t->rows[n];
      next.used[target] = 1;
    }
  clear(t);
  *t = next;
  return true;
}
struct history *history_create(struct fm_error *error) {
  struct history *h = fm_calloc(1, sizeof(*h));
  if (!h)
    fm_error_set(error, errno, "history allocation");
  return h;
}
void history_destroy(struct history *h) {
  if (h) {
    clear(&h->previous);
    clear(&h->current);
    fm_free(h);
  }
}
void history_reset(struct history *h) {
  if (!h || h->staging)
    return;
  clear(&h->previous);
  clear(&h->current);
  h->anchored = false;
}
bool history_begin(struct history *h, double anchor, struct fm_error *error) {
  if (h->staging || !isfinite(anchor) ||
      (h->anchored && anchor <= h->anchor))
    return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "history sample boundary");
  clear(&h->current);
  h->staged_anchor = anchor;
  h->interval = h->anchored ? anchor - h->anchor : -1;
  h->staging = true;
  return true;
}
double history_interval(const struct history *h) { return h->interval; }
bool history_observe(struct history *h, const struct state *s, bool remote,
                     struct state_delta *delta, struct fm_error *error) {
  if (!h->staging)
    return fm_error_set(error, EINVAL, "history sample not begun");
  if (UINT64_MAX - s->pf_packets[0] < s->pf_packets[1])
    return fm_error_set(error, EOVERFLOW, "packet total overflow");
  struct counter row = {.id = s->id,
                        .creator = s->creator,
                        .bytes_from_remote = state_bytes_from_remote(s, remote),
                        .bytes_to_remote = state_bytes_to_remote(s, remote),
                        .packets = s->pf_packets[0] + s->pf_packets[1]};
  const struct counter *old = NULL;
  if (h->previous.capacity) {
    size_t n = slot(&h->previous, s->id, s->creator);
    if (h->previous.used[n])
      old = &h->previous.rows[n];
  }
  memset(delta, 0, sizeof(*delta));
  if (old) {
    /* A counter that went backwards (reset or identity reuse) contributes
     * nothing this sample; the new value becomes the next baseline. */
    delta->bytes_from_remote = row.bytes_from_remote > old->bytes_from_remote
                                   ? row.bytes_from_remote - old->bytes_from_remote
                                   : 0;
    delta->bytes_to_remote = row.bytes_to_remote > old->bytes_to_remote
                                 ? row.bytes_to_remote - old->bytes_to_remote
                                 : 0;
    delta->packets =
        row.packets > old->packets ? row.packets - old->packets : 0;
  } else if (h->interval >= 0 && s->age <= 2 * h->interval) {
    /* Created since the previous sample (age has whole-second resolution):
     * all of its traffic is new. */
    delta->bytes_from_remote = row.bytes_from_remote;
    delta->bytes_to_remote = row.bytes_to_remote;
    delta->packets = row.packets;
  }
  struct table *t = &h->current;
  if ((!t->capacity || t->count >= t->capacity * 3 / 4) && !grow(t, error))
    return false;
  size_t n = slot(t, s->id, s->creator);
  if (!t->used[n]) {
    t->count++;
    t->used[n] = 1;
  }
  /* Every duplicate compares with the previous sample, not an earlier row
   * in this sample. The final duplicate supplies the next sample's baseline. */
  t->rows[n] = row;
  return true;
}
void history_commit(struct history *h) {
  if (!h->staging)
    return;
  clear(&h->previous);
  h->previous = h->current;
  memset(&h->current, 0, sizeof(h->current));
  h->anchor = h->staged_anchor;
  h->anchored = true;
  h->staging = false;
}
void history_abort(struct history *h) {
  clear(&h->current);
  h->staging = false;
}
size_t history_bytes(const struct history *h) {
  return (h->previous.capacity + h->current.capacity) *
         (sizeof(struct counter) + 1);
}
