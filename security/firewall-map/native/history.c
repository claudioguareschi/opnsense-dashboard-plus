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
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
struct counter {
  uint64_t id, toward, away, packets;
  uint32_t creator;
};
struct table {
  struct counter *rows;
  unsigned char *used;
  size_t capacity, count;
};
struct history {
  struct table previous, current;
  double elapsed;
  bool staging;
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
  free(t->rows);
  free(t->used);
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
  next.rows = calloc(capacity, sizeof(*next.rows));
  next.used = calloc(capacity, 1);
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
  struct history *h = calloc(1, sizeof(*h));
  if (!h)
    fm_error_set(error, errno, "history allocation");
  return h;
}
void history_destroy(struct history *h) {
  if (h) {
    clear(&h->previous);
    clear(&h->current);
    free(h);
  }
}
void history_reset(struct history *h) {
  if (!h || h->staging)
    return;
  clear(&h->previous);
  clear(&h->current);
}
bool history_begin(struct history *h, double elapsed, struct fm_error *error) {
  if (h->staging || !isfinite(elapsed))
    return fm_error_set(error, EINVAL, "history sample boundary");
  clear(&h->current);
  h->elapsed = elapsed;
  h->staging = true;
  return true;
}
bool history_observe(struct history *h, const struct state *s, bool remote,
                     struct state_delta *delta, struct fm_error *error) {
  if (!h->staging)
    return fm_error_set(error, EINVAL, "history sample not begun");
  if (UINT64_MAX - s->packets[0] < s->packets[1])
    return fm_error_set(error, EOVERFLOW, "packet total overflow");
  struct counter row = {.id = s->id,
                        .creator = s->creator,
                        .toward = s->bytes[remote ? 0 : 1],
                        .away = s->bytes[remote ? 1 : 0],
                        .packets = s->packets[0] + s->packets[1]};
  const struct counter *old = NULL;
  if (h->previous.capacity) {
    size_t n = slot(&h->previous, s->id, s->creator);
    if (h->previous.used[n])
      old = &h->previous.rows[n];
  }
  memset(delta, 0, sizeof(*delta));
  if (old) {
    delta->toward = row.toward > old->toward ? row.toward - old->toward : 0;
    delta->away = row.away > old->away ? row.away - old->away : 0;
    delta->packets =
        row.packets > old->packets ? row.packets - old->packets : 0;
  } else if (h->elapsed >= 0 && s->age <= 2 * h->elapsed) {
    delta->toward = row.toward;
    delta->away = row.away;
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
