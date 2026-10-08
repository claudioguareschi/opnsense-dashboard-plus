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

#include "discovery.h"
#include "alloc.h"
#include "siphash.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* Entries live in a min-heap ordered by (count, key); `slots` is an
 * open-addressed index (heap position + 1, 0 empty) with backward-shift
 * deletion, sized a power of two at least twice the capacity. */
struct node {
  struct summary_entry entry;
  uint64_t hash;
};
struct summary {
  struct node *heap;
  uint32_t *slots;
  size_t capacity, used, mask;
  uint64_t evictions, total;
};

static bool less(const struct node *a, const struct node *b) {
  if (a->entry.count != b->entry.count) return a->entry.count < b->entry.count;
  return memcmp(a->entry.key, b->entry.key, FM_FLOW_KEY_SIZE) < 0;
}

/* The index slot holding heap position `position`'s key, or the empty slot
 * where hash/key belongs. */
static size_t find_slot(const struct summary *s, const unsigned char *key, uint64_t hash) {
  size_t n = hash & s->mask;
  while (s->slots[n]) {
    const struct node *node = &s->heap[s->slots[n] - 1];
    if (node->hash == hash && !memcmp(node->entry.key, key, FM_FLOW_KEY_SIZE)) return n;
    n = (n + 1) & s->mask;
  }
  return n;
}
static void unindex(struct summary *s, size_t n) {
  size_t hole = n, next = (n + 1) & s->mask;
  while (s->slots[next]) {
    size_t want = s->heap[s->slots[next] - 1].hash & s->mask;
    if (((next - want) & s->mask) >= ((next - hole) & s->mask)) {
      s->slots[hole] = s->slots[next];
      hole = next;
    }
    next = (next + 1) & s->mask;
  }
  s->slots[hole] = 0;
}
/* Moves the node at heap[from] (still there, so its slot is found) to `to`. */
static void move(struct summary *s, size_t from, size_t to) {
  size_t slot = find_slot(s, s->heap[from].entry.key, s->heap[from].hash);
  s->heap[to] = s->heap[from];
  s->slots[slot] = (uint32_t)to + 1;
}
/* Sifts heap[n], whose index slot is `slot`: that slot is found before the
 * sift, while heap[n] still holds the node. */
static void sift_down(struct summary *s, size_t n, size_t slot) {
  struct node node = s->heap[n];
  for (;;) {
    size_t child = 2 * n + 1;
    if (child >= s->used) break;
    if (child + 1 < s->used && less(&s->heap[child + 1], &s->heap[child])) child++;
    if (!less(&s->heap[child], &node)) break;
    move(s, child, n);
    n = child;
  }
  s->heap[n] = node;
  s->slots[slot] = (uint32_t)n + 1;
}
static void sift_up(struct summary *s, size_t n, size_t slot) {
  struct node node = s->heap[n];
  while (n) {
    size_t parent = (n - 1) / 2;
    if (!less(&node, &s->heap[parent])) break;
    move(s, parent, n);
    n = parent;
  }
  s->heap[n] = node;
  s->slots[slot] = (uint32_t)n + 1;
}

struct summary *summary_create(size_t capacity, struct fm_error *error) {
  if (!capacity || capacity > UINT32_MAX / 4) {
    fm_error_set(error, EINVAL, "summary capacity");
    return NULL;
  }
  struct summary *s = fm_calloc(1, sizeof(*s));
  size_t slots = 1;
  while (slots < capacity * 2) slots *= 2;
  if (s) {
    s->capacity = capacity;
    s->mask = slots - 1;
    s->heap = fm_calloc(capacity, sizeof(*s->heap));
    s->slots = fm_calloc(slots, sizeof(*s->slots));
  }
  if (!s || !s->heap || !s->slots) {
    fm_error_set(error, ENOMEM, "summary allocation");
    summary_destroy(s);
    return NULL;
  }
  return s;
}
void summary_destroy(struct summary *s) {
  if (!s) return;
  fm_free(s->heap);
  fm_free(s->slots);
  fm_free(s);
}
void summary_reset(struct summary *s) {
  /* the whole index: clearing slot by slot would break probe chains */
  memset(s->slots, 0, (s->mask + 1) * sizeof(*s->slots));
  s->used = 0;
  s->evictions = s->total = 0;
}

bool summary_add(struct summary *s, const unsigned char key[FM_FLOW_KEY_SIZE], uint64_t hash,
                 uint64_t weight) {
  if (!weight) return true;
  s->total = UINT64_MAX - s->total < weight ? UINT64_MAX : s->total + weight;
  size_t slot = find_slot(s, key, hash);
  if (s->slots[slot]) {
    size_t n = s->slots[slot] - 1;
    struct summary_entry *e = &s->heap[n].entry;
    e->count = UINT64_MAX - e->count < weight ? UINT64_MAX : e->count + weight;
    sift_down(s, n, slot);
    return true;
  }
  if (s->used < s->capacity) {
    size_t n = s->used++;
    s->heap[n] = (struct node){.hash = hash};
    memcpy(s->heap[n].entry.key, key, FM_FLOW_KEY_SIZE);
    s->heap[n].entry.count = weight;
    s->slots[slot] = (uint32_t)n + 1;
    sift_up(s, n, slot);
    return true;
  }
  /* full: the new key takes over the smallest entry and inherits its count
   * as error */
  struct node *min = &s->heap[0];
  uint64_t floor = min->entry.count;
  unindex(s, find_slot(s, min->entry.key, min->hash));
  memcpy(min->entry.key, key, FM_FLOW_KEY_SIZE);
  min->hash = hash;
  min->entry.error = floor;
  min->entry.count = UINT64_MAX - floor < weight ? UINT64_MAX : floor + weight;
  slot = find_slot(s, key, hash);
  s->slots[slot] = 1;
  sift_down(s, 0, slot);
  s->evictions++;
  return true;
}

size_t summary_count(const struct summary *s) { return s->used; }
size_t summary_capacity(const struct summary *s) { return s->capacity; }
uint64_t summary_evictions(const struct summary *s) { return s->evictions; }
uint64_t summary_floor(const struct summary *s) {
  return s->evictions && s->used ? s->heap[0].entry.count : 0;
}
uint64_t summary_total(const struct summary *s) { return s->total; }

const struct summary_entry *summary_find(const struct summary *s,
                                         const unsigned char key[FM_FLOW_KEY_SIZE], uint64_t hash) {
  size_t slot = find_slot(s, key, hash);
  return s->slots[slot] ? &s->heap[s->slots[slot] - 1].entry : NULL;
}

static int larger_first(const void *left, const void *right) {
  const struct summary_entry *a = left, *b = right;
  if (a->count != b->count) return a->count > b->count ? -1 : 1;
  return memcmp(a->key, b->key, FM_FLOW_KEY_SIZE);
}
size_t summary_top(const struct summary *s, struct summary_entry *out, size_t limit) {
  /* a bounded selection: keep the `limit` largest in out, sorted at the end */
  size_t kept = 0;
  for (size_t n = 0; n < s->used && limit; n++) {
    const struct summary_entry *e = &s->heap[n].entry;
    if (kept < limit) {
      out[kept++] = *e;
      if (kept == limit) qsort(out, kept, sizeof(*out), larger_first);
      continue;
    }
    if (larger_first(e, &out[kept - 1]) >= 0) continue;
    /* insert e in sorted position, dropping the last */
    size_t at = kept - 1;
    while (at && larger_first(e, &out[at - 1]) < 0) {
      out[at] = out[at - 1];
      at--;
    }
    out[at] = *e;
  }
  if (kept < limit) qsort(out, kept, sizeof(*out), larger_first);
  return kept;
}
size_t summary_bytes(const struct summary *s) {
  return s ? sizeof(*s) + s->capacity * sizeof(*s->heap) + (s->mask + 1) * sizeof(*s->slots) : 0;
}

/* HyperLogLog (Flajolet et al.) with the small-range linear-counting
 * correction; 2^12 registers. */
static const uint8_t cardinality_key[16] = {0x66, 0x6d, 0x2d, 0x68, 0x6c, 0x6c, 0x2d, 0x76,
                                            0x31, 0x00, 0x5a, 0xa5, 0x3c, 0xc3, 0x0f, 0xf0};
void cardinality_reset(struct cardinality *c) { memset(c->registers, 0, sizeof(c->registers)); }
void cardinality_add(struct cardinality *c, const unsigned char key[FM_FLOW_KEY_SIZE]) {
  uint64_t h = siphash13(cardinality_key, key, FM_FLOW_KEY_SIZE);
  size_t index = h >> 52;
  uint64_t rest = (h << 12) | (UINT64_C(1) << 11);
  unsigned char rank = (unsigned char)(__builtin_clzll(rest) + 1);
  if (rank > c->registers[index]) c->registers[index] = rank;
}
uint64_t cardinality_estimate(const struct cardinality *c) {
  const double m = CARDINALITY_REGISTERS, alpha = 0.7213 / (1.0 + 1.079 / m);
  double sum = 0;
  size_t zeros = 0;
  for (size_t n = 0; n < CARDINALITY_REGISTERS; n++) {
    sum += ldexp(1.0, -(int)c->registers[n]);
    zeros += !c->registers[n];
  }
  double estimate = alpha * m * m / sum;
  if (estimate <= 2.5 * m && zeros) estimate = m * log(m / (double)zeros);
  return (uint64_t)(estimate + 0.5);
}

bool discovery_init(struct discovery *d, struct fm_error *error) {
  memset(d, 0, sizeof(*d));
  d->bytes = summary_create(DISCOVERY_BYTES_CAPACITY, error);
  d->states = d->bytes ? summary_create(DISCOVERY_STATES_CAPACITY, error) : NULL;
  d->created = d->states ? summary_create(DISCOVERY_STATES_CAPACITY, error) : NULL;
  if (!d->created) {
    discovery_destroy(d);
    return false;
  }
  return true;
}
void discovery_reset(struct discovery *d) {
  summary_reset(d->bytes);
  summary_reset(d->states);
  summary_reset(d->created);
  cardinality_reset(&d->flows);
  d->untracked_states = 0;
}
void discovery_destroy(struct discovery *d) {
  summary_destroy(d->bytes);
  summary_destroy(d->states);
  summary_destroy(d->created);
  memset(d, 0, sizeof(*d));
}
size_t discovery_bytes(const struct discovery *d) {
  return summary_bytes(d->bytes) + summary_bytes(d->states) + summary_bytes(d->created);
}
