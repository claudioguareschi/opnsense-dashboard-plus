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

#include "ranking.h"
#include "alloc.h"
#include "index.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct rate_state {
  double from_remote, to_remote, packets, last_active;
  uint64_t order, volume; /* volume: bytes of the current activity episode */
  uint64_t attempts;      /* states created in the current activity episode */
  bool active;
};
/* Two generations of per-flow rate state. `previous` is the committed one
 * (keyed by flow pair, value index = map item id); `current` is built by
 * ranking_update and then becomes `previous`. The value arrays are swapped,
 * not reallocated, so their capacity is reused from sample to sample. */
struct generation {
  struct map keys; /* flow key -> values[item id] */
  struct rate_state *values;
  size_t capacity;
};
struct ranking {
  struct generation previous, current;
  struct flow_rates *rates;
  size_t rates_capacity, total;
  uint64_t next_order;
  double fade, smoothing, sampled_at;
};

static bool reserve(void **data, size_t *capacity, size_t needed, size_t size,
                    struct fm_error *error) {
  if (needed <= *capacity)
    return true;
  size_t next = *capacity ? *capacity : 64;
  while (next < needed) {
    if (next > SIZE_MAX / 2) {
      next = needed;
      break;
    }
    next *= 2;
  }
  if (next > SIZE_MAX / size)
    return fm_error_set(error, EOVERFLOW, "ranking capacity");
  void *p = fm_realloc(*data, next * size);
  if (!p)
    return fm_error_set(error, errno, "ranking allocation");
  *data = p;
  *capacity = next;
  return true;
}

struct ranking *ranking_create(double fade, double smoothing, struct fm_error *error) {
  if (fade <= 0 || smoothing < 0 || smoothing > 1) {
    fm_error_set(error, EINVAL, "ranking options");
    return NULL;
  }
  struct ranking *r = fm_calloc(1, sizeof(*r));
  if (!r)
    fm_error_set(error, errno, "ranking allocation");
  else {
    r->fade = fade;
    r->smoothing = smoothing;
  }
  return r;
}

void ranking_destroy(struct ranking *r) {
  if (!r)
    return;
  map_clear(&r->previous.keys);
  map_clear(&r->current.keys);
  fm_free(r->previous.values);
  fm_free(r->current.values);
  fm_free(r->rates);
  fm_free(r);
}

void ranking_reset(struct ranking *r) {
  if (!r)
    return;
  /* Forget rate state but keep buffers for reuse. */
  map_clear(&r->previous.keys);
  r->total = 0;
  r->next_order = 0;
}

static double activity_at(const struct ranking *r, const struct rate_state *v,
                          double now) {
  double activity = v->active ? 1.0 - (now - v->last_active) / r->fade : 0.0;
  return activity < 0 ? 0 : activity;
}

bool ranking_update(struct ranking *r, const struct aggregate *aggregate,
                    double now, double interval, struct fm_error *error) {
  struct generation *current = &r->current;
  map_clear(&current->keys);
  size_t total = aggregate_counts(aggregate).flows;
  if (!reserve((void **)&current->values, &current->capacity, total,
               sizeof(*current->values), error) ||
      !reserve((void **)&r->rates, &r->rates_capacity, total, sizeof(*r->rates), error))
    return false;
  uint64_t next_order = r->next_order;
  for (size_t n = 0; n < total; n++) {
    const struct flow *flow = aggregate_flow(aggregate, n);
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote, flow->owner);
    struct item *item = map_insert(&current->keys, key, sizeof(key), error);
    if (!item)
      return false;
    const struct item *previous = map_find(&r->previous.keys, key, sizeof(key));
    struct rate_state old = {0};
    if (previous)
      old = r->previous.values[previous->id];
    else {
      if (next_order == UINT64_MAX)
        return fm_error_set(error, EOVERFLOW, "ranking insertion order");
      old.order = next_order++;
    }
    double per_second = interval > 0 ? 1.0 / interval : 0.0;
    struct rate_state next = {
        .from_remote = r->smoothing * flow->delta.bytes_from_remote * per_second +
                       (1.0 - r->smoothing) * old.from_remote,
        .to_remote = r->smoothing * flow->delta.bytes_to_remote * per_second +
                     (1.0 - r->smoothing) * old.to_remote,
        .packets = r->smoothing * flow->delta.packets * per_second +
                   (1.0 - r->smoothing) * old.packets,
        .order = old.order,
        .last_active = old.last_active,
        .active = old.active};
    /* flow volume: bytes since the flow last became active (an episode ends
     * when its activity has faded out) */
    uint64_t moved = flow->delta.bytes_from_remote + flow->delta.bytes_to_remote;
    next.volume = (activity_at(r, &old, now) > 0 ? old.volume : 0);
    next.volume = moved > UINT64_MAX - next.volume ? UINT64_MAX : next.volume + moved;
    next.attempts = (activity_at(r, &old, now) > 0 ? old.attempts : 0) + flow->created;
    if (flow->delta.bytes_from_remote || flow->delta.bytes_to_remote) {
      next.last_active = now;
      next.active = true;
    }
    current->values[item->id] = next;
    double activity = activity_at(r, &next, now);
    r->rates[n] = (struct flow_rates){next.from_remote, next.to_remote, next.packets, activity,
                                      next.order, next.volume, next.attempts};
  }
  /* Commit: the new generation becomes previous; the old previous buffers are
   * kept as next sample's scratch generation. */
  struct generation retired = r->previous;
  r->previous = r->current;
  r->current = retired;
  map_clear(&r->current.keys);
  r->next_order = next_order;
  r->total = total;
  r->sampled_at = now;
  return true;
}

bool ranking_rates(const struct ranking *r, size_t flow, struct flow_rates *out) {
  if (flow >= r->total)
    return false;
  *out = r->rates[flow];
  return true;
}
const struct map *ranking_keys(const struct ranking *r) { return &r->previous.keys; }

bool ranking_retain(struct ranking *r, const struct map *retained, struct fm_error *error) {
  size_t used = r->previous.keys.used;
  /* the kept history becomes the committed generation, in its old order */
  struct generation *next = &r->current;
  map_clear(&next->keys);
  bool ok = reserve((void **)&next->values, &next->capacity, used, sizeof(*next->values), error);
  for (size_t n = 0; ok && n < used; n++) {
    const struct item *i = r->previous.keys.order[n];
    if (!map_find(retained, i->key, i->len)) continue;
    struct item *copy = map_insert(&next->keys, i->key, i->len, error);
    if (!copy) {
      ok = false;
      break;
    }
    next->values[copy->id] = r->previous.values[i->id];
  }
  if (!ok) {
    map_clear(&next->keys);
    return false;
  }
  struct generation retired = r->previous;
  r->previous = *next;
  r->current = retired;
  map_clear(&r->current.keys);
  return true;
}
size_t ranking_bytes(const struct ranking *r) {
  return sizeof(*r) + map_bytes(&r->previous.keys) + map_bytes(&r->current.keys) +
         (r->previous.capacity + r->current.capacity) * sizeof(struct rate_state) +
         r->rates_capacity * sizeof(*r->rates);
}
