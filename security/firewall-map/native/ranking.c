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
#include "index.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct rate_state {
  double in, out, packets, last_active;
  uint64_t order;
  bool active;
};
struct rank_row {
  size_t flow;
  uint64_t order;
  double in, out, packets, activity, score;
};
struct ranking {
  struct map previous, current;
  struct rate_state *previous_values, *current_values;
  size_t previous_capacity, current_capacity;
  struct rank_row *rows;
  size_t rows_capacity, count, total, limit;
  uint64_t next_order;
  double fade, smoothing, sampled_at;
};

static size_t key_for(unsigned char key[34], const struct flow *flow) {
  state_flow_key(key, flow->local, flow->remote);
  return 34;
}

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
  void *p = realloc(*data, next * size);
  if (!p)
    return fm_error_set(error, errno, "ranking allocation");
  *data = p;
  *capacity = next;
  return true;
}

struct ranking *ranking_create(size_t limit, double fade, double smoothing,
                               struct fm_error *error) {
  if (!limit || fade <= 0 || smoothing < 0 || smoothing > 1) {
    fm_error_set(error, EINVAL, "ranking options");
    return NULL;
  }
  struct ranking *r = calloc(1, sizeof(*r));
  if (!r)
    fm_error_set(error, errno, "ranking allocation");
  else {
    r->limit = limit;
    r->fade = fade;
    r->smoothing = smoothing;
  }
  return r;
}

void ranking_destroy(struct ranking *r) {
  if (!r) return;
  map_clear(&r->previous);
  map_clear(&r->current);
  free(r->previous_values);
  free(r->current_values);
  free(r->rows);
  free(r);
}

void ranking_reset(struct ranking *r) {
  if (!r) return;
  map_clear(&r->previous);
  free(r->previous_values);
  r->previous_values = NULL;
  r->previous_capacity = 0;
  r->count = r->total = 0;
  r->next_order = 0;
}

static bool before(const struct rank_row *a, const struct rank_row *b) {
  return a->score > b->score || (a->score == b->score && a->order < b->order);
}

static bool sort_rows(struct rank_row *rows, size_t count, struct fm_error *error) {
  if (count < 2) return true;
  if (count > SIZE_MAX / sizeof(*rows))
    return fm_error_set(error, EOVERFLOW, "ranking sort size");
  struct rank_row *scratch = malloc(count * sizeof(*rows));
  if (!scratch)
    return fm_error_set(error, errno, "ranking sort allocation");
  for (size_t width = 1; width < count; width *= 2) {
    for (size_t start = 0; start < count; start += width * 2) {
      size_t middle = start + width < count ? start + width : count;
      size_t end = middle + width < count ? middle + width : count;
      size_t left = start, right = middle, out = start;
      while (left < middle && right < end)
        scratch[out++] = before(&rows[left], &rows[right]) ? rows[left++] : rows[right++];
      while (left < middle) scratch[out++] = rows[left++];
      while (right < end) scratch[out++] = rows[right++];
    }
    memcpy(rows, scratch, count * sizeof(*rows));
    if (width > SIZE_MAX / 2) break;
  }
  free(scratch);
  return true;
}

bool ranking_update(struct ranking *r, const struct aggregate *aggregate,
                    double now, double elapsed, struct fm_error *error) {
  map_clear(&r->current);
  r->total = aggregate_counts(aggregate).flows;
  if (!reserve((void **)&r->current_values, &r->current_capacity, r->total,
               sizeof(*r->current_values), error) ||
      !reserve((void **)&r->rows, &r->rows_capacity, r->total, sizeof(*r->rows), error))
    return false;
  size_t count = 0;
  for (size_t n = 0; n < r->total; n++) {
    const struct flow *flow = aggregate_flow(aggregate, n);
    unsigned char key[34];
    struct item *current = lookup(&r->current, key, key_for(key, flow), true, error);
    if (!current) return false;
    struct item *previous = lookup(&r->previous, key, 34, false, NULL);
    struct rate_state old = {0};
    if (previous && previous->value < r->previous_capacity)
      old = r->previous_values[previous->value];
    if (!old.active && old.order == 0 && (!previous || previous->value >= r->previous_capacity)) {
      if (r->next_order == UINT64_MAX)
        return fm_error_set(error, EOVERFLOW, "ranking insertion order");
      old.order = r->next_order++;
    }
    struct rate_state next = {
      .in = r->smoothing * (elapsed > 0 ? flow->delta.toward / elapsed : 0.0) +
            (1.0 - r->smoothing) * old.in,
      .out = r->smoothing * (elapsed > 0 ? flow->delta.away / elapsed : 0.0) +
             (1.0 - r->smoothing) * old.out,
      .packets = r->smoothing * (elapsed > 0 ? flow->delta.packets / elapsed : 0.0) +
                 (1.0 - r->smoothing) * old.packets,
      .order = old.order,
      .last_active = old.last_active,
      .active = old.active
    };
    if (flow->delta.toward || flow->delta.away) {
      next.last_active = now;
      next.active = true;
    }
    r->current_values[current->value] = next;
    double activity = next.active ? 1.0 - (now - next.last_active) / r->fade : 0.0;
    if (activity < 0) activity = 0;
    double rate = next.in + next.out;
    double score = (rate > 1.0 ? rate : 1.0) * activity;
    if (activity > 0)
      r->rows[count++] = (struct rank_row){n, next.order, next.in, next.out, next.packets,
                                           activity, score};
  }
  /* Stable descending score order: persistent flow insertion order breaks ties. */
  if (!sort_rows(r->rows, count, error)) return false;
  r->count = count < r->limit ? count : r->limit;
  r->sampled_at = now;
  map_clear(&r->previous);
  r->previous = r->current;
  memset(&r->current, 0, sizeof(r->current));
  r->previous_values = r->current_values;
  r->previous_capacity = r->current_capacity;
  r->current_values = NULL;
  r->current_capacity = 0;
  return true;
}

size_t ranking_count(const struct ranking *r) { return r->count; }
size_t ranking_total(const struct ranking *r) { return r->total; }
bool ranking_at(const struct ranking *r, size_t n, struct ranked_flow *out) {
  if (n >= r->count) return false;
  const struct rank_row *row = &r->rows[n];
  *out = (struct ranked_flow){row->flow, row->in, row->out, row->packets,
                              row->activity, row->score};
  return true;
}

bool ranking_snapshot_at(const struct ranking *r, const struct aggregate *a,
                         size_t n, struct ranked_flow *out, uint64_t *order) {
  const struct flow *flow = aggregate_flow(a, n);
  if (!flow) return false;
  unsigned char key[34];
  state_flow_key(key, flow->local, flow->remote);
  struct item *i = lookup((struct map *)&r->previous, key, sizeof(key), false, NULL);
  if (!i || i->value >= r->previous_capacity) return false;
  const struct rate_state *v = &r->previous_values[i->value];
  double activity = v->active ? 1.0 - (r->sampled_at - v->last_active) / r->fade : 0.0;
  if (activity < 0) activity = 0;
  double rate = v->in + v->out;
  *out = (struct ranked_flow){n, v->in, v->out, v->packets, activity,
                             (rate > 1 ? rate : 1) * activity};
  *order = v->order;
  return true;
}
