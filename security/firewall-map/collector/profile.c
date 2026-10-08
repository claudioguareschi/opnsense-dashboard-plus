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


#include "profile.h"
#include "alloc.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

struct profiles {
  struct profile defs[PROFILE_MAX];
  size_t count;
  /* per profile: this sample's selection and the flow keys of the previous
   * one (incumbency), at most `limit` each */
  struct selected *selection[PROFILE_MAX];
  size_t selected[PROFILE_MAX], capacity[PROFILE_MAX];
  struct map previous[PROFILE_MAX];
  /* scratch: candidates of one selection (two bounded heaps) */
  struct candidate_row *general, *reserved;
  size_t scratch;
};
struct candidate_row {
  uint32_t flow;
  double score;
  uint64_t order;
  bool flagged;
};

struct profiles *profiles_create(struct fm_error *error) {
  struct profiles *p = fm_calloc(1, sizeof(*p));
  if (!p) fm_error_set(error, errno, "profiles allocation");
  return p;
}
void profiles_reset(struct profiles *p) {
  for (size_t n = 0; n < PROFILE_MAX; n++) {
    map_clear(&p->previous[n]);
    p->selected[n] = 0;
  }
}
void profiles_destroy(struct profiles *p) {
  if (!p) return;
  profiles_reset(p);
  for (size_t n = 0; n < PROFILE_MAX; n++) fm_free(p->selection[n]);
  fm_free(p->general);
  fm_free(p->reserved);
  fm_free(p);
}
bool profiles_configure(struct profiles *p, const struct profile *defs, size_t count,
                        struct fm_error *error) {
  if (count > PROFILE_MAX)
    return fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "profile count");
  if (count != p->count || memcmp(defs, p->defs, count * sizeof(*defs)))
    profiles_reset(p);
  memset(p->defs, 0, sizeof(p->defs));
  memcpy(p->defs, defs, count * sizeof(*defs));
  p->count = count;
  return true;
}
size_t profiles_count(const struct profiles *p) { return p->count; }
const struct profile *profiles_at(const struct profiles *p, size_t n) {
  return n < p->count ? &p->defs[n] : NULL;
}
size_t profiles_selection(const struct profiles *p, size_t n, const struct selected **out) {
  *out = n < p->count ? p->selection[n] : NULL;
  return n < p->count ? p->selected[n] : 0;
}

double profiles_value(const struct aggregate *a, const struct ranking *r, size_t flow,
                      enum profile_primitive primitive, double interval) {
  const struct flow *f = aggregate_flow(a, flow);
  struct flow_rates rates;
  if (!f || !ranking_rates(r, flow, &rates)) return 0;
  switch (primitive) {
  case PRIMITIVE_BYTES: return rates.rate_from_remote + rates.rate_to_remote;
  case PRIMITIVE_PACKETS: return rates.packet_rate;
  case PRIMITIVE_STATES: return (double)f->states;
  case PRIMITIVE_CREATED: return interval > 0 ? (double)f->created / interval : 0;
  default: return 0;
  }
}

/* Better first: higher score, then earlier first-seen. */
static bool better(const struct candidate_row *x, const struct candidate_row *y) {
  return x->score > y->score || (x->score == y->score && x->order < y->order);
}
/* A bounded min-heap (worst at the root) keeping the `limit` best rows. */
static void heap_offer(struct candidate_row *heap, size_t *used, size_t limit,
                       const struct candidate_row *row) {
  if (!limit) return;
  size_t n;
  if (*used < limit) {
    n = (*used)++;
    while (n) {
      size_t parent = (n - 1) / 2;
      if (!better(&heap[parent], row)) break;
      heap[n] = heap[parent];
      n = parent;
    }
    heap[n] = *row;
    return;
  }
  if (!better(row, &heap[0])) return;
  n = 0;
  for (;;) {
    size_t child = 2 * n + 1;
    if (child >= *used) break;
    if (child + 1 < *used && better(&heap[child], &heap[child + 1])) child++;
    if (!better(row, &heap[child])) break;
    heap[n] = heap[child];
    n = child;
  }
  heap[n] = *row;
}
static int best_first(const void *left, const void *right) {
  const struct candidate_row *a = left, *b = right;
  return better(a, b) ? -1 : better(b, a) ? 1 : 0;
}
static bool reserve_rows(struct selected **rows, size_t *capacity, size_t needed,
                         struct fm_error *error) {
  if (needed <= *capacity) return true;
  void *grown = fm_realloc(*rows, needed * sizeof(**rows));
  if (!grown) return fm_error_set(error, errno, "profile selection");
  *rows = grown;
  *capacity = needed;
  return true;
}

static bool select_classic(struct profiles *p, size_t n, const struct ranking *r, size_t limit,
                           struct fm_error *error) {
  size_t count = ranking_count(r) < limit ? ranking_count(r) : limit;
  if (!reserve_rows(&p->selection[n], &p->capacity[n], count, error)) return false;
  for (size_t k = 0; k < count; k++) {
    struct ranked_flow row;
    ranking_at(r, k, &row);
    p->selection[n][k] = (struct selected){(uint32_t)row.flow, row.score};
  }
  p->selected[n] = count;
  return true;
}

static bool select_scored(struct profiles *p, size_t n, const struct aggregate *a,
                          const struct ranking *r, double interval, size_t limit,
                          struct fm_error *error) {
  const struct profile *def = &p->defs[n];
  size_t floor = def->floor < limit ? def->floor : limit;
  size_t flows = aggregate_counts(a).flows, general = 0, reserved = 0;
  for (size_t f = 0; f < flows; f++) {
    const struct flow *flow = aggregate_flow(a, f);
    struct flow_rates rates;
    if (!ranking_rates(r, f, &rates)) continue;
    double score = flow->flagged ? def->flagged : 0;
    for (int k = 0; k < PRIMITIVE_COUNT; k++)
      if (def->weight[k] > 0 && def->scale[k] > 0)
        score += def->weight[k] * log1p(profiles_value(a, r, f, k, interval) / def->scale[k]);
    if (def->activity) score *= rates.activity;
    if (!(score > 0)) continue;
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote);
    if (map_find(&p->previous[n], key, sizeof(key))) score *= PROFILE_INCUMBENCY;
    struct candidate_row row = {(uint32_t)f, score, rates.order, flow->flagged};
    /* the floor's candidates are kept apart, so a general slot never takes
     * a flow the floor needs */
    if (row.flagged) heap_offer(p->reserved, &reserved, floor, &row);
    heap_offer(p->general, &general, limit, &row);
  }
  /* the floor's flows, then the best others until the limit */
  qsort(p->reserved, reserved, sizeof(*p->reserved), best_first);
  qsort(p->general, general, sizeof(*p->general), best_first);
  if (!reserve_rows(&p->selection[n], &p->capacity[n], limit, error)) return false;
  size_t count = 0;
  for (size_t k = 0; k < reserved; k++)
    p->selection[n][count++] = (struct selected){p->reserved[k].flow, p->reserved[k].score};
  for (size_t k = 0; k < general && count < limit; k++) {
    bool taken = false;
    for (size_t j = 0; j < reserved && !taken; j++) taken = p->reserved[j].flow == p->general[k].flow;
    if (!taken) p->selection[n][count++] = (struct selected){p->general[k].flow, p->general[k].score};
  }
  /* final order: by score, then first-seen */
  struct candidate_row *order = p->general;
  for (size_t k = 0; k < count; k++) {
    struct flow_rates rates;
    ranking_rates(r, p->selection[n][k].flow, &rates);
    order[k] = (struct candidate_row){p->selection[n][k].flow, p->selection[n][k].score, rates.order, false};
  }
  qsort(order, count, sizeof(*order), best_first);
  for (size_t k = 0; k < count; k++) p->selection[n][k] = (struct selected){order[k].flow, order[k].score};
  p->selected[n] = count;
  /* incumbency for the next sample */
  map_clear(&p->previous[n]);
  for (size_t k = 0; k < count; k++) {
    const struct flow *flow = aggregate_flow(a, p->selection[n][k].flow);
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote);
    if (!lookup(&p->previous[n], key, sizeof(key), true, error)) return false;
  }
  return true;
}

bool profiles_select(struct profiles *p, const struct aggregate *a, const struct ranking *r,
                     double interval, size_t limit, struct fm_error *error) {
  /* the scratch holds the general heap (limit) and the floor heap (limit) */
  if (p->scratch < limit) {
    void *general = fm_realloc(p->general, limit * sizeof(*p->general));
    if (general) p->general = general;
    void *reserved = general ? fm_realloc(p->reserved, limit * sizeof(*p->reserved)) : NULL;
    if (!reserved) return fm_error_set(error, errno ? errno : ENOMEM, "profile scratch");
    p->reserved = reserved;
    p->scratch = limit;
  }
  for (size_t n = 0; n < p->count; n++)
    if (!(p->defs[n].classic ? select_classic(p, n, r, limit, error)
                             : select_scored(p, n, a, r, interval, limit, error)))
      return false;
  return true;
}

size_t profiles_bytes(const struct profiles *p) {
  size_t bytes = sizeof(*p) + p->scratch * 2 * sizeof(*p->general);
  for (size_t n = 0; n < PROFILE_MAX; n++)
    bytes += p->capacity[n] * sizeof(*p->selection[n]) + map_bytes(&p->previous[n]);
  return bytes;
}
