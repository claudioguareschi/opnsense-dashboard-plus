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
#include <stdio.h>
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
  /* scratch: candidates of one selection (bounded heaps: general, and one
   * per security class S1-S3) */
  struct candidate_row *general, *reserved[4];
  size_t scratch;
};
struct candidate_row {
  uint32_t flow;
  double score;
  uint64_t order;
};

/* The closed feature vocabulary, by its request keyword. */
static const char *const FEATURE_KEYS[FEATURE_COUNT] = {
    "byte_rate", "packet_rate", "states", "new_state_rate", "blocked", "threat_list", "ids"};

bool profile_parse(const char *text, struct profile *p, const char **why) {
  memset(p, 0, sizeof(*p));
  bool seen[FEATURE_COUNT] = {0}, seen_activity = false, seen_floors = false;
  char token[96];
  const char *at = text;
  unsigned total = 0;
  for (;;) {
    while (*at == ' ') at++;
    if (!*at || *at == '\n') break;
    size_t length = strcspn(at, " \n");
    if (length >= sizeof(token)) return (*why = "PROFILE token"), false;
    memcpy(token, at, length);
    token[length] = 0;
    at += length;
    char *value = strchr(token, '=');
    if (!value) return (*why = "PROFILE token"), false;
    *value++ = 0;
    char extra;
    if (!strcmp(token, "activity")) {
      unsigned on;
      if (seen_activity || sscanf(value, "%u%c", &on, &extra) != 1 || on > 1)
        return (*why = "PROFILE activity"), false;
      p->activity = on;
      seen_activity = true;
      continue;
    }
    if (!strcmp(token, "floors")) {
      unsigned s3, s2, s1;
      if (seen_floors || sscanf(value, "%u,%u,%u%c", &s3, &s2, &s1, &extra) != 3)
        return (*why = "PROFILE floors"), false;
      p->floor[SECURITY_S3] = s3;
      p->floor[SECURITY_S2] = s2;
      p->floor[SECURITY_S1] = s1;
      total = s3 + s2 + s1;
      seen_floors = true;
      continue;
    }
    int feature = -1;
    for (int k = 0; k < FEATURE_COUNT; k++)
      if (!strcmp(token, FEATURE_KEYS[k])) feature = k;
    if (feature < 0) return (*why = "PROFILE unknown feature"), false;
    double weight, scale;
    if (seen[feature] || sscanf(value, "%lf/%lf%c", &weight, &scale, &extra) != 2 ||
        !isfinite(weight) || weight < 0 || weight > 1000 || !isfinite(scale) || scale <= 0)
      return (*why = "PROFILE feature weight"), false;
    p->weight[feature] = weight;
    p->scale[feature] = scale;
    seen[feature] = true;
  }
  if (total > 150) return (*why = "PROFILE floors over the selection size"), false;
  for (int k = 0; k < FEATURE_COUNT; k++)
    if (!seen[k]) p->scale[k] = 1; /* weight 0: never contributes */
  return true;
}

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
  for (int c = SECURITY_S1; c <= SECURITY_S3; c++) fm_free(p->reserved[c]);
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

static double feature_value(const struct flow *f, const struct flow_rates *rates,
                            enum profile_feature feature, double interval) {
  switch (feature) {
  case FEATURE_BYTE_RATE: return rates->rate_from_remote + rates->rate_to_remote;
  case FEATURE_PACKET_RATE: return rates->packet_rate;
  case FEATURE_STATES: return (double)f->states;
  case FEATURE_NEW_STATE_RATE: return interval > 0 ? (double)f->created / interval : 0;
  case FEATURE_BLOCKED: return (double)f->evidence.blocked_hits;
  case FEATURE_THREAT_LIST: return f->evidence.mask & EVIDENCE_THREAT_LIST ? 1 : 0;
  case FEATURE_IDS:
    return f->evidence.mask & EVIDENCE_IDS_HIGH ? 2 : f->evidence.mask & EVIDENCE_IDS ? 1 : 0;
  default: return 0;
  }
}
double profiles_value(const struct aggregate *a, const struct ranking *r, size_t flow,
                      enum profile_feature feature, double interval) {
  const struct flow *f = aggregate_flow(a, flow);
  struct flow_rates rates;
  if (!f || !ranking_rates(r, flow, &rates)) return 0;
  return feature_value(f, &rates, feature, interval);
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
  size_t flows = aggregate_counts(a).flows, general = 0, reserved[4] = {0};
  for (size_t f = 0; f < flows; f++) {
    const struct flow *flow = aggregate_flow(a, f);
    struct flow_rates rates;
    if (!ranking_rates(r, f, &rates)) continue;
    double score = 0;
    for (int k = 0; k < FEATURE_COUNT; k++)
      if (def->weight[k] > 0)
        score += def->weight[k] * log1p(feature_value(flow, &rates, k, interval) / def->scale[k]);
    if (def->activity) score *= rates.activity;
    if (!(score > 0)) continue;
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote);
    if (map_find(&p->previous[n], key, sizeof(key))) score *= PROFILE_INCUMBENCY;
    struct candidate_row row = {(uint32_t)f, score, rates.order};
    /* a flow counts for its own class's floor only (no flow takes two
     * reserved places) and competes for the general places as well */
    enum security_class class = security_class(&flow->evidence);
    if (class != SECURITY_S0)
      heap_offer(p->reserved[class], &reserved[class], def->floor[class], &row);
    heap_offer(p->general, &general, limit, &row);
  }
  if (!reserve_rows(&p->selection[n], &p->capacity[n], limit, error)) return false;
  /* the floors' flows (S3, S2, S1: disjoint), then the best others until
   * the limit; places a floor did not use stay in the general pool */
  size_t count = 0;
  for (int c = SECURITY_S3; c >= SECURITY_S1; c--)
    for (size_t k = 0; k < reserved[c] && count < limit; k++)
      p->selection[n][count++] = (struct selected){p->reserved[c][k].flow, p->reserved[c][k].score};
  size_t floors = count;
  qsort(p->general, general, sizeof(*p->general), best_first);
  for (size_t k = 0; k < general && count < limit; k++) {
    bool taken = false;
    for (size_t j = 0; j < floors && !taken; j++) taken = p->selection[n][j].flow == p->general[k].flow;
    if (!taken) p->selection[n][count++] = (struct selected){p->general[k].flow, p->general[k].score};
  }
  /* final order: by score, then first-seen */
  struct candidate_row *order = p->general;
  for (size_t k = 0; k < count; k++) {
    struct flow_rates rates;
    ranking_rates(r, p->selection[n][k].flow, &rates);
    order[k] = (struct candidate_row){p->selection[n][k].flow, p->selection[n][k].score, rates.order};
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
  /* the scratch holds the general heap and one floor heap per class (limit each) */
  if (p->scratch < limit) {
    void *general = fm_realloc(p->general, limit * sizeof(*p->general));
    if (!general) return fm_error_set(error, errno ? errno : ENOMEM, "profile scratch");
    p->general = general;
    for (int c = SECURITY_S1; c <= SECURITY_S3; c++) {
      void *reserved = fm_realloc(p->reserved[c], limit * sizeof(*p->reserved[c]));
      if (!reserved) return fm_error_set(error, errno ? errno : ENOMEM, "profile scratch");
      p->reserved[c] = reserved;
    }
    p->scratch = limit;
  }
  for (size_t n = 0; n < p->count; n++)
    if (!(p->defs[n].classic ? select_classic(p, n, r, limit, error)
                             : select_scored(p, n, a, r, interval, limit, error)))
      return false;
  return true;
}

size_t profiles_bytes(const struct profiles *p) {
  size_t bytes = sizeof(*p) + p->scratch * 4 * sizeof(*p->general);
  for (size_t n = 0; n < PROFILE_MAX; n++)
    bytes += p->capacity[n] * sizeof(*p->selection[n]) + map_bytes(&p->previous[n]);
  return bytes;
}
