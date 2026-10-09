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


#include "tracker.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct tracker {
  enum track_regime regime;
  double fade, smoothing, warming_until;
  struct budget_limits limits;
  size_t limit, hard_limit, forced_limit, exit_threshold;
  /* flow keys for this sample (promoted, pinned) and their successors being
   * built for the next one; presence only (item fields unused) */
  struct map promoted, pinned;
  struct discovery discovery;
  struct summary_entry *top;
  /* scratch: promotion candidates (untracked flows from the discovery
   * summaries; not aggregate.c's attribution candidates), and the tracked
   * flows by effective score */
  struct promotion *promotions;
  struct scored *scored;
  size_t scored_capacity;
};
struct promotion {
  unsigned char key[FM_FLOW_KEY_SIZE];
  double estimate;
};
struct scored {
  uint32_t flow;
  double score;
  uint64_t order;
};
#define TRACK_CANDIDATES (TRACK_PROMOTE_MAX + 2 * TRACK_PROMOTE_STATES_MAX)

struct tracker *tracker_create(double fade, double smoothing, struct fm_error *error) {
  struct tracker *t = fm_calloc(1, sizeof(*t));
  if (!t) {
    fm_error_set(error, errno, "tracker allocation");
    return NULL;
  }
  t->fade = fade;
  t->smoothing = smoothing;
  t->top = fm_calloc(TRACK_PROMOTE_MAX, sizeof(*t->top));
  t->promotions = t->top ? fm_calloc(TRACK_CANDIDATES, sizeof(*t->promotions)) : NULL;
  if (!t->promotions || !discovery_init(&t->discovery, error)) {
    if (!t->promotions) fm_error_set(error, ENOMEM, "tracker allocation");
    tracker_destroy(t);
    return NULL;
  }
  return t;
}
void tracker_destroy(struct tracker *t) {
  if (!t) return;
  map_clear(&t->promoted);
  map_clear(&t->pinned);
  discovery_destroy(&t->discovery);
  fm_free(t->top);
  fm_free(t->promotions);
  fm_free(t->scored);
  fm_free(t);
}
void tracker_reset(struct tracker *t) {
  map_clear(&t->promoted);
  map_clear(&t->pinned);
  t->regime = TRACK_EXACT;
  t->warming_until = 0;
}

bool tracker_begin(struct tracker *t, struct ranking *ranking, struct budget_limits limits,
                   struct admission *admission, struct fm_error *error) {
  t->limits = limits;
  t->limit = (size_t)limits.tracked;
  t->forced_limit = t->limit / 4 < TRACK_FORCED_MAX ? t->limit / 4 : TRACK_FORCED_MAX;
  t->hard_limit = t->limit + t->forced_limit;
  t->exit_threshold = t->limit / 4 * 3;
  /* bounded: T carries over what the previous sample retained (pinned and
   * the best others, leaving room for its promotions) */
  if (t->regime == TRACK_BOUNDED && !ranking_retain(ranking, &t->pinned, error))
    return false;
  discovery_reset(&t->discovery);
  *admission = (struct admission){
      .regime = t->regime, .limit = t->limit, .hard_limit = t->hard_limit,
      .forced_limit = t->forced_limit, .candidate_limit = (size_t)limits.candidates,
      .join_limit = (size_t)limits.joins, .known = ranking_keys(ranking),
      .promoted = &t->promoted, .discovery = &t->discovery};
  return true;
}

static bool promote(struct tracker *t, const unsigned char *key, struct fm_error *error) {
  return map_insert(&t->promoted, key, FM_FLOW_KEY_SIZE, error) != NULL;
}
static int better_scored(const void *left, const void *right) {
  const struct scored *a = left, *b = right;
  if (a->score != b->score) return a->score > b->score ? -1 : 1;
  return a->order < b->order ? -1 : a->order > b->order;
}
static int better_promotion(const void *left, const void *right) {
  const struct promotion *a = left, *b = right;
  if (a->estimate != b->estimate) return a->estimate > b->estimate ? -1 : 1;
  return memcmp(a->key, b->key, FM_FLOW_KEY_SIZE);
}
/* The raw total of a key in a summary (count over its unit) and its unit. */
static double raw_count(const struct summary *s, const unsigned char *key, uint64_t hash, uint64_t *unit) {
  const struct summary_entry *e = summary_find(s, key, hash);
  if (!e) return 0;
  if (e->unit > *unit) *unit = e->unit;
  return (double)e->count / (double)(e->unit ? e->unit : 1);
}
/* Promotion candidates: the tops of the three summaries (asset-weighted),
 * each estimated by the effective score the active profile would give it
 * after one tracked sample. Returns how many, best first. */
static size_t promotion_candidates(struct tracker *t, const struct profile *def, double interval) {
  const struct discovery *d = &t->discovery;
  struct {
    const struct summary *summary;
    size_t limit;
  } bands[] = {{d->bytes, TRACK_PROMOTE_MAX},
               {d->states, TRACK_PROMOTE_STATES_MAX},
               {d->created, TRACK_PROMOTE_STATES_MAX}};
  size_t count = 0;
  double per_second = interval > 0 ? 1.0 / interval : 0.0;
  for (size_t b = 0; b < sizeof(bands) / sizeof(*bands); b++) {
    size_t top = summary_top(bands[b].summary, t->top, bands[b].limit);
    for (size_t n = 0; n < top; n++) {
      const unsigned char *key = t->top[n].key;
      bool seen = false;
      for (size_t k = 0; k < count && !seen; k++) seen = !memcmp(t->promotions[k].key, key, FM_FLOW_KEY_SIZE);
      if (seen) continue;
      uint64_t hash = index_hash(key, FM_FLOW_KEY_SIZE), unit = 0;
      double bytes = raw_count(d->bytes, key, hash, &unit), states = raw_count(d->states, key, hash, &unit),
             created = raw_count(d->created, key, hash, &unit);
      double values[FEATURE_COUNT] = {0};
      values[FEATURE_BYTE_RATE] = t->smoothing * bytes * per_second;
      values[FEATURE_ACTIVE_STATES] = states;
      values[FEATURE_NEW_STATE_RATE] = created * per_second;
      values[FEATURE_FLOW_VOLUME] = bytes;
      memcpy(t->promotions[count].key, key, FM_FLOW_KEY_SIZE);
      t->promotions[count++].estimate = profile_estimate(def, values, profile_unit_multiplier(def, unit));
    }
  }
  qsort(t->promotions, count, sizeof(*t->promotions), better_promotion);
  return count;
}
static bool pin(struct tracker *t, const struct flow *f, struct fm_error *error) {
  unsigned char key[FM_FLOW_KEY_SIZE];
  state_flow_key(key, f->local, f->remote);
  return map_insert(&t->pinned, key, sizeof(key), error) != NULL;
}

bool tracker_finish(struct tracker *t, const struct aggregate *a, const struct ranking *ranking,
                    double now, double interval, const struct track_hints *hints,
                    struct tracker_report *report, struct fm_error *error) {
  struct aggregate_counts counts = aggregate_counts(a);
  const struct discovery *d = &t->discovery;
  bool all_tracked = !counts.untracked_states;
  bool summaries_exact = !summary_evictions(d->bytes) && !summary_evictions(d->states) &&
                         !summary_evictions(d->created);
  uint64_t untracked = all_tracked ? 0
                       : summaries_exact ? summary_count(d->states)
                                         : cardinality_estimate(&d->flows);
  bool bounded = t->regime == TRACK_BOUNDED || counts.exhausted;
  *report = (struct tracker_report){
      .regime = bounded ? TRACK_BOUNDED : TRACK_EXACT,
      .discovery = all_tracked || summaries_exact ? DISCOVERY_EXACT : DISCOVERY_BOUNDED,
      .ranking = bounded ? RANKING_BOUNDED : now < t->warming_until ? RANKING_WARMING : RANKING_EXACT,
      .attribution = counts.candidate_evictions || counts.join_refused || counts.forced_refused
                         ? ATTRIBUTION_PARTIAL : ATTRIBUTION_EXACT,
      .discovery_error = summary_floor(d->bytes),
      .flows = counts.flows + untracked,
      .flows_estimated = !all_tracked && !summaries_exact,
      .tracked = counts.flows, .limit = t->limit, .exit_threshold = t->exit_threshold,
      .forced_limit = t->forced_limit, .candidate_limit = t->limits.candidates,
      .join_limit = t->limits.joins};
  /* the next regime */
  enum track_regime next = t->regime;
  if (t->regime == TRACK_EXACT && counts.exhausted)
    next = TRACK_BOUNDED;
  else if (t->regime == TRACK_BOUNDED && report->flows < t->exit_threshold) {
    next = TRACK_EXACT;
    /* flows untracked until now have no rate history: one fade window */
    t->warming_until = now + t->fade;
  }
  report->next_regime = next;
  map_clear(&t->pinned);
  map_clear(&t->promoted);
  if (next == TRACK_BOUNDED) {
    /* the selected flows stay tracked (seats of the ordinary limit), and
     * flagged flows (up to the forced cap: their own reservation) */
    for (size_t n = 0; n < hints->selected_count; n++)
      if (!pin(t, aggregate_flow(a, hints->selected[n].flow), error)) return false;
    size_t selected_seats = t->pinned.used;
    size_t flagged = 0;
    for (size_t n = 0; n < counts.flows && flagged < t->forced_limit; n++) {
      const struct flow *f = aggregate_flow(a, n);
      if (!f->evidence.mask) continue;
      flagged++;
      if (!pin(t, f, error)) return false;
    }
    /* the tracked flows by effective score (then first-seen) */
    if (counts.flows > t->scored_capacity) {
      void *grown = fm_realloc(t->scored, counts.flows * sizeof(*t->scored));
      if (!grown) return fm_error_set(error, errno ? errno : ENOMEM, "tracker scores");
      t->scored = grown;
      t->scored_capacity = counts.flows;
    }
    for (size_t n = 0; n < counts.flows; n++) {
      struct flow_rates rates = {0};
      ranking_rates(ranking, n, &rates);
      t->scored[n] = (struct scored){(uint32_t)n, ranker_score(hints->ranker, n), rates.order};
    }
    qsort(t->scored, counts.flows, sizeof(*t->scored), better_scored);
    /* promotions: the best untracked candidates, each displacing the
     * incumbent at T's edge only by the incumbency margin */
    size_t offered = promotion_candidates(t, ranker_profile(hints->ranker), interval);
    size_t seats = t->limit;
    for (size_t n = 0; n < offered && t->promoted.used < TRACK_PROMOTE_MAX; n++) {
      if (t->promoted.used >= seats) break;
      size_t edge = seats - t->promoted.used - 1; /* the incumbent this would push out */
      double incumbent = edge < counts.flows ? t->scored[edge].score : 0;
      if (incumbent > 0 && !(t->promotions[n].estimate > incumbent * TRACK_INCUMBENCY_MARGIN)) break;
      if (!(t->promotions[n].estimate > 0)) break;
      if (!promote(t, t->promotions[n].key, error)) return false;
    }
    /* retention: the best others, in the seats the selection and the
     * promotions leave (tracked_limit is the ordinary set's limit; flagged
     * flows come on top of it, up to the hard limit) */
    size_t taken = selected_seats + t->promoted.used;
    size_t room = t->limit > taken ? t->limit - taken : 0, kept = 0;
    for (size_t n = 0; n < counts.flows && kept < room; n++) {
      const struct flow *f = aggregate_flow(a, t->scored[n].flow);
      unsigned char key[FM_FLOW_KEY_SIZE];
      state_flow_key(key, f->local, f->remote);
      if (map_find(&t->pinned, key, sizeof(key))) continue;
      if (!map_insert(&t->pinned, key, sizeof(key), error)) return false;
      kept++;
    }
  }
  report->promoted = t->promoted.used;
  t->regime = next;
  return true;
}

size_t tracker_bytes(const struct tracker *t) {
  return sizeof(*t) + map_bytes(&t->promoted) + map_bytes(&t->pinned) +
         discovery_bytes(&t->discovery) + TRACK_PROMOTE_MAX * sizeof(*t->top) +
         TRACK_CANDIDATES * sizeof(*t->promotions) + t->scored_capacity * sizeof(*t->scored);
}
