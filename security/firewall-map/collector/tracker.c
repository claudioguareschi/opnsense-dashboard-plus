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
   * built for the next one */
  struct map promoted, pinned;
  struct discovery discovery;
  struct summary_entry *top;
};

struct tracker *tracker_create(double fade, double smoothing, struct fm_error *error) {
  struct tracker *t = fm_calloc(1, sizeof(*t));
  if (!t) {
    fm_error_set(error, errno, "tracker allocation");
    return NULL;
  }
  t->fade = fade;
  t->smoothing = smoothing;
  t->top = fm_calloc(TRACK_PROMOTE_MAX, sizeof(*t->top));
  if (!t->top || !discovery_init(&t->discovery, error)) {
    if (!t->top) fm_error_set(error, ENOMEM, "tracker allocation");
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
  /* bounded: what T carries over is the pinned flows and the best of the
   * rest, leaving room for this sample's promotions */
  if (t->regime == TRACK_BOUNDED) {
    size_t room = t->limit > t->promoted.used ? t->limit - t->promoted.used : 0;
    if (!ranking_trim(ranking, room, &t->pinned, error))
      return false;
  }
  discovery_reset(&t->discovery);
  *admission = (struct admission){
      .regime = t->regime, .limit = t->limit, .hard_limit = t->hard_limit,
      .forced_limit = t->forced_limit, .candidate_limit = (size_t)limits.candidates,
      .join_limit = (size_t)limits.joins, .known = ranking_keys(ranking),
      .promoted = &t->promoted, .discovery = &t->discovery};
  return true;
}

static bool promote(struct tracker *t, const unsigned char *key, struct fm_error *error) {
  return lookup(&t->promoted, key, FM_FLOW_KEY_SIZE, true, error) != NULL;
}
/* A state band: the untracked flows with the most states (or new states)
 * that beat the active profile's edge by the margin. */
static bool promote_band(struct tracker *t, const struct summary *band, double per_unit, double edge,
                         struct fm_error *error) {
  size_t candidates = summary_top(band, t->top, TRACK_PROMOTE_STATES_MAX);
  for (size_t n = 0; n < candidates; n++) {
    if (!((double)t->top[n].count * per_unit > edge * TRACK_INCUMBENCY_MARGIN)) break;
    if (!promote(t, t->top[n].key, error)) return false;
  }
  return true;
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
    /* the ranked flows stay tracked, and flagged flows (up to the forced
     * cap) */
    for (size_t n = 0; hints && n < hints->selected_count; n++) {
      const struct flow *f = aggregate_flow(a, hints->selected[n].flow);
      unsigned char key[FM_FLOW_KEY_SIZE];
      state_flow_key(key, f->local, f->remote);
      if (!lookup(&t->pinned, key, sizeof(key), true, error)) return false;
    }
    size_t flagged = 0;
    for (size_t n = 0; n < counts.flows && flagged < t->forced_limit; n++) {
      const struct flow *f = aggregate_flow(a, n);
      if (!f->evidence.mask) continue;
      flagged++;
      unsigned char key[FM_FLOW_KEY_SIZE];
      state_flow_key(key, f->local, f->remote);
      if (!lookup(&t->pinned, key, sizeof(key), true, error)) return false;
    }
    /* promotions: the heaviest untracked flows by byte rate, each displacing
     * the incumbent at T's edge only by the incumbency margin */
    size_t candidates = summary_top(d->bytes, t->top, TRACK_PROMOTE_MAX);
    size_t active = ranking_active(ranking), seats = t->limit;
    double per_second = interval > 0 ? 1.0 / interval : 0.0;
    for (size_t n = 0; n < candidates && t->promoted.used < TRACK_PROMOTE_MAX; n++) {
      size_t edge = seats - t->promoted.used - 1; /* the incumbent this would push out */
      if (t->promoted.used >= seats) break;
      /* the score it would have after one tracked sample, against the
       * incumbents' smoothed scores */
      double rate = t->smoothing * (double)t->top[n].count * per_second;
      if (edge < active && !(rate > ranking_score_at(ranking, edge) * TRACK_INCUMBENCY_MARGIN))
        break;
      if (!promote(t, t->top[n].key, error)) return false;
    }
    if (hints && hints->states && !promote_band(t, d->states, 1.0, hints->states_edge, error))
      return false;
    if (hints && hints->created && interval > 0 &&
        !promote_band(t, d->created, 1.0 / interval, hints->created_edge, error))
      return false;
  }
  report->promoted = t->promoted.used;
  t->regime = next;
  return true;
}

size_t tracker_bytes(const struct tracker *t) {
  return sizeof(*t) + map_bytes(&t->promoted) + map_bytes(&t->pinned) +
         discovery_bytes(&t->discovery) + TRACK_PROMOTE_MAX * sizeof(*t->top);
}
