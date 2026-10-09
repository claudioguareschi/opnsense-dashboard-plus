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


#ifndef FM_TRACKER_H
#define FM_TRACKER_H
#include "aggregate.h"
#include "budget.h"
#include "profile.h"
#include "ranking.h"

/* The tracked set T and its two regimes (CONTRACTS.md, "Tracked set").
 *
 * Ranking-exact: every flow is tracked, admitted during the pass, while T
 * stays under its limit; ranking and history are then exact. If the
 * limit is reached during a pass, that whole sample is bounded and the next
 * one starts in the bounded regime.
 *
 * Bounded: T keeps the selected flows, flagged flows (pinned) and the best
 * others by effective score (the active profile's, asset importance
 * included), and the discovery tier's
 * best untracked flows, promoted at the end of a sample for the next one: a
 * promotion displaces an incumbent only when its estimated effective score
 * beats the incumbent's by the incumbency margin. Discovery counts are
 * weighted by asset importance, so an important flow is not lost to heavier
 * unimportant ones before it can be compared. The
 * collector returns to the exact regime when the estimated flow count falls
 * below the exit threshold; history stays warming for one fade window.
 *
 * Quality (the three axes): discovery exact or bounded (with the error
 * floor), ranking/history exact, warming or bounded, attribution exact or
 * partial (a candidate summary evicted, the join or the forced cap ran out).
 * Attribution is never warming here: the LAN-companion join runs in both
 * regimes under its budget, so a newly tracked flow is complete at once. */
enum quality_discovery { DISCOVERY_EXACT = 0, DISCOVERY_BOUNDED = 1 };
enum quality_ranking { RANKING_EXACT = 0, RANKING_WARMING = 1, RANKING_BOUNDED = 2 };
enum quality_attribution { ATTRIBUTION_EXACT = 0, ATTRIBUTION_WARMING = 1, ATTRIBUTION_PARTIAL = 2 };
/* A promotion must beat the incumbent it displaces by this factor. */
#define TRACK_INCUMBENCY_MARGIN 1.25
/* Flows promoted per sample at most (candidates: the byte summary's top, and
 * a quarter of that from each state summary when a profile is active), and
 * flagged flows admitted beyond T. */
#define TRACK_PROMOTE_MAX 1024
#define TRACK_PROMOTE_STATES_MAX 256
#define TRACK_FORCED_MAX 4096

struct tracker_report {
  enum track_regime regime;      /* this sample's committed regime */
  enum track_regime next_regime; /* the next sample's */
  enum quality_discovery discovery;
  enum quality_ranking ranking;
  enum quality_attribution attribution;
  uint64_t discovery_error;      /* byte-delta floor of untracked flows (0 when exact) */
  uint64_t flows;                /* tracked + untracked flows */
  bool flows_estimated;          /* the untracked part is a HyperLogLog estimate */
  uint64_t tracked, limit, exit_threshold, forced_limit, candidate_limit, join_limit;
  uint64_t promoted;             /* flows promoted for the next sample */
};
struct tracker;
/* fade and smoothing: the ranking's (a promotion is compared by the score it
 * would have after one tracked sample) */
struct tracker *tracker_create(double fade, double smoothing, struct fm_error *);
void tracker_destroy(struct tracker *);
/* Forgets regime history (a refused or failed sample: the next is a baseline). */
void tracker_reset(struct tracker *);
/* Prepares one sample: sizes T from the budget limits, trims the ranking's
 * history to T in the bounded regime, resets discovery, and fills the
 * admission policy (evidence and threat mask are the caller's). */
bool tracker_begin(struct tracker *, struct ranking *, struct budget_limits, struct admission *,
                   struct fm_error *);
/* What the next sample's tracked set needs from this one's selection: the
 * flows selected (kept tracked), and the ranker, whose effective scores
 * order retention and promotion (and whose profile estimates candidates). */
struct track_hints {
  const struct ranked_flow *selected;
  size_t selected_count;
  const struct ranker *ranker;
};
/* After the sample's ranking update and profile selection: quality, regime
 * transition, pinned flows and promotions for the next sample. */
bool tracker_finish(struct tracker *, const struct aggregate *, const struct ranking *, double now,
                    double interval, const struct track_hints *, struct tracker_report *,
                    struct fm_error *);
size_t tracker_bytes(const struct tracker *);
#endif
