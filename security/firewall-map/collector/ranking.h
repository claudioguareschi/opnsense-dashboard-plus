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

#ifndef FM_RANKING_H
#define FM_RANKING_H
#include "aggregate.h"
struct ranking;
struct ranked_flow {
  size_t flow;
  double rate_from_remote, rate_to_remote, packet_rate, activity, score;
};
struct ranking *ranking_create(size_t limit, double fade, double smoothing,
                               struct fm_error *);
void ranking_destroy(struct ranking *);
void ranking_reset(struct ranking *);
/* `now` is the sample's anchor on the same monotonic clock as history; an
 * `interval` below zero marks a baseline sample (no rates). On failure the
 * previous generation is untouched. */
bool ranking_update(struct ranking *, const struct aggregate *, double now,
                    double interval, struct fm_error *);
size_t ranking_count(const struct ranking *);
size_t ranking_total(const struct ranking *);
bool ranking_at(const struct ranking *, size_t, struct ranked_flow *);
/* Every active flow of the last update in rank order (ranking_count stops at
 * the limit): the tracked set's retention and incumbency use the full order. */
size_t ranking_active(const struct ranking *);
double ranking_score_at(const struct ranking *, size_t);
/* The flow keys with rate history (the tracked set carried to the next
 * sample), keyed as state_flow_key. */
const struct map *ranking_keys(const struct ranking *);
/* Keeps the history of the `pinned` keys and of the `keep` best others (by
 * score at the last update, then first-seen order), forgetting the rest. */
bool ranking_trim(struct ranking *, size_t keep, const struct map *pinned, struct fm_error *);
/* Snapshot-only rate/order view, including quiet flows for Python's IDS policy.
 * Uses existing history, without updating rates or re-ranking. */
bool ranking_snapshot_at(const struct ranking *, const struct aggregate *, size_t,
                         struct ranked_flow *, uint64_t *order);
size_t ranking_bytes(const struct ranking *);
/* The last update's rates of aggregate flow n, idle flows included, with its
 * first-seen order (the profile scores every tracked flow, not only active ones). */
struct flow_rates {
  double rate_from_remote, rate_to_remote, packet_rate, activity;
  uint64_t order;
};
bool ranking_rates(const struct ranking *, size_t flow, struct flow_rates *);
#endif
