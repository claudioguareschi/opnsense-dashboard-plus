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

#ifndef FM_PROTOCOL_H
#define FM_PROTOCOL_H
#include "aggregate.h"
#include "event_correlation.h"
#include "profile.h"
#include "ranking.h"
#include "threat_summary.h"
#include <stdio.h>
/* Wire formats are specified in PROTOCOL.md. No C structure is serialized.
 * The collector speaks exactly one protocol: it is announced in the banner and
 * carried by every response header (FMAGG4, FMSTATE2). */
#define FM_PROTOCOL_VERSION 1
#define FM_FRAME_MAX 4096
enum record_kind {
  RECORD_HEADER = 0,
  RECORD_FLOW = 1,
  RECORD_CANDIDATE = 2,
  RECORD_THREAT_REMOTE = 3,
  RECORD_THREAT_CANDIDATE = 4,
  RECORD_EVENT_MATCH = 5,
  RECORD_TELEMETRY = 6,
  RECORD_CLASSIFIED = 7,
  RECORD_CLASS_SET = 8,
  RECORD_SNAPSHOT_CANDIDATE = 10,
  RECORD_FAILURE = 254,
  RECORD_FOOTER = 255,
};
enum sample_outcome_code {
  OUTCOME_SAMPLE = 0,
  OUTCOME_REFUSED_STATES = 1,
  OUTCOME_REFUSED_CONTEXT = 2,
  OUTCOME_REFUSED_MEMORY = 3,
};
struct sample_outcome {
  uint32_t code, context_kind;
  uint64_t actual, limit;
};
struct telemetry {
  uint32_t pid;
  uint64_t sequence;
  double interval, dump_seconds, processing_seconds, user_cpu, system_cpu;
  uint64_t max_rss, heap_bytes, heap_peak, heap_blocks, heap_budget, state_limit,
      preflight_states, skipped_af_translation, candidates_omitted,
      threat_remotes_omitted, threat_candidates_omitted, event_history_evicted,
      classifier_bytes, snapshot_candidates_omitted;
  /* the tracked set and the quality axes (tracker.h) */
  uint64_t regime, next_regime, quality_discovery, quality_ranking, quality_attribution,
      discovery_error, flows_total, flows_estimated, tracked_flows, tracked_limit,
      exit_threshold, forced_limit, forced_flows, forced_refused, candidate_limit,
      candidate_evictions, join_limit, join_refused, untracked_states, promoted;
  /* accounted bytes by structure at the end of the sample */
  uint64_t baseline_bytes, tracked_bytes, candidate_bytes, join_bytes, ranking_bytes,
      discovery_bytes;
  /* the recommended sampling interval and why (cadence.h) */
  uint64_t recommended_interval_ms, cadence_reason;
  /* the lifetime screen (lifetime.h): PF records observed, those skipped for
   * an impossible lifetime, those whose age is unknown; whether validation
   * was active, its limit (largest applicable timeout, s), the errno that
   * made it unavailable, and the bound refresh's cost (us) */
  uint64_t pf_records_observed, invalid_pf_states_skipped, age_unknown_states,
      lifetime_validation, lifetime_limit, lifetime_error, lifetime_refresh_us;
};
/* The sample's classification: set statuses, and the masks of the addresses
 * the request asked about (K rows). */
struct class_report {
  const struct classifier *classifier;
  const struct addr *addresses;
  size_t address_count;
  /* each address's evidence (the sample's EVIDENCE facts, the threat sets)
   * and its PF states in tracked flows (optional: NULL aggregate) */
  const struct aggregate *aggregate;
  const struct map *evidence;
  const struct evidence *facts;
  uint64_t threat_mask;
};
void protocol_put(unsigned char **, uint64_t, unsigned);
uint64_t protocol_get(const unsigned char **, unsigned);
void protocol_address_put(unsigned char **, struct addr);
bool protocol_frame(FILE *, const void *, size_t, uint32_t *,
                    struct fm_error *);
/* The ranked part of a sample: the active profile's selection, in rank
 * order. */
struct ranked_output {
  const struct ranked_flow *flows;
  size_t count;
  /* a sample that opens a snapshot session: the flows a snapshot may
   * capture (aggregate flow indexes, in priority order) */
  const uint32_t *snapshot;
  size_t snapshot_count;
  const struct ranking *ranking; /* the candidates' rates */
  const struct ranker *ranker;   /* the candidates' effective scores */
};
/* FMAGG4 sample response. */
/* Fills the telemetry's omission counters before writing it. */
bool protocol_write_ranked(FILE *, const struct aggregate *, const struct ranked_output *,
                           const struct threat_summary *, const struct event_match *, size_t,
                           const struct class_report *, size_t candidates_per_kind,
                           struct telemetry *, struct fm_error *);
/* FMAGG4 response for a snapshot selection (explicit flows, no threats). */
bool protocol_write_selected(FILE *, const struct aggregate *,
                             const struct ranked_flow *, size_t,
                             const struct telemetry *, struct fm_error *);
/* FMAGG4 refusal: header, telemetry and footer only. */
bool protocol_write_refusal(FILE *, struct sample_outcome, uint64_t states_seen,
                            const struct telemetry *, struct fm_error *);
/* FMFAIL1: best effort; the helper exits afterwards. */
void protocol_write_failure(FILE *, const struct fm_error *);
/* Devel-only FMAGG2 aggregate dump used by the equivalence tools; defined in
 * devel/collector_fmagg2.c, not in the installed helper. */
bool protocol_write(FILE *, const struct aggregate *, const struct correlation *, bool with_deltas,
                    struct fm_error *);
#endif
