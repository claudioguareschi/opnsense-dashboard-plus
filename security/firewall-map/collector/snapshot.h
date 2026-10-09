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

#ifndef FM_SNAPSHOT_H
#define FM_SNAPSHOT_H
#include "pf_reader.h"
#include "protocol.h"
#include "ranking.h"
struct ranker;
#define FM_SNAPSHOT_FLOWS 5000
#define FM_SNAPSHOT_BYTES (10u * 1024u * 1024u)
#define FM_SNAPSHOT_STATES 5000
/* FMSTATE2 omission reason bits (PROTOCOL.md). */
#define SNAPSHOT_OMITTED_BYTES 1      /* the encoded-size budget ran out */
#define SNAPSHOT_OMITTED_STATES 2     /* the state budget left this flow no quota */
#define SNAPSHOT_OMITTED_FLOW_QUOTA 4 /* more matching states than the flow's quota */
/* FMSTATE2 exemplar selection policy: per flow, the exemplars with the most
 * bytes, then the newest, then the lowest PF identity (creator, id). */
#define SNAPSHOT_POLICY_BYTES_NEWEST 2
/* Evidence budget policy. Incident flows (Python's required evidence) are
 * guaranteed most of the state budget, so routine traffic cannot crowd out
 * the flows a snapshot is usually taken for, while some room stays for the
 * context around them. Each incident flow first gets a floor of exemplars,
 * so one huge incident cannot starve the others; the rest is water-filled by
 * demand, and every share a flow cannot use returns to the pool. */
#define SNAPSHOT_INCIDENT_SHARE_PERCENT 80
#define SNAPSHOT_INCIDENT_FLOOR 20
struct snapshot;
struct snapshot_flow {
  struct addr local, remote;
  bool incident;
  uint64_t sample_states; /* matching states in the sample: the quota demand */
};
/* Borrows context; owns only bounded accepted evidence and a selected-flow index.
 * Call snapshot_write only after the PF reader has completed successfully.
 * Truncation never fails a snapshot: what was left out is reported. */
struct snapshot *snapshot_create(const struct context *, const struct snapshot_flow *,
                                 size_t, size_t byte_limit, size_t state_limit,
                                 uint64_t generation, double sample_time,
                                 struct fm_error *);
void snapshot_destroy(struct snapshot *);
bool snapshot_add(const struct state *, void *, struct fm_error *);
/* The lifetime bound its PF records are screened with (lifetime.h); a new
 * snapshot screens ages only (no bound: nothing is rejected). */
void snapshot_screen(struct snapshot *, struct lifetime_bound);
bool snapshot_write(struct snapshot *, FILE *, struct fm_error *);
/* Per-flow exemplar quotas for a state budget (exposed for tests). */
void snapshot_quotas(const struct snapshot_flow *, size_t count, size_t state_limit,
                     size_t *quotas);
/* Snapshot-only session following a sample explicitly requesting it. The
 * aggregate/ranking are borrowed until DETAIL or CANCEL closes the session;
 * the telemetry describes the sample the session belongs to. */
bool snapshot_session(FILE *, FILE *, const struct context *, const struct aggregate *,
                      const struct ranking *, const struct ranker *, uint64_t, double,
                      struct lifetime_bound, const struct telemetry *, struct fm_error *);
#endif
