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
#define FM_SNAPSHOT_FLOWS 5000
#define FM_SNAPSHOT_BYTES (10u * 1024u * 1024u)
#define FM_SNAPSHOT_STATES 5000
/* FMSTATE2 omission reason bits (PROTOCOL.md). */
#define SNAPSHOT_OMITTED_BYTES 1
#define SNAPSHOT_OMITTED_STATES 2
#define SNAPSHOT_OMITTED_FLOW_QUOTA 4
/* FMSTATE2 exemplar selection policies. */
#define SNAPSHOT_POLICY_ARRIVAL 1 /* traversal order, incidents displace ordinary */
struct snapshot;
struct snapshot_flow {
  struct addr local, remote;
  bool incident;
};
/* Borrows context; owns only bounded accepted evidence and a selected-flow index.
 * Call snapshot_write only after the PF reader has completed successfully. */
struct snapshot *snapshot_create(const struct context *, const struct snapshot_flow *,
                                 size_t, size_t byte_limit, size_t state_limit,
                                 uint64_t generation, double sample_time,
                                 struct fm_error *);
void snapshot_destroy(struct snapshot *);
bool snapshot_add(const struct state *, void *, struct fm_error *);
bool snapshot_write(struct snapshot *, FILE *, struct fm_error *);
/* Snapshot-only session following a sample explicitly requesting it. The
 * aggregate/ranking are borrowed until DETAIL or CANCEL closes the session;
 * the telemetry describes the sample the session belongs to. */
bool snapshot_session(FILE *, FILE *, const struct context *, const struct aggregate *,
                      const struct ranking *, uint64_t, double,
                      const struct telemetry *, struct fm_error *);
#endif
