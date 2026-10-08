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

#ifndef FM_AGGREGATE_H
#define FM_AGGREGATE_H
#include "classify.h"
#include "correlation.h"
#include "history.h"
struct aggregate;
/* Attribution evidence kept per flow, deduplicated by (flow, kind, value) and
 * weighted by traffic. The numbers are part of the FMAGG4 wire format. */
enum candidate_kind {
  CANDIDATE_PROTOCOL = 1,         /* value: protocol number (1 byte) */
  CANDIDATE_INSIDE_HOST = 2,      /* value: address (17 bytes) */
  CANDIDATE_EGRESS_INTERFACE = 3, /* value: interface name */
  CANDIDATE_SERVICE = 4,          /* value: group(4) proto(1) port(2) */
  CANDIDATE_REMOTE_TARGET = 5,    /* value: proto(1) address(17) port(2) */
  CANDIDATE_RULE_LABEL = 6,       /* value: PF rule label */
};
#define CANDIDATE_KIND_COUNT 6
#define CANDIDATE_VALUE_MAX 64
struct flow {
  struct addr local, remote;
  uint64_t states, bytes_from_remote, bytes_to_remote, remote_initiated_weight,
      local_initiated_weight, remote_initiated_states, local_initiated_states,
      first;
  uint64_t classes; /* classification sets containing the remote */
  uint32_t oldest, youngest;
  struct state_delta delta;
};
struct candidate_view {
  uint32_t flow;
  unsigned char kind;
  const unsigned char *data;
  size_t len;
  uint64_t seq, weight, association;
};
struct aggregate_counts {
  uint64_t seen, retained, mapped, skipped_af_translation;
  size_t flows, candidates;
};
/* Context and history are borrowed for the lifetime of this single sample.
 * Returned flow/candidate views remain valid until aggregate_destroy(). */
/* observe (optional): called with the outside tuple of every correlated
 * state, for IDS/block event matching; NULL skips that work. */
struct aggregate *aggregate_create(const struct context *, struct history *,
                                   tuple_observer observe, void *observer,
                                   struct fm_error *);
/* The sample's classification snapshot (borrowed; NULL: no sets). Set before
 * the first state. */
void aggregate_set_classifier(struct aggregate *, const struct classifier *);
void aggregate_destroy(struct aggregate *);
bool aggregate_add(struct aggregate *, const struct state *, struct fm_error *);
bool aggregate_finish(struct aggregate *, struct fm_error *);
struct aggregate_counts aggregate_counts(const struct aggregate *);
const struct flow *aggregate_flow(const struct aggregate *, size_t);
bool aggregate_candidate(const struct aggregate *, size_t,
                         struct candidate_view *);
size_t aggregate_bytes(const struct aggregate *);
#endif
