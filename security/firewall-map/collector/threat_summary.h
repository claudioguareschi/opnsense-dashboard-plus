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

#ifndef FM_THREAT_SUMMARY_H
#define FM_THREAT_SUMMARY_H
#include "aggregate.h"

struct threat_summary;
struct threat_remote {
  struct addr address;
  uint64_t remote_initiated_states, local_initiated_states, bytes;
  uint32_t youngest;
};
struct threat_candidate_view {
  uint32_t remote;
  struct candidate_view candidate;
};
/* Which remotes a bounded threat summary keeps, in this order (stable within
 * each class by first appearance in the sample):
 *   1. remotes Python named as evidence (IDS, reputation, blocked sources);
 *   2. remotes this site initiated traffic with, by bytes, largest first;
 *   3. remotes that only initiated toward this site, by bytes, then youngest.
 * At most `remote_limit` remotes and `candidates_per_kind` candidates per
 * (remote, kind) are kept; the omitted counts say what was left out. */
struct threat_limits {
  const struct addr *evidence;
  size_t evidence_count, remote_limit, candidates_per_kind;
};
struct threat_summary *threat_summary_create(const struct aggregate *,
                                             struct threat_limits,
                                             struct fm_error *);
void threat_summary_destroy(struct threat_summary *);
size_t threat_summary_remote_count(const struct threat_summary *);
size_t threat_summary_candidate_count(const struct threat_summary *);
uint64_t threat_summary_remotes_omitted(const struct threat_summary *);
uint64_t threat_summary_candidates_omitted(const struct threat_summary *);
bool threat_summary_remote_at(const struct threat_summary *, size_t,
                              struct threat_remote *);
bool threat_summary_candidate_at(const struct threat_summary *, size_t,
                                 struct threat_candidate_view *);

#endif
