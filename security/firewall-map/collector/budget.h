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

#ifndef FM_BUDGET_H
#define FM_BUDGET_H
#include <stdint.h>
/* The helper's resource model (PROTOCOL.md, "Resource budgets";
 * CONTRACTS.md, "Boundedness").
 *
 * 1. The memory budget (BUDGET row; accounted heap, alloc.c). After the
 *    fixed structures and the classification snapshot, the rest is shared
 *    out: the state baseline (the only structure that grows with PF's state
 *    count; it derives the state admission limit), the tracked set T (rich
 *    per-flow accounting and rate history), the attribution candidates and
 *    the LAN-companion join. Each has an explicit entry cap derived from its
 *    share; reaching one degrades quality (bounded ranking, partial
 *    attribution), it never refuses the sample. A sample over the state
 *    admission limit, or an allocation the budget refuses, is refused.
 *
 * 2. The output budget: ranked flows, candidates per (flow, kind), threat
 *    remotes and their candidates per (remote, kind), and event matches. It
 *    bounds the response and therefore all of Python's per-sample work. */

/* Ranked flows sent per sample (the map's own limit). */
#define BUDGET_RANKED_FLOWS 150
/* Candidates per (flow, kind) and per (threat remote, kind): the request may
 * lower the default, never exceed the maximum. */
#define BUDGET_CANDIDATES_DEFAULT 16
#define BUDGET_CANDIDATES_MAX 64
/* Remotes in one threat summary (request may lower). */
#define BUDGET_THREAT_REMOTES_DEFAULT 20000
#define BUDGET_THREAT_REMOTES_MAX 20000
/* Memory budget bounds (bytes); the default applies when no BUDGET row is
 * sent (Python always sends one: 5% of physical memory, at most 1 GiB). */
#define BUDGET_MEMORY_MIN (UINT64_C(64) << 20)
#define BUDGET_MEMORY_MAX (UINT64_C(16384) << 20)
#define BUDGET_MEMORY_DEFAULT (UINT64_C(256) << 20)
/* Accounted heap that does not scale with states or flows: the IDS
 * recent-tuple ring, its sample window and rebuild copy (about 13 MB), the
 * discovery summaries (about 9.5 MB), request context at its maxima, response
 * bookkeeping. */
#define BUDGET_FIXED_BYTES (UINT64_C(40) << 20)
/* Shares of the rest, in percent. */
#define BUDGET_BASELINE_SHARE 45
#define BUDGET_TRACKED_SHARE 15
#define BUDGET_CANDIDATE_SHARE 15
#define BUDGET_JOIN_SHARE 25
/* Accounted bytes per unit on LP64, with a margin over what the synthetic
 * worst cases measure (unique flows, 90k to 300k states): a baseline entry
 * at the table's load (57-64 measured); a tracked flow: aggregate row and
 * index, rate history in two generations, ranking rows (750-800 measured)
 * plus the threat summary's per-flow row and the active profile's per-flow
 * state (asset multiplier, flow volume, effective score and the bounded
 * regime's retention order: about 64); a candidate entry with its index
 * (about 136); a join entry, LAN label or pending inside-flow label (about
 * 128). */
#define BUDGET_BASELINE_BYTES_PER_STATE 80
#define BUDGET_BYTES_PER_TRACKED_FLOW 1536
#define BUDGET_BYTES_PER_CANDIDATE 136
#define BUDGET_BYTES_PER_JOIN 224
/* The tracked set never shrinks below this (very small budgets). */
#define BUDGET_TRACKED_MIN 1000

/* What the shares come to for a budget less the classification snapshot. */
struct budget_limits {
  uint64_t states, tracked, candidates, joins;
};
static inline struct budget_limits budget_limits(uint64_t memory, uint64_t classifier) {
  uint64_t rest = memory > BUDGET_FIXED_BYTES + classifier ? memory - BUDGET_FIXED_BYTES - classifier : 0;
  struct budget_limits l = {
      rest / 100 * BUDGET_BASELINE_SHARE / BUDGET_BASELINE_BYTES_PER_STATE,
      rest / 100 * BUDGET_TRACKED_SHARE / BUDGET_BYTES_PER_TRACKED_FLOW,
      rest / 100 * BUDGET_CANDIDATE_SHARE / BUDGET_BYTES_PER_CANDIDATE,
      rest / 100 * BUDGET_JOIN_SHARE / BUDGET_BYTES_PER_JOIN};
  if (l.tracked < BUDGET_TRACKED_MIN) l.tracked = BUDGET_TRACKED_MIN;
  return l;
}
#endif
