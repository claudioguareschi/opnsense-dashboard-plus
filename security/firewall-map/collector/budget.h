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
/* The helper's resource model (PROTOCOL.md, "Resource budgets").
 *
 * Two controls bound everything the helper does per sample:
 *
 * 1. The memory budget (BUDGET row; accounted heap, alloc.c). Every per-sample
 *    structure (history, aggregate, candidates, correlation, ranking, threat
 *    summary) grows at most linearly with the PF states traversed, so the same
 *    budget derives the PF state admission ceiling: a sample whose state count
 *    exceeds it is refused before traversal (preflight) or as soon as the
 *    count passes it (backstop), and any allocation the budget refuses turns
 *    the sample into a refusal too. Refusals are not helper failures.
 *
 * 2. The output budget: ranked flows, candidates per (flow, kind), threat
 *    remotes and their candidates per (remote, kind), and event matches. It
 *    bounds the response and therefore all of Python's per-sample work.
 *
 * Nothing else is capped independently: every other size is derived. */

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
/* Accounted heap per PF state at a sample's peak in the worst case: every
 * state its own flow, remote and attribution values, with the compact
 * baseline, the per-flow aggregate and ranking structures and a threat
 * summary. Measured on LP64 with the synthetic reader's "unique" table after
 * the 0.60 Phase B changes (compact baseline, streamed IDS tuples): at most
 * 2,100 bytes per additional state between 100,000 and 300,000 states
 * (tests/test_collector_scale.py), plus a 25% margin. Tables with many states
 * per flow cost far less (about 56 bytes per state: the baseline alone), but
 * admission stays worst-case until Phase D bounds the per-flow structures.
 * Accounting counts requested bytes, not allocator overhead, so the figure
 * does not depend on the libc; how RSS relates to it on the target (jemalloc)
 * is pending FreeBSD calibration. */
#define BUDGET_BYTES_PER_STATE 2624
/* Accounted heap that does not scale with states: the IDS recent-tuple ring,
 * its sample window and rebuild copy (about 13 MB), request context at its
 * maxima, response bookkeeping. */
#define BUDGET_FIXED_BYTES (UINT64_C(24) << 20)

static inline uint64_t budget_state_limit(uint64_t memory) {
  return memory > BUDGET_FIXED_BYTES ? (memory - BUDGET_FIXED_BYTES) / BUDGET_BYTES_PER_STATE : 0;
}
#endif
