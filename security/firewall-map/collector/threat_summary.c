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

#include "threat_summary.h"
#include "alloc.h"
#include "index.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* One distinct remote of the sample while the summary is being chosen. */
struct remote_row {
  struct threat_remote remote;
  size_t first; /* first appearance: the stable tie-break */
  unsigned priority;
  bool flagged;     /* evidence or a flagged classification */
  uint32_t kept; /* 1 + output index when kept, else 0 */
};
struct threat_summary {
  struct threat_remote *remotes;
  size_t remote_count;
  struct threat_candidate_view *candidates;
  size_t candidate_count, candidate_capacity;
  uint64_t remotes_omitted, candidates_omitted;
};

static size_t address_key(unsigned char key[17], struct addr address) {
  key[0] = address.af;
  memcpy(key + 1, address.b, 16);
  return 17;
}
static bool add_count(uint64_t *value, uint64_t add, struct fm_error *error) {
  if (UINT64_MAX - *value < add)
    return fm_error_set(error, EOVERFLOW, "threat summary counter");
  *value += add;
  return true;
}
static bool reserve(struct threat_summary *summary, struct fm_error *error) {
  if (summary->candidate_count < summary->candidate_capacity) return true;
  size_t next = summary->candidate_capacity ? summary->candidate_capacity * 2 : 64;
  if (next < summary->candidate_capacity || next > SIZE_MAX / sizeof(*summary->candidates))
    return fm_error_set(error, EOVERFLOW, "threat candidate capacity");
  void *data = fm_realloc(summary->candidates, next * sizeof(*summary->candidates));
  if (!data) return fm_error_set(error, errno, "threat candidate allocation");
  summary->candidates = data;
  summary->candidate_capacity = next;
  return true;
}
/* Priority classes, smaller first. */
enum { PRIORITY_EVIDENCE = 0, PRIORITY_LOCAL = 1, PRIORITY_REMOTE_ONLY = 2 };
static int compare_rows(const void *left, const void *right) {
  const struct remote_row *a = *(const struct remote_row *const *)left;
  const struct remote_row *b = *(const struct remote_row *const *)right;
  if (a->priority != b->priority) return a->priority < b->priority ? -1 : 1;
  if (a->priority != PRIORITY_EVIDENCE && a->remote.bytes != b->remote.bytes)
    return a->remote.bytes > b->remote.bytes ? -1 : 1;
  if (a->priority == PRIORITY_REMOTE_ONLY && a->remote.youngest != b->remote.youngest)
    return a->remote.youngest < b->remote.youngest ? -1 : 1;
  return a->first < b->first ? -1 : a->first > b->first;
}

struct threat_summary *threat_summary_create(const struct aggregate *aggregate,
                                             struct threat_limits limits,
                                             struct fm_error *error) {
  struct threat_summary *summary = fm_calloc(1, sizeof(*summary));
  struct aggregate_counts counts = aggregate_counts(aggregate);
  struct map ids = {0}, evidence = {0}, candidates = {0};
  struct remote_row *rows = NULL, **order = NULL;
  size_t row_count = 0;
  if (!summary) {
    fm_error_set(error, errno, "threat summary allocation");
    return NULL;
  }
  rows = counts.flows ? fm_calloc(counts.flows, sizeof(*rows)) : NULL;
  if (counts.flows && !rows) {
    fm_error_set(error, errno, "threat remote allocation");
    goto fail;
  }
  for (size_t n = 0; n < limits.evidence_count; n++) {
    unsigned char key[17];
    struct item *item = lookup(&evidence, key, address_key(key, limits.evidence[n]), true, error);
    if (!item) goto fail;
  }
  /* every distinct remote of the sample, totals summed over its flows */
  for (size_t n = 0; n < counts.flows; n++) {
    const struct flow *flow = aggregate_flow(aggregate, n);
    unsigned char key[17];
    struct item *item = lookup(&ids, key, address_key(key, flow->remote), true, error);
    if (!item) goto fail;
    if (!item->count) {
      item->count = 1;
      item->value = row_count;
      rows[row_count++] = (struct remote_row){
          .remote = {.address = flow->remote, .classes = flow->classes, .youngest = UINT32_MAX},
          .first = n,
          .priority = map_find(&evidence, key, 17) ? PRIORITY_EVIDENCE : PRIORITY_REMOTE_ONLY};
      rows[row_count - 1].flagged = rows[row_count - 1].priority == PRIORITY_EVIDENCE ||
                                    (flow->classes & limits.flagged);
    }
    struct remote_row *row = &rows[item->value];
    if (UINT64_MAX - flow->bytes_from_remote < flow->bytes_to_remote) {
      fm_error_set(error, EOVERFLOW, "threat flow byte total");
      goto fail;
    }
    if (!add_count(&row->remote.remote_initiated_states, flow->remote_initiated_states, error) ||
        !add_count(&row->remote.local_initiated_states, flow->local_initiated_states, error) ||
        !add_count(&row->remote.bytes, flow->bytes_from_remote + flow->bytes_to_remote, error))
      goto fail;
    if (flow->youngest < row->remote.youngest) row->remote.youngest = flow->youngest;
  }
  for (size_t n = 0; n < row_count; n++)
    if (rows[n].priority != PRIORITY_EVIDENCE && rows[n].remote.local_initiated_states)
      rows[n].priority = PRIORITY_LOCAL;
  order = row_count ? fm_calloc(row_count, sizeof(*order)) : NULL;
  if (row_count && !order) {
    fm_error_set(error, errno, "threat remote order");
    goto fail;
  }
  size_t flagged = 0;
  for (size_t n = 0; n < row_count; n++)
    if (rows[n].flagged) order[flagged++] = &rows[n];
  qsort(order, flagged, sizeof(*order), compare_rows);
  size_t kept = flagged < limits.remote_limit ? flagged : limits.remote_limit;
  summary->remotes_omitted = flagged - kept;
  summary->remotes = kept ? fm_calloc(kept, sizeof(*summary->remotes)) : NULL;
  if (kept && !summary->remotes) {
    fm_error_set(error, errno, "threat remote allocation");
    goto fail;
  }
  for (size_t n = 0; n < kept; n++) {
    order[n]->kept = (uint32_t)n + 1;
    summary->remotes[summary->remote_count++] = order[n]->remote;
  }
  /* Inside hosts, services and targets of kept remotes, deduplicated (the
   * threat record keeps unique values in first-seen order), at most
   * candidates_per_kind each: IPC size scales with distinct evidence. */
  for (size_t n = 0; n < counts.candidates; n++) {
    struct candidate_view candidate;
    if (!aggregate_candidate(aggregate, n, &candidate) || candidate.flow >= counts.flows) {
      fm_error_set(error, EINVAL, "threat aggregate candidate");
      goto fail;
    }
    if (candidate.kind != CANDIDATE_INSIDE_HOST && candidate.kind != CANDIDATE_SERVICE &&
        candidate.kind != CANDIDATE_REMOTE_TARGET) continue;
    if (candidate.len > CANDIDATE_VALUE_MAX) {
      fm_error_set(error, EOVERFLOW, "threat candidate size");
      goto fail;
    }
    unsigned char key[17];
    const struct item *item = map_find(&ids, key, address_key(key, aggregate_flow(aggregate, candidate.flow)->remote));
    if (!item || item->value >= row_count) {
      fm_error_set(error, EINVAL, "threat candidate remote");
      goto fail;
    }
    const struct remote_row *row = &rows[item->value];
    /* values of remotes outside the summary are never indexed */
    if (!row->kept) continue;
    unsigned char candidate_key[7 + CANDIDATE_VALUE_MAX], *key_end = candidate_key;
    uint32_t remote_id = (uint32_t)item->value;
    memcpy(key_end, &remote_id, sizeof(remote_id)); key_end += sizeof(remote_id);
    *key_end++ = candidate.kind;
    *key_end++ = candidate.len >> 8;
    *key_end++ = candidate.len;
    memcpy(key_end, candidate.data, candidate.len);
    key_end += candidate.len;
    struct item *seen = lookup(&candidates, candidate_key, (size_t)(key_end - candidate_key), true, error);
    if (!seen) goto fail;
    if (seen->count) continue;
    seen->count = 1;
    /* per (remote, kind) count, kept in a second key without the value */
    unsigned char kind_key[5];
    memcpy(kind_key, &remote_id, 4);
    kind_key[4] = candidate.kind;
    struct item *per_kind = lookup(&candidates, kind_key, sizeof(kind_key), true, error);
    if (!per_kind) goto fail;
    if (per_kind->value >= limits.candidates_per_kind) {
      summary->candidates_omitted++;
      continue;
    }
    per_kind->value++;
    if (!reserve(summary, error)) goto fail;
    summary->candidates[summary->candidate_count++] =
        (struct threat_candidate_view){row->kept - 1, candidate};
  }
  map_clear(&ids);
  map_clear(&evidence);
  map_clear(&candidates);
  fm_free(order);
  fm_free(rows);
  return summary;
fail:
  map_clear(&ids);
  map_clear(&evidence);
  map_clear(&candidates);
  fm_free(order);
  fm_free(rows);
  threat_summary_destroy(summary);
  return NULL;
}

void threat_summary_destroy(struct threat_summary *summary) {
  if (!summary) return;
  fm_free(summary->remotes);
  fm_free(summary->candidates);
  fm_free(summary);
}
size_t threat_summary_remote_count(const struct threat_summary *summary) { return summary->remote_count; }
size_t threat_summary_candidate_count(const struct threat_summary *summary) { return summary->candidate_count; }
uint64_t threat_summary_remotes_omitted(const struct threat_summary *summary) { return summary->remotes_omitted; }
uint64_t threat_summary_candidates_omitted(const struct threat_summary *summary) { return summary->candidates_omitted; }
bool threat_summary_remote_at(const struct threat_summary *summary, size_t n,
                              struct threat_remote *remote) {
  if (n >= summary->remote_count) return false;
  *remote = summary->remotes[n];
  return true;
}
bool threat_summary_candidate_at(const struct threat_summary *summary, size_t n,
                                 struct threat_candidate_view *candidate) {
  if (n >= summary->candidate_count) return false;
  *candidate = summary->candidates[n];
  return true;
}
