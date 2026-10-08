/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "threat_summary.h"
#include "index.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct threat_summary {
  struct threat_remote *remotes;
  size_t remote_count;
  struct threat_candidate_view *candidates;
  size_t candidate_count, candidate_capacity;
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

struct threat_summary *threat_summary_create(const struct aggregate *aggregate,
                                             struct fm_error *error) {
  struct threat_summary *summary = fm_calloc(1, sizeof(*summary));
  struct aggregate_counts counts = aggregate_counts(aggregate);
  struct map ids = {0}, candidates = {0};
  if (!summary) {
    fm_error_set(error, errno, "threat summary allocation");
    return NULL;
  }
  if (counts.flows > SIZE_MAX / sizeof(*summary->remotes)) {
    fm_error_set(error, EOVERFLOW, "threat remote capacity");
    goto fail;
  }
  summary->remotes = counts.flows ? fm_calloc(counts.flows, sizeof(*summary->remotes)) : NULL;
  if (counts.flows && !summary->remotes) {
    fm_error_set(error, errno, "threat remote allocation");
    goto fail;
  }
  for (size_t n = 0; n < counts.flows; n++) {
    const struct flow *flow = aggregate_flow(aggregate, n);
    unsigned char key[17];
    struct item *item = lookup(&ids, key, address_key(key, flow->remote), true, error);
    if (!item) goto fail;
    if (!item->count) {
      item->count = 1;
      item->value = summary->remote_count;
      summary->remotes[summary->remote_count++] =
          (struct threat_remote){.address = flow->remote, .youngest = UINT32_MAX};
    }
    struct threat_remote *remote = &summary->remotes[item->value];
    uint64_t bytes;
    if (UINT64_MAX - flow->bytes_from_remote < flow->bytes_to_remote)
      { fm_error_set(error, EOVERFLOW, "threat flow byte total"); goto fail; }
    bytes = flow->bytes_from_remote + flow->bytes_to_remote;
    if (!add_count(&remote->remote_initiated_states, flow->remote_initiated_states, error) ||
        !add_count(&remote->local_initiated_states, flow->local_initiated_states, error) ||
        !add_count(&remote->bytes, bytes, error)) goto fail;
    if (flow->youngest < remote->youngest) remote->youngest = flow->youngest;
  }
  for (size_t n = 0; n < counts.candidates; n++) {
    struct candidate_view candidate;
    if (!aggregate_candidate(aggregate, n, &candidate) || candidate.flow >= counts.flows) {
      fm_error_set(error, EINVAL, "threat aggregate candidate");
      goto fail;
    }
    if (candidate.kind != CANDIDATE_INSIDE_HOST && candidate.kind != CANDIDATE_SERVICE &&
        candidate.kind != CANDIDATE_REMOTE_TARGET) continue;
    const struct flow *flow = aggregate_flow(aggregate, candidate.flow);
    unsigned char key[17];
    struct item *item = lookup(&ids, key, address_key(key, flow->remote), false, NULL);
    if (!item || item->value >= summary->remote_count || !reserve(summary, error)) {
      if (!error->code) fm_error_set(error, EINVAL, "threat candidate remote");
      goto fail;
    }
    /* ThreatRecorder retains unique inside hosts, targets and services in
     * first-seen order. Deduplicate here so IPC size scales with distinct
     * evidence, not with the number of states repeating it. */
    unsigned char candidate_key[7 + CANDIDATE_VALUE_MAX], *key_end = candidate_key;
    if (candidate.len > CANDIDATE_VALUE_MAX) {
      fm_error_set(error, EOVERFLOW, "threat candidate size");
      goto fail;
    }
    uint32_t remote_id = (uint32_t)item->value;
    memcpy(key_end, &remote_id, sizeof(remote_id)); key_end += sizeof(remote_id);
    *key_end++ = candidate.kind;
    *key_end++ = candidate.len >> 8;
    *key_end++ = candidate.len;
    memcpy(key_end, candidate.data, candidate.len);
    key_end += candidate.len;
    struct item *seen = lookup(&candidates, candidate_key,
                               (size_t)(key_end - candidate_key), true, error);
    if (!seen) goto fail;
    if (seen->count) continue;
    seen->count = 1;
    summary->candidates[summary->candidate_count++] =
        (struct threat_candidate_view){(uint32_t)item->value, candidate};
  }
  map_clear(&ids);
  map_clear(&candidates);
  return summary;
fail:
  map_clear(&ids);
  map_clear(&candidates);
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
