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

#include "protocol.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
void protocol_put(unsigned char **p, uint64_t value, unsigned width) {
  for (unsigned n = width; n; n--)
    *(*p)++ = value >> ((n - 1) * 8);
}
uint64_t protocol_get(const unsigned char **p, unsigned width) {
  uint64_t value = 0;
  while (width--)
    value = (value << 8) | *(*p)++;
  return value;
}
void protocol_address_put(unsigned char **p, struct addr a) {
  *(*p)++ = a.af;
  memcpy(*p, a.b, 16);
  *p += 16;
}
static void put_double(unsigned char **p, double value) {
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  protocol_put(p, bits, 8);
}
static uint32_t crc(uint32_t value, const void *data, size_t size) {
  /* A small stack table keeps output writers independent and reentrant. */
  uint32_t table[256];
  for (unsigned i = 0; i < 256; i++) {
    uint32_t v = i;
    for (unsigned j = 0; j < 8; j++)
      v = (v >> 1) ^ (v & 1 ? UINT32_C(0xedb88320) : 0);
    table[i] = v;
  }
  value = ~value;
  const unsigned char *p = data;
  while (size--)
    value = table[(value ^ *p++) & 255] ^ (value >> 8);
  return ~value;
}
bool protocol_frame(FILE *f, const void *data, size_t len, uint32_t *checksum,
                    struct fm_error *error) {
  if (!len || len > FM_FRAME_MAX)
    return fm_error_set(error, EOVERFLOW, "frame size");
  unsigned char size[4], *p = size;
  protocol_put(&p, len, 4);
  if (fwrite(size, 1, 4, f) != 4 || fwrite(data, 1, len, f) != len)
    return fm_error_set(error, errno ? errno : EIO, "frame write");
  if (checksum) {
    *checksum = crc(*checksum, size, 4);
    *checksum = crc(*checksum, data, len);
  }
  return true;
}

/* Sizes of the fixed FMAGG4 records (PROTOCOL.md). */
#define FLOW_RECORD_SIZE 159
#define EVENT_RECORD_SIZE 194
#define TELEMETRY_RECORD_SIZE 141
#define FOOTER_RECORD_SIZE 101

struct sent {
  uint64_t flows, candidates, matches, remotes, remote_candidates;
};

static bool write_header(FILE *f, bool threats, uint32_t *checksum,
                         struct fm_error *error) {
  if (fwrite("FMAGG4\0\0", 1, 8, f) != 8)
    return fm_error_set(error, errno ? errno : EIO, "FMAGG4 header");
  unsigned char b[16], *p = b;
  *p++ = RECORD_HEADER;
  protocol_put(&p, 4, 4);
  protocol_put(&p, threats ? 1 : 0, 4);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_flow(FILE *f, size_t rank, const struct flow *flow,
                       const struct ranked_flow *rates, uint32_t *checksum,
                       struct fm_error *error) {
  unsigned char b[FLOW_RECORD_SIZE], *p = b;
  *p++ = RECORD_FLOW;
  protocol_put(&p, rank, 4);
  protocol_address_put(&p, flow->local);
  protocol_address_put(&p, flow->remote);
  protocol_put(&p, flow->states, 8);
  protocol_put(&p, flow->bytes_from_remote, 8);
  protocol_put(&p, flow->bytes_to_remote, 8);
  protocol_put(&p, flow->oldest, 4);
  protocol_put(&p, flow->youngest, 4);
  protocol_put(&p, flow->remote_initiated_weight, 8);
  protocol_put(&p, flow->local_initiated_weight, 8);
  protocol_put(&p, flow->first, 8);
  protocol_put(&p, flow->delta.bytes_from_remote, 8);
  protocol_put(&p, flow->delta.bytes_to_remote, 8);
  protocol_put(&p, flow->delta.packets, 8);
  put_double(&p, rates->rate_from_remote);
  put_double(&p, rates->rate_to_remote);
  put_double(&p, rates->packet_rate);
  put_double(&p, rates->activity);
  put_double(&p, rates->score);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_candidate(FILE *f, unsigned char kind, uint32_t owner,
                            const struct candidate_view *value, bool weight,
                            uint32_t *checksum, struct fm_error *error) {
  unsigned char b[32 + CANDIDATE_VALUE_MAX], *p = b;
  if (value->len > CANDIDATE_VALUE_MAX)
    return fm_error_set(error, EOVERFLOW, "candidate size");
  *p++ = kind;
  protocol_put(&p, owner, 4);
  *p++ = value->kind;
  protocol_put(&p, value->seq, 8);
  if (weight)
    protocol_put(&p, value->weight, 8);
  protocol_put(&p, value->association, 8);
  protocol_put(&p, value->len, 2);
  memcpy(p, value->data, value->len);
  p += value->len;
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_match(FILE *f, const struct event_match *match,
                        uint32_t *checksum, struct fm_error *error) {
  const struct correlation_value *v = &match->value;
  unsigned char b[EVENT_RECORD_SIZE], *p = b;
  *p++ = RECORD_EVENT_MATCH;
  protocol_put(&p, match->id, 2);
  *p++ = match->kind;
  *p++ = match->key.protocol;
  protocol_address_put(&p, match->key.public.a);
  protocol_put(&p, match->key.public.port, 2);
  protocol_address_put(&p, match->key.remote.a);
  protocol_put(&p, match->key.remote.port, 2);
  *p++ = v->has_inside;
  protocol_address_put(&p, v->inside.a);
  protocol_put(&p, v->inside.port, 2);
  protocol_put(&p, v->state_id, 8);
  protocol_put(&p, v->creator_id, 4);
  *p++ = v->ambiguous;
  protocol_put(&p, v->age, 4);
  protocol_put(&p, v->bytes_from_remote, 8);
  protocol_put(&p, v->bytes_to_remote, 8);
  protocol_put(&p, v->packets_from_remote, 8);
  protocol_put(&p, v->packets_to_remote, 8);
  *p++ = v->remote_initiated;
  *p++ = v->apparent_remote_initiated;
  memcpy(p, v->interface, FM_INTERFACE_SIZE);
  p += FM_INTERFACE_SIZE;
  memcpy(p, v->rule, FM_LABEL_SIZE);
  p += FM_LABEL_SIZE;
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_telemetry(FILE *f, const struct telemetry *t,
                            uint32_t *checksum, struct fm_error *error) {
  unsigned char b[TELEMETRY_RECORD_SIZE], *p = b;
  *p++ = RECORD_TELEMETRY;
  protocol_put(&p, t->pid, 4);
  protocol_put(&p, t->sequence, 8);
  put_double(&p, t->interval);
  put_double(&p, t->dump_seconds);
  put_double(&p, t->processing_seconds);
  put_double(&p, t->user_cpu);
  put_double(&p, t->system_cpu);
  const uint64_t values[] = {t->max_rss,
                             t->heap_bytes,
                             t->heap_peak,
                             t->heap_blocks,
                             t->heap_budget,
                             t->preflight_states,
                             t->skipped_af_translation,
                             t->candidates_omitted,
                             t->threat_remotes_omitted,
                             t->threat_candidates_omitted,
                             t->event_history_evicted};
  for (size_t n = 0; n < sizeof(values) / sizeof(*values); n++)
    protocol_put(&p, values[n], 8);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_footer(FILE *f, struct sample_outcome outcome,
                         struct aggregate_counts counts, const struct sent *sent,
                         uint32_t checksum, struct fm_error *error) {
  unsigned char b[FOOTER_RECORD_SIZE], *p = b;
  *p++ = RECORD_FOOTER;
  protocol_put(&p, outcome.code, 4);
  protocol_put(&p, outcome.context_kind, 4);
  protocol_put(&p, outcome.actual, 8);
  protocol_put(&p, outcome.limit, 8);
  protocol_put(&p, counts.seen, 8);
  protocol_put(&p, counts.retained, 8);
  protocol_put(&p, counts.mapped, 8);
  protocol_put(&p, counts.flows, 8);
  protocol_put(&p, sent->flows, 8);
  protocol_put(&p, sent->candidates, 8);
  protocol_put(&p, sent->matches, 8);
  protocol_put(&p, sent->remotes, 8);
  protocol_put(&p, sent->remote_candidates, 8);
  protocol_put(&p, checksum, 4);
  return protocol_frame(f, b, p - b, NULL, error) &&
         (fflush(f) == 0 || fm_error_set(error, errno, "FMAGG4 flush"));
}

/* Ranked (or explicitly selected) flows with the candidates of those flows. */
static bool write_flows(FILE *f, const struct aggregate *a,
                        const struct ranking *ranking,
                        const struct ranked_flow *selection, size_t selected,
                        uint32_t *checksum, struct sent *sent,
                        struct fm_error *error) {
  size_t total = aggregate_counts(a).flows;
  if (total > UINT32_MAX || total > SIZE_MAX / sizeof(uint32_t))
    return fm_error_set(error, EOVERFLOW, "ranked flow count");
  /* rank_of[flow] = rank + 1 for sent flows, 0 otherwise. */
  uint32_t *rank_of = total ? fm_calloc(total, sizeof(*rank_of)) : NULL;
  if (total && !rank_of)
    return fm_error_set(error, errno, "ranked flow index");
  bool ok = true;
  for (size_t n = 0; ok && n < selected; n++) {
    struct ranked_flow rank;
    bool valid = ranking ? ranking_at(ranking, n, &rank) : true;
    if (!ranking)
      rank = selection[n];
    if (!valid || rank.flow >= total || n >= UINT32_MAX || rank_of[rank.flow]) {
      ok = fm_error_set(error, EINVAL, "ranked flow identity");
      break;
    }
    rank_of[rank.flow] = (uint32_t)n + 1;
    ok = write_flow(f, n, aggregate_flow(a, rank.flow), &rank, checksum, error);
    sent->flows += ok;
  }
  size_t candidates = aggregate_counts(a).candidates;
  for (size_t n = 0; ok && n < candidates; n++) {
    struct candidate_view value;
    if (!aggregate_candidate(a, n, &value) || value.flow >= total) {
      ok = fm_error_set(error, EINVAL, "ranked candidate identity");
      break;
    }
    if (!rank_of[value.flow])
      continue;
    ok = write_candidate(f, RECORD_CANDIDATE, rank_of[value.flow] - 1, &value,
                         true, checksum, error);
    sent->candidates += ok;
  }
  fm_free(rank_of);
  return ok;
}
static bool write_threats(FILE *f, const struct threat_summary *threats,
                          uint32_t *checksum, struct sent *sent,
                          struct fm_error *error) {
  size_t remotes = threat_summary_remote_count(threats);
  for (size_t n = 0; n < remotes; n++) {
    struct threat_remote remote;
    if (!threat_summary_remote_at(threats, n, &remote))
      return fm_error_set(error, EINVAL, "threat summary remote");
    unsigned char b[64], *p = b;
    *p++ = RECORD_THREAT_REMOTE;
    protocol_put(&p, n, 4);
    protocol_address_put(&p, remote.address);
    protocol_put(&p, remote.remote_initiated_states, 8);
    protocol_put(&p, remote.local_initiated_states, 8);
    protocol_put(&p, remote.bytes, 8);
    protocol_put(&p, remote.youngest, 4);
    if (!protocol_frame(f, b, p - b, checksum, error))
      return false;
    sent->remotes++;
  }
  size_t candidates = threat_summary_candidate_count(threats);
  for (size_t n = 0; n < candidates; n++) {
    struct threat_candidate_view view;
    if (!threat_summary_candidate_at(threats, n, &view))
      return fm_error_set(error, EINVAL, "threat summary candidate");
    if (!write_candidate(f, RECORD_THREAT_CANDIDATE, view.remote,
                         &view.candidate, false, checksum, error))
      return false;
    sent->remote_candidates++;
  }
  return true;
}

bool protocol_write_ranked(FILE *f, const struct aggregate *a,
                           const struct ranking *ranking,
                           const struct threat_summary *threats,
                           const struct event_match *matches, size_t count,
                           const struct telemetry *telemetry,
                           struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  if (!write_header(f, threats != NULL, &checksum, error) ||
      !write_flows(f, a, ranking, NULL, ranking_count(ranking), &checksum,
                   &sent, error) ||
      (threats && !write_threats(f, threats, &checksum, &sent, error)))
    return false;
  for (size_t n = 0; n < count; n++) {
    if (!write_match(f, &matches[n], &checksum, error))
      return false;
    sent.matches++;
  }
  return write_telemetry(f, telemetry, &checksum, error) &&
         write_footer(f, (struct sample_outcome){OUTCOME_SAMPLE, 0, 0, 0},
                      aggregate_counts(a), &sent, checksum, error);
}

bool protocol_write_selected(FILE *f, const struct aggregate *a,
                             const struct ranked_flow *rows, size_t count,
                             const struct telemetry *telemetry,
                             struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  return write_header(f, false, &checksum, error) &&
         write_flows(f, a, NULL, rows, count, &checksum, &sent, error) &&
         write_telemetry(f, telemetry, &checksum, error) &&
         write_footer(f, (struct sample_outcome){OUTCOME_SAMPLE, 0, 0, 0},
                      aggregate_counts(a), &sent, checksum, error);
}

bool protocol_write_refusal(FILE *f, struct sample_outcome outcome,
                            uint64_t states_seen,
                            const struct telemetry *telemetry,
                            struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  struct aggregate_counts counts = {.seen = states_seen};
  return write_header(f, false, &checksum, error) &&
         write_telemetry(f, telemetry, &checksum, error) &&
         write_footer(f, outcome, counts, &sent, checksum, error);
}

void protocol_write_failure(FILE *f, const struct fm_error *failure) {
  unsigned char b[16 + sizeof(failure->message)], *p = b;
  size_t length = strnlen(failure->message, sizeof(failure->message));
  *p++ = RECORD_FAILURE;
  protocol_put(&p, (uint32_t)failure->failure_class, 4);
  protocol_put(&p, (uint32_t)failure->code, 4);
  memcpy(p, failure->message, length);
  p += length;
  struct fm_error ignored = {0};
  if (fwrite("FMFAIL1\0", 1, 8, f) == 8)
    protocol_frame(f, b, p - b, NULL, &ignored);
  fflush(f);
}

/* FMAGG2: every aggregate flow, candidate and correlation, for the devel
 * equivalence tools only. Not used by the production request loop. */
bool protocol_write(FILE *f, const struct aggregate *a, bool deltas,
                    struct fm_error *error) {
  if (fwrite("FMAGG2\0", 1, 8, f) != 8)
    return fm_error_set(error, errno ? errno : EIO, "aggregate header");
  uint32_t checksum = 0;
  unsigned char b[FM_FRAME_MAX], *p = b;
  *p++ = 0;
  protocol_put(&p, 2, 4);
  protocol_put(&p, 15 | (deltas ? 16 : 0) | 32, 4);
  if (!protocol_frame(f, b, p - b, &checksum, error))
    return false;
  struct aggregate_counts count = aggregate_counts(a);
  for (size_t n = 0; n < count.flows; n++) {
    const struct flow *flow = aggregate_flow(a, n);
    if (!flow || n > UINT32_MAX)
      return fm_error_set(error, EINVAL, "unfinished aggregate/flow ID");
    p = b;
    *p++ = 1;
    protocol_put(&p, n, 4);
    protocol_address_put(&p, flow->local);
    protocol_address_put(&p, flow->remote);
    protocol_put(&p, flow->states, 8);
    protocol_put(&p, flow->bytes_from_remote, 8);
    protocol_put(&p, flow->bytes_to_remote, 8);
    protocol_put(&p, flow->oldest, 4);
    protocol_put(&p, flow->youngest, 4);
    protocol_put(&p, flow->remote_initiated_weight, 8);
    protocol_put(&p, flow->local_initiated_weight, 8);
    protocol_put(&p, flow->first, 8);
    if (deltas) {
      protocol_put(&p, flow->delta.bytes_from_remote, 8);
      protocol_put(&p, flow->delta.bytes_to_remote, 8);
      protocol_put(&p, flow->delta.packets, 8);
    }
    if (!protocol_frame(f, b, p - b, &checksum, error))
      return false;
  }
  for (size_t n = 0; n < count.candidates; n++) {
    struct candidate_view v;
    if (!aggregate_candidate(a, n, &v))
      return fm_error_set(error, EINVAL, "aggregate candidate");
    p = b;
    *p++ = 2;
    protocol_put(&p, v.flow, 4);
    *p++ = v.kind;
    protocol_put(&p, v.seq, 8);
    protocol_put(&p, v.weight, 8);
    protocol_put(&p, v.association, 8);
    protocol_put(&p, v.len, 2);
    memcpy(p, v.data, v.len);
    p += v.len;
    if (!protocol_frame(f, b, p - b, &checksum, error))
      return false;
  }
  for (size_t n = 0; n < aggregate_correlation_count(a); n++) {
    struct outside_key key;
    struct correlation_value value;
    if (!aggregate_correlation(a, n, &key, &value))
      return fm_error_set(error, EINVAL, "correlation record");
    p = b;
    *p++ = 3;
    *p++ = key.protocol;
    protocol_address_put(&p, key.public.a);
    protocol_put(&p, key.public.port, 2);
    protocol_address_put(&p, key.remote.a);
    protocol_put(&p, key.remote.port, 2);
    *p++ = value.has_inside;
    protocol_address_put(&p, value.inside.a);
    protocol_put(&p, value.inside.port, 2);
    protocol_put(&p, value.state_id, 8);
    protocol_put(&p, value.creator_id, 4);
    *p++ = value.ambiguous;
    protocol_put(&p, value.age, 4);
    protocol_put(&p, value.bytes_from_remote, 8);
    protocol_put(&p, value.bytes_to_remote, 8);
    *p++ = value.apparent_remote_initiated;
    memcpy(p, value.interface, FM_INTERFACE_SIZE);
    p += FM_INTERFACE_SIZE;
    memcpy(p, value.rule, FM_LABEL_SIZE);
    p += FM_LABEL_SIZE;
    if (!protocol_frame(f, b, p - b, &checksum, error))
      return false;
  }
  p = b;
  *p++ = 255;
  protocol_put(&p, count.seen, 8);
  protocol_put(&p, count.retained, 8);
  protocol_put(&p, count.mapped, 8);
  protocol_put(&p, count.flows, 8);
  protocol_put(&p, count.candidates, 8);
  protocol_put(&p, aggregate_correlation_count(a), 8);
  protocol_put(&p, checksum, 8);
  return protocol_frame(f, b, p - b, NULL, error) &&
         (fflush(f) == 0 || fm_error_set(error, errno, "aggregate flush"));
}
