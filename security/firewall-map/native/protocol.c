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
  if (len > UINT32_MAX)
    return fm_error_set(error, EOVERFLOW, "frame size");
  unsigned char size[4], *p = size;
  protocol_put(&p, len, 4);
  if (fwrite(size, 1, 4, f) != 4 || (len && fwrite(data, 1, len, f) != len))
    return fm_error_set(error, errno ? errno : EIO, "frame write");
  if (checksum) {
    *checksum = crc(*checksum, size, 4);
    *checksum = crc(*checksum, data, len);
  }
  return true;
}
static bool write_flow(FILE *f, size_t id, const struct flow *flow, bool deltas,
                       uint32_t *crc, struct fm_error *error) {
  if (!flow || id > UINT32_MAX)
    return fm_error_set(error, EINVAL, "unfinished aggregate/flow ID");
  unsigned char b[128], *p = b;
  *p++ = 1;
  protocol_put(&p, id, 4);
  protocol_address_put(&p, flow->local);
  protocol_address_put(&p, flow->remote);
  protocol_put(&p, flow->states, 8);
  protocol_put(&p, flow->toward, 8);
  protocol_put(&p, flow->away, 8);
  protocol_put(&p, flow->oldest, 4);
  protocol_put(&p, flow->youngest, 4);
  protocol_put(&p, flow->remote_started, 8);
  protocol_put(&p, flow->local_started, 8);
  protocol_put(&p, flow->first, 8);
  if (deltas) {
    protocol_put(&p, flow->delta.toward, 8);
    protocol_put(&p, flow->delta.away, 8);
    protocol_put(&p, flow->delta.packets, 8);
  }
  return protocol_frame(f, b, p - b, crc, error);
}
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
  for (size_t n = 0; n < count.flows; n++)
    if (!write_flow(f, n, aggregate_flow(a, n), deltas, &checksum, error))
      return false;
  for (size_t n = 0; n < count.candidates; n++) {
    struct candidate_view v;
    if (!aggregate_candidate(a, n, &v) || v.len > sizeof(b) - 32)
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
    protocol_put(&p, value.bytes[0], 8);
    protocol_put(&p, value.bytes[1], 8);
    *p++ = value.remote_started;
    memcpy(p, value.interface, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    memcpy(p, value.rule, FM_LABEL_SIZE); p += FM_LABEL_SIZE;
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

static void put_double(unsigned char **p, double value) {
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  protocol_put(p, bits, 8);
}

static bool write_ranked(FILE *f, const struct aggregate *a,
                           const struct ranking *ranking,
                           const struct ranked_flow *selection, size_t selection_count,
                           const struct threat_summary *threat_summary,
                           const struct event_match *matches,
                           size_t match_count, struct fm_error *error) {
  if (fwrite("FMAGG3\0\0", 1, 8, f) != 8)
    return fm_error_set(error, errno ? errno : EIO, "ranked aggregate header");
  size_t total_flows = aggregate_counts(a).flows;
  size_t selected = ranking ? ranking_count(ranking) : selection_count;
  if (total_flows > UINT32_MAX || total_flows > SIZE_MAX / sizeof(uint32_t))
    return fm_error_set(error, EOVERFLOW, "ranked flow count");
  uint32_t *ranked = total_flows ? malloc(total_flows * sizeof(*ranked)) : NULL;
  if (total_flows && !ranked)
    return fm_error_set(error, errno, "ranked flow index");
  for (size_t n = 0; n < total_flows; n++) ranked[n] = UINT32_MAX;
  uint32_t checksum = 0;
  unsigned char b[FM_FRAME_MAX], *p = b;
  *p++ = 0;
  protocol_put(&p, 3, 4);
  protocol_put(&p, 1 | (threat_summary ? 2 : 0) | 4, 4);
  if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
  for (size_t n = 0; n < selected; n++) {
    struct ranked_flow rank;
    bool valid = ranking ? ranking_at(ranking, n, &rank) : true;
    if (!ranking) rank = selection[n];
    if (!valid || rank.flow >= total_flows || n > UINT32_MAX) {
      fm_error_set(error, EINVAL, "ranked flow identity");
      goto fail;
    }
    ranked[rank.flow] = (uint32_t)n;
    const struct flow *flow = aggregate_flow(a, rank.flow);
    p = b;
    *p++ = 1;
    protocol_put(&p, n, 4);
    protocol_address_put(&p, flow->local);
    protocol_address_put(&p, flow->remote);
    protocol_put(&p, flow->states, 8);
    protocol_put(&p, flow->toward, 8);
    protocol_put(&p, flow->away, 8);
    protocol_put(&p, flow->oldest, 4);
    protocol_put(&p, flow->youngest, 4);
    protocol_put(&p, flow->remote_started, 8);
    protocol_put(&p, flow->local_started, 8);
    protocol_put(&p, flow->first, 8);
    protocol_put(&p, flow->delta.toward, 8);
    protocol_put(&p, flow->delta.away, 8);
    protocol_put(&p, flow->delta.packets, 8);
    put_double(&p, rank.rate_in);
    put_double(&p, rank.rate_out);
    put_double(&p, rank.packet_rate);
    put_double(&p, rank.activity);
    put_double(&p, rank.score);
    if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
  }
  size_t candidate_count = 0;
  struct aggregate_counts counts = aggregate_counts(a);
  for (size_t n = 0; n < counts.candidates; n++) {
    struct candidate_view value;
    if (!aggregate_candidate(a, n, &value) || value.flow >= total_flows) {
      fm_error_set(error, EINVAL, "ranked candidate identity");
      goto fail;
    }
    if (ranked[value.flow] == UINT32_MAX) continue;
    p = b;
    *p++ = 2;
    protocol_put(&p, ranked[value.flow], 4);
    *p++ = value.kind;
    protocol_put(&p, value.seq, 8);
    protocol_put(&p, value.weight, 8);
    protocol_put(&p, value.association, 8);
    protocol_put(&p, value.len, 2);
    if (value.len > sizeof(b) - (size_t)(p - b)) {
      fm_error_set(error, EOVERFLOW, "ranked candidate size");
      goto fail;
    }
    memcpy(p, value.data, value.len);
    p += value.len;
    if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
    candidate_count++;
  }
  if (threat_summary) {
    size_t remote_count = threat_summary_remote_count(threat_summary);
    size_t remote_candidate_count = threat_summary_candidate_count(threat_summary);
    for (size_t n = 0; n < remote_count; n++) {
      struct threat_remote remote;
      if (!threat_summary_remote_at(threat_summary, n, &remote)) {
        fm_error_set(error, EINVAL, "threat summary remote"); goto fail;
      }
      p = b;
      *p++ = 3;
      protocol_put(&p, n, 4);
      protocol_address_put(&p, remote.address);
      protocol_put(&p, remote.inbound, 8);
      protocol_put(&p, remote.outbound, 8);
      protocol_put(&p, remote.bytes, 8);
      protocol_put(&p, remote.youngest, 4);
      if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
    }
    for (size_t n = 0; n < remote_candidate_count; n++) {
      struct threat_candidate_view view;
      if (!threat_summary_candidate_at(threat_summary, n, &view)) {
        fm_error_set(error, EINVAL, "threat summary candidate"); goto fail;
      }
      struct candidate_view value = view.candidate;
      p = b;
      *p++ = 4;
      protocol_put(&p, view.remote, 4);
      *p++ = value.kind;
      protocol_put(&p, value.seq, 8);
      protocol_put(&p, value.association, 8);
      protocol_put(&p, value.len, 2);
      if (value.len > sizeof(b) - (size_t)(p - b)) {
        fm_error_set(error, EOVERFLOW, "threat candidate size"); goto fail;
      }
      memcpy(p, value.data, value.len); p += value.len;
      if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
    }
  }
  for (size_t n = 0; n < match_count; n++) {
    const struct event_match *match = &matches[n];
    p = b;
    *p++ = 5;
    protocol_put(&p, match->id, 2);
    *p++ = match->kind;
    *p++ = match->key.protocol;
    protocol_address_put(&p, match->key.public.a);
    protocol_put(&p, match->key.public.port, 2);
    protocol_address_put(&p, match->key.remote.a);
    protocol_put(&p, match->key.remote.port, 2);
    *p++ = match->value.has_inside;
    protocol_address_put(&p, match->value.inside.a);
    protocol_put(&p, match->value.inside.port, 2);
    protocol_put(&p, match->value.state_id, 8);
    protocol_put(&p, match->value.creator_id, 4);
    *p++ = match->value.ambiguous;
    protocol_put(&p, match->value.age, 4);
    protocol_put(&p, match->value.bytes[0], 8);
    protocol_put(&p, match->value.bytes[1], 8);
    *p++ = match->value.remote_started;
    memcpy(p, match->value.interface, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    memcpy(p, match->value.rule, FM_LABEL_SIZE); p += FM_LABEL_SIZE;
    if (!protocol_frame(f, b, p - b, &checksum, error)) goto fail;
  }
  p = b;
  *p++ = 255;
  protocol_put(&p, counts.seen, 8);
  protocol_put(&p, counts.retained, 8);
  protocol_put(&p, counts.mapped, 8);
  protocol_put(&p, total_flows, 8);
  protocol_put(&p, selected, 8);
  protocol_put(&p, candidate_count, 8);
  protocol_put(&p, match_count, 8);
  protocol_put(&p, threat_summary ? threat_summary_remote_count(threat_summary) : 0, 8);
  protocol_put(&p, threat_summary ? threat_summary_candidate_count(threat_summary) : 0, 8);
  protocol_put(&p, checksum, 8);
  free(ranked);
  return protocol_frame(f, b, p - b, NULL, error) &&
         (fflush(f) == 0 || fm_error_set(error, errno, "ranked aggregate flush"));
fail:
  free(ranked);
  return false;
}

bool protocol_write_ranked(FILE *f, const struct aggregate *a,
                           const struct ranking *r, const struct threat_summary *t,
                           const struct event_match *m, size_t count, struct fm_error *error) {
  return write_ranked(f, a, r, NULL, 0, t, m, count, error);
}

bool protocol_write_selected(FILE *f, const struct aggregate *a,
                             const struct ranked_flow *rows, size_t count,
                             struct fm_error *error) {
  return write_ranked(f, a, NULL, rows, count, NULL, NULL, 0, error);
}
