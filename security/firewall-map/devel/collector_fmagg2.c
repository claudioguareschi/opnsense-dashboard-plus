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

/* Devel-only FMAGG2 aggregate dump (every flow, candidate and correlation) used
 * by devel/collector_sample.c and the equivalence tools. Never linked into the
 * installed helper. */
#include "collector_fmagg2.h"
#include <errno.h>
#include <string.h>

/* FMAGG2: every aggregate flow, candidate and correlation, for the devel
 * equivalence tools only. Not used by the production request loop. */
bool protocol_write(FILE *f, const struct aggregate *a, const struct correlation *c, bool deltas,
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
  for (size_t n = 0; n < correlation_count(c); n++) {
    struct outside_key key;
    struct correlation_value value;
    if (!correlation_at(c, n, &key, &value))
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
  protocol_put(&p, correlation_count(c), 8);
  protocol_put(&p, checksum, 8);
  return protocol_frame(f, b, p - b, NULL, error) &&
         (fflush(f) == 0 || fm_error_set(error, errno, "aggregate flush"));
}
