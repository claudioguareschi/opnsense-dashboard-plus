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

#ifndef FM_CORRELATION_H
#define FM_CORRELATION_H
#include "state.h"
struct correlation;
struct outside_key {
  unsigned char protocol;
  struct endpoint public, remote;
};
/* The PF state behind one outside tuple. Counters are oriented by the PF
 * initiator (remote_initiated), never by the apparent-initiator heuristic. When
 * several states share the tuple the last one supplies the value and
 * `ambiguous` records whether their inside endpoints disagreed. */
struct correlation_value {
  struct endpoint inside;
  uint64_t state_id;
  uint32_t creator_id;
  uint32_t age;
  uint64_t bytes_from_remote, bytes_to_remote, packets_from_remote,
      packets_to_remote;
  char interface[FM_INTERFACE_SIZE], rule[FM_LABEL_SIZE];
  bool remote_initiated, apparent_remote_initiated;
  bool has_inside, ambiguous;
};
/* Called once per correlated state, in PF order (aggregate.c). */
typedef bool (*tuple_observer)(void *, const struct outside_key *,
                               const struct correlation_value *, struct fm_error *);
/* The tuple rule shared by every consumer: the last state wins; `ambiguous`
 * records whether the states seen so far disagreed about the inside endpoint.
 * `seen` says whether `current` already holds an earlier state. */
void correlation_merge(struct correlation_value *current, bool seen,
                       const struct correlation_value *value);
#define OUTSIDE_KEY_SIZE 39
size_t outside_key_encode(unsigned char out[OUTSIDE_KEY_SIZE], struct outside_key);
/* The full per-tuple map: devel tools and tests only (it is O(S)); production
 * streams tuples into the bounded event sample instead (event_correlation.c). */
bool correlation_observe(void *correlation, const struct outside_key *,
                         const struct correlation_value *, struct fm_error *);
struct correlation *correlation_create(struct fm_error *);
void correlation_destroy(struct correlation *);
bool correlation_add(struct correlation *, struct outside_key,
                     const struct correlation_value *, struct fm_error *);
bool correlation_lookup(const struct correlation *, struct outside_key,
                        struct correlation_value *);
size_t correlation_count(const struct correlation *);
size_t correlation_bytes(const struct correlation *);
bool correlation_at(const struct correlation *, size_t, struct outside_key *,
                    struct correlation_value *);
#endif
