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

#include "aggregate.h"
#include "alloc.h"
#include "index.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
/* One PF label slot per LAN companion tuple: labels are bounded by PF. */
typedef char label_slot[FM_LABEL_SIZE];
struct aggregate {
  const struct context *ctx;
  struct history *history;
  struct correlation *correlation;
  /* flows: value unused, id is the flow id. candidates: value holds the
   * association of the earliest state. lan: value is a slot in lan_labels.
   * pending: count/seq only. */
  struct map flows, candidates, lan, pending;
  struct flow *totals;
  size_t capacity;
  label_slot *lan_labels;
  size_t lan_label_capacity;
  uint64_t seen, retained, mapped;
  bool finished, correlate;
};
static void put32(unsigned char **p, uint32_t value) {
  for (unsigned n = 4; n; n--)
    *(*p)++ = value >> ((n - 1) * 8);
}
static uint32_t get32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static void put_addr(unsigned char **p, struct addr a) {
  *(*p)++ = a.af;
  memcpy(*p, a.b, 16);
  *p += 16;
}
static bool add_count(uint64_t *dest, uint64_t value, struct fm_error *error) {
  if (UINT64_MAX - *dest < value)
    return fm_error_set(error, EOVERFLOW, "aggregate counter overflow");
  *dest += value;
  return true;
}
struct aggregate *aggregate_create(const struct context *ctx,
                                   struct history *history, bool correlate,
                                   struct fm_error *error) {
  struct aggregate *a = fm_calloc(1, sizeof(*a));
  if (!a) {
    fm_error_set(error, errno, "aggregate allocation");
    return NULL;
  }
  a->ctx = ctx;
  a->history = history;
  a->correlate = correlate;
  a->correlation = correlation_create(error);
  if (!a->correlation) {
    fm_free(a);
    return NULL;
  }
  return a;
}
void aggregate_destroy(struct aggregate *a) {
  if (!a)
    return;
  correlation_destroy(a->correlation);
  map_clear(&a->lan);
  map_clear(&a->pending);
  map_clear(&a->flows);
  map_clear(&a->candidates);
  fm_free(a->lan_labels);
  fm_free(a->totals);
  fm_free(a);
}
static bool candidate(struct aggregate *a, uint32_t flow, unsigned char kind,
                      const void *value, size_t len, uint64_t weight,
                      uint64_t seq, uint64_t association,
                      struct fm_error *error) {
  unsigned char key[5 + CANDIDATE_VALUE_MAX], *p = key;
  if (len > CANDIDATE_VALUE_MAX)
    return fm_error_set(error, EOVERFLOW, "candidate size");
  put32(&p, flow);
  *p++ = kind;
  memcpy(p, value, len);
  struct item *i = lookup(&a->candidates, key, len + 5, true, error);
  if (!i || !add_count(&i->count, weight, error))
    return false;
  if (seq < i->seq) {
    i->seq = seq;
    i->value = association;
  }
  return true;
}
static bool lan_label_slot(struct aggregate *a, struct item *i,
                           struct fm_error *error) {
  if (i->count)
    return true;
  size_t slot = i->id;
  if (slot >= a->lan_label_capacity) {
    size_t capacity = a->lan_label_capacity ? a->lan_label_capacity * 2 : 64;
    if (capacity <= slot || capacity > SIZE_MAX / sizeof(*a->lan_labels))
      return fm_error_set(error, EOVERFLOW, "LAN label capacity");
    void *labels = fm_realloc(a->lan_labels, capacity * sizeof(*a->lan_labels));
    if (!labels)
      return fm_error_set(error, errno, "LAN label allocation");
    a->lan_labels = labels;
    a->lan_label_capacity = capacity;
  }
  i->value = slot;
  i->count = 1;
  return true;
}
static bool lan_label(struct aggregate *a, const struct state *s,
                      const struct state_view *v, struct fm_error *error) {
  if (!s->label[0] || v->pf.translated ||
      !(address_flags(a->ctx, v->pf.initiator.a) & FM_PRIVATE) ||
      !(address_flags(a->ctx, v->pf.responder.a) & FM_PUBLIC))
    return true;
  unsigned char key[FM_TUPLE_SIZE];
  state_tuple(key, v->pf.proto, v->pf.initiator, v->pf.responder);
  struct item *i = lookup(&a->lan, key, sizeof(key), true, error);
  if (!i || !lan_label_slot(a, i, error))
    return false;
  /* The last LAN companion label wins even if its state has no map pair. */
  memcpy(a->lan_labels[i->value], s->label, FM_LABEL_SIZE);
  return true;
}
static struct flow *flow_get(struct aggregate *a, const struct state_view *v,
                             uint64_t seq, uint32_t *id,
                             struct fm_error *error) {
  unsigned char key[FM_FLOW_KEY_SIZE];
  state_flow_key(key, v->local, v->remote);
  struct item *i = lookup(&a->flows, key, sizeof(key), true, error);
  if (!i)
    return NULL;
  if (i->id > UINT32_MAX) {
    fm_error_set(error, EOVERFLOW, "flow ID overflow");
    return NULL;
  }
  *id = (uint32_t)i->id;
  if (a->flows.used > a->capacity) {
    size_t capacity = a->flows.allocated;
    if (capacity > SIZE_MAX / sizeof(*a->totals)) {
      fm_error_set(error, EOVERFLOW, "flow capacity");
      return NULL;
    }
    void *rows = fm_realloc(a->totals, capacity * sizeof(*a->totals));
    if (!rows) {
      fm_error_set(error, errno, "flow allocation");
      return NULL;
    }
    a->totals = rows;
    a->capacity = capacity;
  }
  struct flow *f = &a->totals[*id];
  if (!i->count) {
    memset(f, 0, sizeof(*f));
    f->local = v->local;
    f->remote = v->remote;
    f->first = seq;
  }
  i->count++;
  return f;
}
static bool service_candidate(struct aggregate *a, uint32_t flow,
                              const struct state_view *v, uint64_t weight,
                              uint64_t seq, struct fm_error *error) {
  /* Group 0: ungrouped (protocol/port kept); 1: ICMP; Python's service names
   * start at 2. */
  unsigned group = context_service_group(a->ctx, v->pf.proto, v->service_port);
  if (state_is_icmp(v->pf.proto))
    group = 1;
  unsigned char value[7], *p = value;
  put32(&p, group);
  *p++ = group ? 0 : v->pf.proto;
  unsigned port = group ? 0 : v->service_port;
  *p++ = port >> 8;
  *p = port;
  return candidate(a, flow, CANDIDATE_SERVICE, value, sizeof(value), weight,
                   seq, ((uint64_t)v->pf.proto << 16) | v->service_port, error);
}
static bool attribution(struct aggregate *a, uint32_t flow,
                        const struct state *s, const struct state_view *v,
                        uint64_t weight, uint64_t seq, struct fm_error *error) {
  unsigned char value[4 + FM_TUPLE_SIZE + FM_LABEL_SIZE], *p = value;
  unsigned char proto = v->pf.proto;
  if (!candidate(a, flow, CANDIDATE_PROTOCOL, &proto, 1, 1, seq, 0, error))
    return false;
  if (v->has_inside) {
    put_addr(&p, v->inside.a);
    if (!candidate(a, flow, CANDIDATE_INSIDE_HOST, value, 17, weight, seq, 0,
                   error))
      return false;
  }
  if (s->original_interface[0] &&
      !candidate(a, flow, CANDIDATE_EGRESS_INTERFACE, s->original_interface,
                 strlen(s->original_interface), weight, seq, 0, error))
    return false;
  if (!service_candidate(a, flow, v, weight, seq, error))
    return false;
  if (v->apparent_remote_initiated) {
    p = value;
    *p++ = v->pf.proto;
    put_addr(&p, v->has_inside ? v->inside.a : v->local);
    unsigned port = state_is_icmp(v->pf.proto) ? 0
                    : v->remote_initiated
                        ? (v->has_inside ? v->inside.port : v->pf.responder.port)
                        : v->service_port;
    *p++ = port >> 8;
    *p = port;
    if (!candidate(a, flow, CANDIDATE_REMOTE_TARGET, value, 20, weight, seq, 0,
                   error))
      return false;
  }
  if (!v->has_inside)
    return !s->label[0] ||
           candidate(a, flow, CANDIDATE_RULE_LABEL, s->label, strlen(s->label),
                     1, seq, 0, error);
  /* Rule labels of inside flows are resolved in aggregate_finish: a LAN-side
   * companion state's label wins over the outside state's own label. */
  p = value;
  put32(&p, flow);
  p += state_tuple(p, v->pf.proto, v->inside, v->remote_endpoint);
  size_t length = strlen(s->label);
  memcpy(p, s->label, length);
  p += length;
  struct item *i = lookup(&a->pending, value, p - value, true, error);
  if (!i || !add_count(&i->count, 1, error))
    return false;
  if (seq < i->seq)
    i->seq = seq;
  return true;
}
static bool add_correlation(struct aggregate *a, const struct state *s,
                            const struct state_view *v,
                            struct fm_error *error) {
  struct endpoint public = s->pf_direction == FM_OUT ? v->pf.initiator
                           : v->pf.translated        ? v->pf.untranslated
                                                     : v->pf.responder;
  if (v->pf.translated && !address_equal(public.a, v->local))
    return true;
  if (!(address_flags(a->ctx, v->remote_endpoint.a) & FM_PUBLIC))
    return true;
  bool remote = v->remote_initiated;
  struct correlation_value value = {
      .state_id = s->id,
      .creator_id = s->creator,
      .age = s->age,
      .bytes_from_remote = state_bytes_from_remote(s, remote),
      .bytes_to_remote = state_bytes_to_remote(s, remote),
      .packets_from_remote = state_packets_from_remote(s, remote),
      .packets_to_remote = state_packets_to_remote(s, remote),
      .remote_initiated = remote,
      .apparent_remote_initiated = v->apparent_remote_initiated,
      .has_inside = v->has_inside};
  memcpy(value.interface, s->original_interface, sizeof(value.interface));
  memcpy(value.rule, s->label, sizeof(value.rule));
  if (v->has_inside)
    value.inside = v->inside;
  return correlation_add(
      a->correlation,
      (struct outside_key){v->pf.proto, public, v->remote_endpoint}, &value,
      error);
}
bool aggregate_add(struct aggregate *a, const struct state *s,
                   struct fm_error *error) {
  if (a->finished)
    return fm_error_set(error, EINVAL, "aggregate already finished");
  struct state_view v;
  if (!state_normalize(s, a->ctx, &v, error))
    return false;
  uint64_t seq = a->seen++;
  if (!v.retained)
    return true;
  a->retained++;
  if (!lan_label(a, s, &v, error))
    return false;
  if (!v.mapped)
    return true;
  uint32_t id;
  struct flow *f = flow_get(a, &v, seq, &id, error);
  if (!f)
    return false;
  struct state_delta delta = {0};
  if (a->history &&
      !history_observe(a->history, s, v.remote_initiated, &delta, error))
    return false;
  uint64_t weight = delta.bytes_from_remote;
  if (!add_count(&weight, delta.bytes_to_remote, error) ||
      !add_count(&weight, 1, error))
    return false;
  if (!add_count(&f->bytes_from_remote,
                 state_bytes_from_remote(s, v.remote_initiated), error) ||
      !add_count(&f->bytes_to_remote,
                 state_bytes_to_remote(s, v.remote_initiated), error) ||
      !add_count(&f->delta.bytes_from_remote, delta.bytes_from_remote, error) ||
      !add_count(&f->delta.bytes_to_remote, delta.bytes_to_remote, error) ||
      !add_count(&f->delta.packets, delta.packets, error) ||
      !add_count(v.apparent_remote_initiated ? &f->remote_initiated_weight
                                             : &f->local_initiated_weight,
                 weight, error))
    return false;
  if (a->correlate && !add_correlation(a, s, &v, error))
    return false;
  f->states++;
  if (!add_count(v.apparent_remote_initiated ? &f->remote_initiated_states
                                             : &f->local_initiated_states,
                 1, error))
    return false;
  if (f->states == 1 || s->age < f->youngest)
    f->youngest = s->age;
  a->mapped++;
  if (s->age > f->oldest)
    f->oldest = s->age;
  return attribution(a, id, s, &v, weight, seq, error);
}
bool aggregate_finish(struct aggregate *a, struct fm_error *error) {
  if (a->finished)
    return fm_error_set(error, EINVAL, "aggregate already finished");
  for (size_t n = 0; n < a->pending.used; n++) {
    const struct item *i = a->pending.order[n];
    const struct item *l = map_find(&a->lan, i->key + 4, FM_TUPLE_SIZE);
    const char *label = l ? a->lan_labels[l->value]
                          : (const char *)i->key + 4 + FM_TUPLE_SIZE;
    size_t length = l ? strnlen(label, FM_LABEL_SIZE)
                      : i->len - 4 - FM_TUPLE_SIZE;
    if (length && !candidate(a, get32(i->key), CANDIDATE_RULE_LABEL, label,
                             length, i->count, i->seq, 0, error))
      return false;
  }
  a->finished = true;
  return true;
}
struct aggregate_counts aggregate_counts(const struct aggregate *a) {
  return (struct aggregate_counts){a->seen, a->retained, a->mapped,
                                   a->flows.used, a->candidates.used};
}
const struct flow *aggregate_flow(const struct aggregate *a, size_t n) {
  return a->finished && n < a->flows.used ? &a->totals[n] : NULL;
}
bool aggregate_candidate(const struct aggregate *a, size_t n,
                         struct candidate_view *v) {
  if (!a->finished || n >= a->candidates.used)
    return false;
  const struct item *i = a->candidates.order[n];
  *v = (struct candidate_view){get32(i->key), i->key[4], i->key + 5, i->len - 5,
                               i->seq,        i->count,  i->value};
  return true;
}
bool aggregate_correlation(const struct aggregate *a, size_t n,
                           struct outside_key *key,
                           struct correlation_value *value) {
  return a->finished && correlation_at(a->correlation, n, key, value);
}
size_t aggregate_correlation_count(const struct aggregate *a) {
  return a->finished ? correlation_count(a->correlation) : 0;
}
bool aggregate_correlation_lookup(const struct aggregate *a,
                                  struct outside_key key,
                                  struct correlation_value *value) {
  return a->finished && correlation_lookup(a->correlation, key, value);
}
size_t aggregate_bytes(const struct aggregate *a) {
  size_t bytes = sizeof(*a) + a->capacity * sizeof(*a->totals) +
                 a->lan_label_capacity * sizeof(*a->lan_labels);
  bytes += map_bytes(&a->flows) + map_bytes(&a->candidates) +
           map_bytes(&a->lan) + map_bytes(&a->pending);
  return bytes + correlation_bytes(a->correlation);
}
