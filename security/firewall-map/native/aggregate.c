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
#include "index.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct aggregate {
  const struct context *ctx;
  struct history *history;
  struct correlation *correlation;
  struct map flows, candidates, lan, pending;
  struct flow *totals;
  size_t capacity;
  uint64_t seen, retained, mapped;
  bool finished;
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
                                   struct history *history,
                                   struct fm_error *error) {
  struct aggregate *a = calloc(1, sizeof(*a));
  if (!a) {
    fm_error_set(error, errno, "aggregate allocation");
    return NULL;
  }
  a->ctx = ctx;
  a->history = history;
  a->correlation = correlation_create(error);
  if (!a->correlation) { free(a); return NULL; }
  return a;
}
void aggregate_destroy(struct aggregate *a) {
  if (!a)
    return;
  correlation_destroy(a->correlation);
  for (size_t n = 0; n < a->lan.used; n++)
    free((void *)(uintptr_t)a->lan.order[n]->value);
  map_clear(&a->lan);
  map_clear(&a->pending);
  map_clear(&a->flows);
  map_clear(&a->candidates);
  free(a->totals);
  free(a);
}
static bool candidate(struct aggregate *a, uint32_t flow, unsigned char kind,
                      const void *value, size_t len, uint64_t weight,
                      uint64_t seq, uint64_t association,
                      struct fm_error *error) {
  unsigned char key[256], *p = key;
  if (len > sizeof(key) - 5)
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
static bool lan_label(struct aggregate *a, const struct state *s,
                      const struct state_view *v, struct fm_error *error) {
  if (!s->label[0] || v->has_nat ||
      !(address_flags(a->ctx, v->src.a) & FM_PRIVATE) ||
      !(address_flags(a->ctx, v->dst.a) & FM_PUBLIC))
    return true;
  unsigned char key[39];
  state_tuple(key, v->proto, v->src, v->dst);
  struct item *i = lookup(&a->lan, key, sizeof(key), true, error);
  if (!i)
    return false;
  /* The last LAN companion label wins even if its state has no map pair. */
  char *label = strdup(s->label);
  if (!label)
    return fm_error_set(error, errno, "LAN label allocation");
  if (i->count)
    free((void *)(uintptr_t)i->value);
  i->value = (uintptr_t)label;
  i->count = 1;
  return true;
}
static struct flow *flow_get(struct aggregate *a, const struct state_view *v,
                             uint64_t seq, uint32_t *id,
                             struct fm_error *error) {
  unsigned char key[34], *p = key;
  put_addr(&p, v->local);
  put_addr(&p, v->remote);
  struct item *i = lookup(&a->flows, key, sizeof(key), true, error);
  if (!i)
    return NULL;
  if (i->value > UINT32_MAX) {
    fm_error_set(error, EOVERFLOW, "flow ID overflow");
    return NULL;
  }
  *id = i->value;
  if (a->flows.used > a->capacity) {
    size_t capacity = a->flows.allocated;
    if (capacity > SIZE_MAX / sizeof(*a->totals)) {
      fm_error_set(error, EOVERFLOW, "flow capacity");
      return NULL;
    }
    void *rows = realloc(a->totals, capacity * sizeof(*a->totals));
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
  unsigned group = 0;
  for (size_t n = 0; n < a->ctx->ns; n++)
    if (a->ctx->services[n].proto == v->proto &&
        a->ctx->services[n].port == v->service_port)
      group = a->ctx->services[n].group;
  if (state_is_icmp(v->proto))
    group = 1;
  unsigned char value[7], *p = value;
  put32(&p, group);
  *p++ = group ? 0 : v->proto;
  unsigned port = group ? 0 : v->service_port;
  *p++ = port >> 8;
  *p = port;
  return candidate(a, flow, 4, value, sizeof(value), weight, seq,
                   ((uint64_t)v->proto << 16) | v->service_port, error);
}
static bool attribution(struct aggregate *a, uint32_t flow,
                        const struct state *s, const struct state_view *v,
                        uint64_t weight, uint64_t seq, struct fm_error *error) {
  unsigned char value[256], *p = value, proto = v->proto;
  if (!candidate(a, flow, 1, &proto, 1, 1, seq, 0, error))
    return false;
  if (v->has_inside) {
    put_addr(&p, v->inside.a);
    if (!candidate(a, flow, 2, value, 17, weight, seq, 0, error))
      return false;
  }
  if (s->orig[0] &&
      !candidate(a, flow, 3, s->orig, strlen(s->orig), weight, seq, 0, error))
    return false;
  if (!service_candidate(a, flow, v, weight, seq, error))
    return false;
  if (v->remote_started) {
    p = value;
    *p++ = v->proto;
    put_addr(&p, v->has_inside ? v->inside.a : v->local);
    unsigned port = state_is_icmp(v->proto) ? 0
                    : v->src_remote
                        ? (v->has_inside ? v->inside.port : v->dst.port)
                        : v->service_port;
    *p++ = port >> 8;
    *p = port;
    if (!candidate(a, flow, 5, value, 20, weight, seq, 0, error))
      return false;
  }
  if (!v->has_inside)
    return !s->label[0] ||
           candidate(a, flow, 6, s->label, strlen(s->label), 1, seq, 0, error);
  p = value;
  put32(&p, flow);
  p += state_tuple(p, v->proto, v->inside, v->far);
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
  struct endpoint public = s->direction == FM_OUT
                               ? v->src
                               : v->has_nat ? v->nat : v->dst;
  if (v->has_nat && !address_equal(public.a, v->local))
    return true;
  struct endpoint remote = v->src_remote ? v->src : v->dst;
  if (!(address_flags(a->ctx, remote.a) & FM_PUBLIC))
    return true;
  struct correlation_value value = {.state_id = s->id,
                                    .creator_id = s->creator,
                                    .age = s->age,
                                    .bytes = {s->bytes[0], s->bytes[1]},
                                    .remote_started = v->remote_started,
                                    .has_inside = v->has_inside};
  memcpy(value.interface, s->orig, sizeof(value.interface));
  memcpy(value.rule, s->label, sizeof(value.rule));
  if (v->has_inside) value.inside = v->inside;
  return correlation_add(a->correlation,
                         (struct outside_key){v->proto, public, remote},
                         &value, error);
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
      !history_observe(a->history, s, v.src_remote, &delta, error))
    return false;
  uint64_t weight = delta.toward;
  if (!add_count(&weight, delta.away, error) || !add_count(&weight, 1, error))
    return false;
  if (!add_count(&f->toward, s->bytes[v.src_remote ? 0 : 1], error) ||
      !add_count(&f->away, s->bytes[v.src_remote ? 1 : 0], error) ||
      !add_count(&f->delta.toward, delta.toward, error) ||
      !add_count(&f->delta.away, delta.away, error) ||
      !add_count(&f->delta.packets, delta.packets, error) ||
      !add_count(v.remote_started ? &f->remote_started : &f->local_started,
                 weight, error))
    return false;
  if (!add_correlation(a, s, &v, error))
    return false;
  f->states++;
  if (!add_count(v.remote_started ? &f->remote_states : &f->local_states, 1, error))
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
    struct item *i = a->pending.order[n];
    struct item *l = lookup(&a->lan, i->key + 4, 39, false, error);
    const void *label = l ? (const void *)(uintptr_t)l->value : i->key + 43;
    size_t length = l ? strlen(label) : i->len - 43;
    if (length && !candidate(a, get32(i->key), 6, label, length, i->count,
                             i->seq, 0, error))
      return false;
  }
  a->finished = true;
  return true;
}
const char *aggregate_rule(const struct aggregate *a,
                           const struct state_view *v, const char *fallback) {
  if (!v->has_inside)
    return fallback;
  unsigned char key[39];
  state_tuple(key, v->proto, v->inside, v->far);
  struct item *l = lookup((struct map *)&a->lan, key, sizeof(key), false, NULL);
  return l ? (const char *)(uintptr_t)l->value : fallback;
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
  struct item *i = a->candidates.order[n];
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
  size_t bytes = sizeof(*a) + a->capacity * sizeof(*a->totals);
  bytes += map_bytes(&a->flows) + map_bytes(&a->candidates) +
           map_bytes(&a->lan) + map_bytes(&a->pending);
  bytes += correlation_bytes(a->correlation);
  for (size_t n = 0; n < a->lan.used; n++)
    bytes += strlen((const char *)(uintptr_t)a->lan.order[n]->value) + 1;
  return bytes;
}
