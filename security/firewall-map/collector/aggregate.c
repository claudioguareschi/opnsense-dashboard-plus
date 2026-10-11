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
#include "lifetime.h"
#include "alloc.h"
#include "profile.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
/* One PF label slot per LAN companion tuple: labels are bounded by PF. */
typedef char label_slot[FM_LABEL_SIZE];
/* One attribution value of one tracked flow. A (flow, kind) holds at most
 * CANDIDATE_SLOTS values, linked through `next`; when it is full, a new value
 * replaces the lightest one and inherits its weight as error (Space-Saving),
 * so the heaviest values survive whatever their order. */
struct candidate {
  uint64_t weight, error, seq, association, hash;
  uint32_t flow, next; /* next: index + 1 of the group's next value, 0 at the end */
  unsigned char kind, len;
  unsigned char value[CANDIDATE_VALUE_MAX];
};
struct groups {
  uint32_t head[CANDIDATE_KIND_COUNT];
  /* per kind: the entry (index + 1) the flow's latest value went to, so a
   * repeated value skips the keyed table lookup (see candidate()) */
  uint32_t last[CANDIDATE_KIND_COUNT];
  unsigned char count[CANDIDATE_KIND_COUNT];
};
struct aggregate {
  const struct context *ctx;
  struct history *history;
  tuple_observer observe;
  void *observer;
  const struct classifier *classifier;
  struct admission admission;
  bool limited;
  /* flows: tracked flows (value unused, id is the flow id). lan: value is a
   * slot in lan_labels. pending: count/seq only. */
  struct map flows, lan, pending;
  struct flow *totals;
  struct groups *groups;
  size_t capacity;
  label_slot *lan_labels;
  size_t lan_label_capacity;
  /* candidates: entries in first-seen order, indexed by an open-addressed
   * table (entry index + 1, 0 empty) of a power-of-two size */
  struct candidate *candidates;
  size_t candidate_count, candidate_capacity;
  uint32_t *slots;
  size_t slot_mask;
  uint64_t seen, retained, mapped, skipped_af_translation, forced, forced_refused,
      candidate_evictions, join_refused;
  bool exhausted, finished;
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
                                   struct history *history, tuple_observer observe,
                                   void *observer, struct fm_error *error) {
  struct aggregate *a = fm_calloc(1, sizeof(*a));
  if (!a) {
    fm_error_set(error, errno, "aggregate allocation");
    return NULL;
  }
  a->ctx = ctx;
  a->history = history;
  a->observe = observe;
  a->observer = observer;
  return a;
}
void aggregate_set_classifier(struct aggregate *a, const struct classifier *classifier) {
  a->classifier = classifier;
}
void aggregate_set_admission(struct aggregate *a, const struct admission *admission) {
  a->admission = *admission;
  a->limited = true;
}
void aggregate_destroy(struct aggregate *a) {
  if (!a)
    return;
  map_clear(&a->lan);
  map_clear(&a->pending);
  map_clear(&a->flows);
  fm_free(a->lan_labels);
  fm_free(a->totals);
  fm_free(a->groups);
  fm_free(a->candidates);
  fm_free(a->slots);
  fm_free(a);
}

/* The bounded candidate table. */
static size_t candidate_key(unsigned char *key, uint32_t flow, unsigned char kind,
                            const void *value, size_t len) {
  unsigned char *p = key;
  put32(&p, flow);
  *p++ = kind;
  memcpy(p, value, len);
  return len + 5;
}
static bool candidate_is(const struct candidate *c, uint64_t hash, uint32_t flow,
                         unsigned char kind, const void *value, size_t len) {
  return c->hash == hash && c->flow == flow && c->kind == kind && c->len == len &&
         !memcmp(c->value, value, len);
}
static size_t slot_find(const struct aggregate *a, uint64_t hash, uint32_t flow,
                        unsigned char kind, const void *value, size_t len) {
  size_t n = hash & a->slot_mask;
  while (a->slots[n] && !candidate_is(&a->candidates[a->slots[n] - 1], hash, flow, kind, value, len))
    n = (n + 1) & a->slot_mask;
  return n;
}
static void slot_remove(struct aggregate *a, size_t n) {
  size_t hole = n, next = (n + 1) & a->slot_mask;
  while (a->slots[next]) {
    size_t want = a->candidates[a->slots[next] - 1].hash & a->slot_mask;
    if (((next - want) & a->slot_mask) >= ((next - hole) & a->slot_mask)) {
      a->slots[hole] = a->slots[next];
      hole = next;
    }
    next = (next + 1) & a->slot_mask;
  }
  a->slots[hole] = 0;
}
/* Room for one more entry: the entry array and an index at most half full. */
static bool candidate_reserve(struct aggregate *a, struct fm_error *error) {
  if (a->candidate_count == a->candidate_capacity) {
    size_t next = a->candidate_capacity ? a->candidate_capacity * 2 : 256;
    if (next > UINT32_MAX - 1 || next > SIZE_MAX / sizeof(*a->candidates))
      return fm_error_set(error, EOVERFLOW, "candidate capacity");
    void *grown = fm_realloc(a->candidates, next * sizeof(*a->candidates));
    if (!grown)
      return fm_error_set(error, errno, "candidate allocation");
    a->candidates = grown;
    a->candidate_capacity = next;
  }
  if (a->slots && (a->candidate_count + 1) * 2 <= a->slot_mask + 1)
    return true;
  size_t size = a->slots ? (a->slot_mask + 1) * 2 : 512;
  uint32_t *slots = fm_calloc(size, sizeof(*slots));
  if (!slots)
    return fm_error_set(error, errno, "candidate index allocation");
  fm_free(a->slots);
  a->slots = slots;
  a->slot_mask = size - 1;
  for (size_t n = 0; n < a->candidate_count; n++) {
    size_t slot = a->candidates[n].hash & a->slot_mask;
    while (a->slots[slot])
      slot = (slot + 1) & a->slot_mask;
    a->slots[slot] = (uint32_t)n + 1;
  }
  return true;
}
static bool lighter(const struct candidate *x, const struct candidate *y) {
  if (x->weight != y->weight) return x->weight < y->weight;
  if (x->seq != y->seq) return x->seq > y->seq; /* the newer value goes first */
  return x->len != y->len ? x->len < y->len : memcmp(x->value, y->value, x->len) < 0;
}
/* A value already in the table: its weight grows, and the earliest
 * observation keeps the first-seen order and the association. */
static bool candidate_hit(struct candidate *c, uint64_t weight, uint64_t seq, uint64_t association,
                          struct fm_error *error) {
  if (!add_count(&c->weight, weight, error))
    return false;
  if (seq < c->seq) {
    c->seq = seq;
    c->association = association;
  }
  return true;
}
static bool candidate(struct aggregate *a, uint32_t flow, unsigned char kind,
                      const void *value, size_t len, uint64_t weight,
                      uint64_t seq, uint64_t association,
                      struct fm_error *error) {
  if (len > CANDIDATE_VALUE_MAX)
    return fm_error_set(error, EOVERFLOW, "candidate size");
  if (!kind || kind > CANDIDATE_KIND_COUNT)
    return fm_error_set(error, EINVAL, "candidate kind");
  struct groups *g = &a->groups[flow];
  unsigned k = kind - 1;
  /* the flow's previous value of this kind, again: a (flow, kind, value) is
   * in the table at most once, so the entry that still holds exactly it is
   * the one the keyed lookup below would find (an evicted or replaced entry
   * no longer matches and takes the lookup) */
  if (g->last[k]) {
    struct candidate *c = &a->candidates[g->last[k] - 1];
    if (c->flow == flow && c->kind == kind && c->len == len && !memcmp(c->value, value, len))
      return candidate_hit(c, weight, seq, association, error);
  }
  unsigned char key[5 + CANDIDATE_VALUE_MAX];
  uint64_t hash = index_hash(key, candidate_key(key, flow, kind, value, len));
  if (a->slots) {
    size_t slot = slot_find(a, hash, flow, kind, value, len);
    if (a->slots[slot]) {
      g->last[k] = a->slots[slot];
      return candidate_hit(&a->candidates[a->slots[slot] - 1], weight, seq, association, error);
    }
  }
  if (g->count[k] < CANDIDATE_SLOTS &&
      (!a->limited || a->candidate_count < a->admission.candidate_limit)) {
    if (!candidate_reserve(a, error))
      return false;
    size_t n = a->candidate_count++;
    struct candidate *c = &a->candidates[n];
    *c = (struct candidate){.weight = weight, .seq = seq, .association = association,
                            .hash = hash, .flow = flow, .next = g->head[k],
                            .kind = kind, .len = (unsigned char)len};
    memcpy(c->value, value, len);
    g->head[k] = (uint32_t)n + 1;
    g->count[k]++;
    a->slots[slot_find(a, hash, flow, kind, value, len)] = (uint32_t)n + 1;
    g->last[k] = (uint32_t)n + 1;
    return true;
  }
  /* full: replace the group's lightest value (an empty group of a full table
   * has none, and the value is dropped) */
  a->candidate_evictions++;
  a->totals[flow].evicted = true;
  struct candidate *lightest = NULL;
  for (uint32_t n = g->head[k]; n; n = a->candidates[n - 1].next)
    if (!lightest || lighter(&a->candidates[n - 1], lightest))
      lightest = &a->candidates[n - 1];
  if (!lightest)
    return true;
  slot_remove(a, slot_find(a, lightest->hash, lightest->flow, lightest->kind, lightest->value,
                           lightest->len));
  uint64_t floor = lightest->weight;
  lightest->error = floor;
  lightest->weight = UINT64_MAX - floor < weight ? UINT64_MAX : floor + weight;
  lightest->seq = seq;
  lightest->association = association;
  lightest->hash = hash;
  lightest->len = (unsigned char)len;
  memcpy(lightest->value, value, len);
  a->slots[slot_find(a, hash, flow, kind, value, len)] = (uint32_t)(lightest - a->candidates) + 1;
  g->last[k] = (uint32_t)(lightest - a->candidates) + 1;
  return true;
}

/* The budgeted LAN-companion join: lan and pending entries together stay
 * under join_limit; a refused entry makes the sample's attribution partial. */
static struct item *join_entry(struct aggregate *a, struct map *m, const void *key, size_t len,
                               bool *refused, struct fm_error *error) {
  *refused = false;
  if (a->limited && a->lan.used + a->pending.used >= a->admission.join_limit) {
    struct item *found = (struct item *)map_find(m, key, len);
    if (!found) {
      a->join_refused++;
      *refused = true;
    }
    return found;
  }
  return map_insert(m, key, len, error);
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
  bool refused;
  struct item *i = join_entry(a, &a->lan, key, sizeof(key), &refused, error);
  if (!i)
    return refused;
  if (!lan_label_slot(a, i, error))
    return false;
  /* The last LAN companion label wins even if its state has no map pair. */
  memcpy(a->lan_labels[i->value], s->label, FM_LABEL_SIZE);
  return true;
}
static size_t address_key(unsigned char key[17], struct addr address) {
  key[0] = address.af;
  memcpy(key + 1, address.b, 16);
  return 17;
}
/* Admission of a flow seen for the first time in this sample: 0 to the
 * discovery tier, 1 tracked, 2 tracked by the forced security cap. Every
 * condition only tightens during a pass, so a flow refused once is refused
 * for the rest of it: tracked and untracked flows stay disjoint. */
static int admit(struct aggregate *a, const unsigned char *key, uint64_t hash,
                 const struct state_view *v) {
  if (!a->limited)
    return 1;
  const struct admission *ad = &a->admission;
  size_t used = a->flows.used;
  if (ad->regime == TRACK_EXACT && !a->exhausted) {
    if (used < ad->limit)
      return 1;
    a->exhausted = true;
  }
  bool room = used < ad->hard_limit;
  if (room && ((ad->known && map_find_hashed(ad->known, key, FM_FLOW_KEY_SIZE, hash)) ||
               (ad->promoted && map_find_hashed(ad->promoted, key, FM_FLOW_KEY_SIZE, hash))))
    return 1;
  /* any evidence: a threat-table match or an EVIDENCE row */
  bool flagged = classifier_lookup(a->classifier, v->remote) & ad->threat_mask;
  if (!flagged && ad->evidence && ad->evidence->used) {
    unsigned char remote[17];
    flagged = map_find(ad->evidence, remote, address_key(remote, v->remote)) != NULL;
  }
  if (!flagged)
    return 0;
  if (room && a->forced < ad->forced_limit)
    return 2;
  /* counted per state: the flow is refused for the rest of the pass */
  a->forced_refused++;
  return 0;
}
static struct flow *flow_add(struct aggregate *a, const struct state_view *v,
                             const unsigned char *key, uint64_t seq, uint32_t *id,
                             struct fm_error *error) {
  struct item *i = map_insert(&a->flows, key, FM_FLOW_KEY_SIZE, error);
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
    void *groups = rows ? fm_realloc(a->groups, capacity * sizeof(*a->groups)) : NULL;
    if (rows)
      a->totals = rows;
    if (!groups) {
      fm_error_set(error, errno ? errno : ENOMEM, "flow allocation");
      return NULL;
    }
    a->groups = groups;
    a->capacity = capacity;
  }
  struct flow *f = &a->totals[*id];
  memset(f, 0, sizeof(*f));
  memset(&a->groups[*id], 0, sizeof(a->groups[*id]));
  f->local = v->local;
  f->remote = v->remote;
  f->owner = state_owner(v);
  f->first = seq;
  /* one lookup per flow, never per state */
  f->classes = classifier_lookup(a->classifier, v->remote);
  /* the remote's evidence: Python's facts, and the threat-table match */
  if (a->admission.evidence && a->admission.evidence->used) {
    unsigned char remote[17];
    const struct item *i = map_find(a->admission.evidence, remote, address_key(remote, v->remote));
    if (i)
      f->evidence = a->admission.evidence_facts[i->value];
  }
  if (f->classes & a->admission.threat_mask)
    f->evidence.mask |= EVIDENCE_THREAT_LIST;
  /* one lookup per flow: a flow on a CARP address held as BACKUP is the master's */
  if (a->admission.carp_backup && a->admission.carp_backup->used) {
    unsigned char local[17];
    if (map_find(a->admission.carp_backup, local, address_key(local, v->local)))
      f->carp = a->admission.mirror ? FLOW_CARP_MIRROR : FLOW_CARP_HIDDEN;
  }
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
                 strnlen(s->original_interface, FM_INTERFACE_SIZE), weight, seq, 0, error))
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
           candidate(a, flow, CANDIDATE_RULE_LABEL, s->label, strnlen(s->label, FM_LABEL_SIZE),
                     1, seq, 0, error);
  /* Rule labels of inside flows are resolved in aggregate_finish: a LAN-side
   * companion state's label wins over the outside state's own label. */
  p = value;
  put32(&p, flow);
  p += state_tuple(p, v->pf.proto, v->inside, v->remote_endpoint);
  size_t length = strnlen(s->label, FM_LABEL_SIZE);
  memcpy(p, s->label, length);
  p += length;
  bool refused;
  struct item *i = join_entry(a, &a->pending, value, p - value, &refused, error);
  if (!i)
    return refused;
  if (!add_count(&i->count, 1, error))
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
  struct outside_key key = {v->pf.proto, public, v->remote_endpoint};
  return a->observe(a->observer, &key, &value, error);
}
/* A state of a flow outside the tracked set: the discovery tier only. */
static void discover(struct aggregate *a, const unsigned char *key, uint64_t hash,
                     const struct state_delta *delta, bool created, double asset) {
  struct discovery *d = a->admission.discovery;
  if (!d)
    return;
  d->untracked_states++;
  /* weighted by asset importance, so an important flow keeps its place in
   * the summaries against heavier unimportant ones */
  uint64_t unit = a->admission.profile ? profile_unit(a->admission.profile, asset) : 1;
  uint64_t bytes = delta->bytes_from_remote;
  bytes = UINT64_MAX - bytes < delta->bytes_to_remote ? UINT64_MAX : bytes + delta->bytes_to_remote;
  summary_add(d->bytes, key, hash, bytes, unit);
  summary_add(d->states, key, hash, 1, unit);
  if (created)
    summary_add(d->created, key, hash, 1, unit);
  cardinality_add(&d->flows, key);
}
bool aggregate_add(struct aggregate *a, const struct state *s,
                   struct fm_error *error) {
  if (a->finished)
    return fm_error_set(error, EINVAL, "aggregate already finished");
  struct state_view v;
  if (!state_normalize(s, a->ctx, &v, error))
    return false;
  uint64_t seq = a->seen++;
  if (v.pf.skip == SKIP_AF_TRANSLATION) {
    a->skipped_af_translation++;
    return true;
  }
  if (!v.retained)
    return true;
  a->retained++;
  if (!lan_label(a, s, &v, error))
    return false;
  if (!v.mapped)
    return true;
  /* every mapped state: the baseline (all of PF's counters) and IDS tuples */
  struct state_delta delta = {0};
  bool created = false;
  if (a->history) {
    uint64_t before = history_stats(a->history).new_states;
    if (!history_observe(a->history, s, v.remote_initiated, &delta, error))
      return false;
    created = history_stats(a->history).new_states != before && history_interval(a->history) >= 0;
  }
  if (a->observe && !add_correlation(a, s, &v, error))
    return false;
  a->mapped++;
  unsigned char key[FM_FLOW_KEY_SIZE];
  state_flow_key(key, v.local, v.remote, state_owner(&v));
  uint64_t hash = index_hash(key, sizeof(key));
  const struct item *known = map_find_hashed(&a->flows, key, sizeof(key), hash);
  /* the state's local anchor: the inside host when known (an aggregate
   * outside the engine, with no admission, is never ranked: no weighting) */
  double asset = a->admission.profile
                     ? profile_asset(a->admission.profile, v.has_inside ? v.inside.a : v.local)
                     : 1.0;
  uint32_t id;
  struct flow *f;
  if (known) {
    id = (uint32_t)known->id;
    f = &a->totals[id];
  } else {
    int admitted = admit(a, key, hash, &v);
    if (!admitted) {
      discover(a, key, hash, &delta, created, asset);
      return true;
    }
    if (!(f = flow_add(a, &v, key, seq, &id, error)))
      return false;
    a->forced += admitted == 2;
  }
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
  f->states++;
  f->created += created;
  if (f->states == 1 || asset > f->asset)
    f->asset = asset;
  if (!add_count(v.apparent_remote_initiated ? &f->remote_initiated_states
                                             : &f->local_initiated_states,
                 1, error))
    return false;
  /* ages over the states whose age is known (FM_AGE_UNKNOWN: none yet) */
  if (f->states == 1)
    f->youngest = f->oldest = s->age;
  else if (s->age != FM_AGE_UNKNOWN) {
    if (f->youngest == FM_AGE_UNKNOWN || s->age < f->youngest)
      f->youngest = s->age;
    if (f->oldest == FM_AGE_UNKNOWN || s->age > f->oldest)
      f->oldest = s->age;
  }
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
  return (struct aggregate_counts){
      .seen = a->seen, .retained = a->retained, .mapped = a->mapped,
      .skipped_af_translation = a->skipped_af_translation, .flows = a->flows.used,
      .candidates = a->candidate_count,
      .untracked_states = a->admission.discovery ? a->admission.discovery->untracked_states : 0,
      .exhausted = a->exhausted, .forced = a->forced, .forced_refused = a->forced_refused,
      .candidate_evictions = a->candidate_evictions, .join_refused = a->join_refused};
}
const struct flow *aggregate_flow(const struct aggregate *a, size_t n) {
  return a->finished && n < a->flows.used ? &a->totals[n] : NULL;
}
bool aggregate_candidate(const struct aggregate *a, size_t n,
                         struct candidate_view *v) {
  if (!a->finished || n >= a->candidate_count)
    return false;
  const struct candidate *c = &a->candidates[n];
  *v = (struct candidate_view){c->flow, c->kind, c->value, c->len, c->seq, c->weight, c->association};
  return true;
}
struct aggregate_usage aggregate_usage(const struct aggregate *a) {
  return (struct aggregate_usage){
      .tracked = a->capacity * (sizeof(*a->totals) + sizeof(*a->groups)) + map_bytes(&a->flows),
      .candidates = a->candidate_capacity * sizeof(*a->candidates) +
                    (a->slots ? (a->slot_mask + 1) * sizeof(*a->slots) : 0),
      .join = a->lan_label_capacity * sizeof(*a->lan_labels) + map_bytes(&a->lan) + map_bytes(&a->pending)};
}
size_t aggregate_bytes(const struct aggregate *a) {
  size_t bytes = sizeof(*a) + a->capacity * (sizeof(*a->totals) + sizeof(*a->groups)) +
                 a->lan_label_capacity * sizeof(*a->lan_labels) +
                 a->candidate_capacity * sizeof(*a->candidates) +
                 (a->slots ? (a->slot_mask + 1) * sizeof(*a->slots) : 0);
  bytes += map_bytes(&a->flows) + map_bytes(&a->lan) + map_bytes(&a->pending);
  return bytes;
}
