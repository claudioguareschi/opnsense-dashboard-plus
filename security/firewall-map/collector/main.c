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

/* Persistent sample worker (see PROTOCOL.md). Each request is an FMCONF2
 * context followed by RUN; each answer is one complete FMAGG4 response, or
 * FMFAIL1 followed by exit. History, ranking and event correlation persist
 * across requests; the sample interval is measured here, never supplied. */
#include "aggregate.h"
#include "alloc.h"
#include "budget.h"
#include "classify.h"
#include "event_correlation.h"
#include "history.h"
#include "index.h"
#include "pf_reader.h"
#include "profile.h"
#include "protocol.h"
#include "ranking.h"
#include "response.h"
#include "snapshot.h"
#include "threat_summary.h"
#include "tracker.h"
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#define BUILD_FREEBSD_VERSION __FreeBSD_version
#else
#define BUILD_FREEBSD_VERSION 0
#endif

/* Live ranking policy: a flow fades over this many seconds once its counters
 * stop; rates are smoothed with this weight on the newest interval. */
#define FADE_SECONDS 20.0
#define RATE_SMOOTHING 0.5

/* A request's classification: the sets (CLASS rows) and the generation
 * token (CLASSGEN) Python derives from their source files. */
#define CLASS_GENERATION_SIZE 64
struct class_config {
  struct class_set sets[CLASSIFY_MAX_SETS];
  size_t count;
  char generation[CLASS_GENERATION_SIZE];
};
struct engine {
  struct history *history;
  struct ranking *ranking;
  struct tracker *tracker;
  struct profiles *profiles;
  struct event_history *events;
  /* the classification snapshot and what it was loaded for; replaced only
   * between samples, when the request's configuration differs */
  struct classifier *classifier;
  struct class_config classes;
  bool classes_loaded;
  uint64_t sequence;
};
struct request {
  struct context *ctx;
  bool threats, snapshot, correlation;
  uint64_t memory_budget, candidates_per_kind, threat_remotes;
  struct addr *evidence;
  size_t evidence_count;
  struct event_query queries[FM_MAX_EVENT_QUERIES];
  size_t query_count;
  struct class_config classes;
  struct profile profiles[PROFILE_MAX];
  size_t profile_count;
  struct addr *classify;
  size_t classify_count;
  struct sample_outcome refusal;
};
struct sample {
  struct aggregate *aggregate;
  struct history *history;
  double anchor;
  bool begun;
  uint64_t states, state_limit;
  bool over_limit;
};

static bool request_error(struct fm_error *error, const char *message) {
  return fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, message);
}
static bool parse_address(const char *text, struct addr *out,
                          struct fm_error *error) {
  memset(out, 0, sizeof(*out));
  out->af = strchr(text, ':') ? 6 : 4;
  if (inet_pton(out->af == 4 ? AF_INET : AF_INET6, text, out->b) != 1)
    return request_error(error, "invalid context address");
  return true;
}
/* Operator context beyond its maximum refuses the sample; nothing is ever
 * silently dropped. The first overflowing kind is reported with its count. */
static void context_overflow(struct request *r, char kind, size_t limit) {
  if (!r->refusal.code)
    r->refusal = (struct sample_outcome){OUTCOME_REFUSED_CONTEXT, (uint32_t)kind, limit, limit};
  if (r->refusal.context_kind == (uint32_t)kind)
    r->refusal.actual++;
}
static bool keyword(const char *line, const char *word, bool *seen,
                    struct fm_error *error) {
  size_t length = strlen(word);
  if (strncmp(line, word, length) || (line[length] != ' ' && line[length] != '\n'))
    return false;
  if (*seen)
    return !request_error(error, "duplicate request keyword");
  *seen = true;
  return true;
}
/* PF table names as OPNsense aliases and feed tables spell them. */
static bool table_name(const char *name) {
  size_t length = strlen(name);
  if (!length || length >= CLASSIFY_NAME_SIZE) return false;
  for (const char *c = name; *c; c++)
    if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') ||
          *c == '_' || *c == '-' || *c == '.'))
      return false;
  return true;
}
static void class_row(struct request *r, const char *line, struct fm_error *error) {
  unsigned id;
  char category, name[64], extra;
  struct class_config *c = &r->classes;
  if (sscanf(line, "CLASS %u %c %63s %c", &id, &category, name, &extra) != 3 ||
      c->count >= CLASSIFY_MAX_SETS || id != c->count ||
      (category != 'T' && category != 'C' && category != 'O') || !table_name(name)) {
    request_error(error, "CLASS row");
    return;
  }
  for (size_t n = 0; n < c->count; n++)
    if (!strcmp(c->sets[n].name, name)) {
      request_error(error, "duplicate CLASS table");
      return;
    }
  struct class_set *set = &c->sets[c->count++];
  memset(set, 0, sizeof(*set));
  set->id = id;
  set->category = category;
  strcpy(set->name, name);
}
/* PROFILE <id> classic
 * PROFILE <id> scored <activity 0|1> <floor> <flagged> (<weight> <scale>) x 4
 * (bytes/s, packets/s, states, new states/s). */
static void profile_row(struct request *r, const char *line, struct fm_error *error) {
  unsigned id, activity, floor;
  char kind[16], extra;
  double flagged, v[2 * PRIMITIVE_COUNT];
  struct profile p = {0};
  if (sscanf(line, "PROFILE %u %15s", &id, kind) != 2 || id != r->profile_count ||
      r->profile_count >= PROFILE_MAX) {
    request_error(error, "PROFILE row");
    return;
  }
  if (!strcmp(kind, "classic")) {
    if (sscanf(line, "PROFILE %u %15s %c", &id, kind, &extra) != 2) {
      request_error(error, "PROFILE row");
      return;
    }
    p.classic = true;
  } else if (!strcmp(kind, "scored") &&
             sscanf(line, "PROFILE %u scored %u %u %lf %lf %lf %lf %lf %lf %lf %lf %lf %c", &id,
                    &activity, &floor, &flagged, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6],
                    &v[7], &extra) == 12 &&
             activity <= 1 && floor <= BUDGET_RANKED_FLOWS && isfinite(flagged) && flagged >= 0 &&
             flagged <= 1000) {
    p.activity = activity;
    p.floor = floor;
    p.flagged = flagged;
    for (int k = 0; k < PRIMITIVE_COUNT; k++) {
      p.weight[k] = v[2 * k];
      p.scale[k] = v[2 * k + 1];
      if (!isfinite(p.weight[k]) || p.weight[k] < 0 || p.weight[k] > 1000 || !isfinite(p.scale[k]) ||
          p.scale[k] <= 0) {
        request_error(error, "PROFILE weights");
        return;
      }
    }
  } else {
    request_error(error, "PROFILE row");
    return;
  }
  r->profiles[r->profile_count++] = p;
}
static bool read_request(struct request *r, bool *clean_eof, struct fm_error *error) {
  char *line = NULL;
  size_t capacity = 0;
  bool header = false, run = false, got_line = false;
  bool seen_threats = false, seen_snapshot = false, seen_budget = false,
       seen_correlation = false, seen_generation = false;
  struct context *ctx = r->ctx;
  while (!error->code && getline(&line, &capacity, stdin) >= 0) {
    got_line = true;
    char a[64], b[64], device[FM_INTERFACE_SIZE], extra;
    unsigned x, y, z, id, proto, public_port, remote_port;
    unsigned long long memory, candidates, remotes;
    if (!header) {
      if (strcmp(line, "FMCONF2\n"))
        request_error(error, "configuration version");
      header = true;
    } else if (!strcmp(line, "RUN\n")) {
      run = true;
      break;
    } else if (keyword(line, "THREATS", &seen_threats, error)) {
      if (strcmp(line, "THREATS\n")) request_error(error, "THREATS row");
      r->threats = true;
    } else if (keyword(line, "SNAPSHOT", &seen_snapshot, error)) {
      if (strcmp(line, "SNAPSHOT\n")) request_error(error, "SNAPSHOT row");
      r->snapshot = true;
    } else if (keyword(line, "BUDGET", &seen_budget, error)) {
      if (sscanf(line, "BUDGET %llu %llu %llu %c", &memory, &candidates, &remotes, &extra) != 3 ||
          memory < BUDGET_MEMORY_MIN || memory > BUDGET_MEMORY_MAX || !candidates ||
          candidates > BUDGET_CANDIDATES_MAX || remotes > BUDGET_THREAT_REMOTES_MAX)
        request_error(error, "BUDGET row");
      r->memory_budget = memory;
      r->candidates_per_kind = candidates;
      r->threat_remotes = remotes;
    } else if (keyword(line, "CORRELATION", &seen_correlation, error)) {
      if (sscanf(line, "CORRELATION %u %c", &x, &extra) != 1 || x > 1)
        request_error(error, "CORRELATION row");
      r->correlation = x;
    } else if (!strncmp(line, "PROFILE ", 8)) {
      profile_row(r, line, error);
    } else if (!strncmp(line, "CLASS ", 6)) {
      class_row(r, line, error);
    } else if (keyword(line, "CLASSGEN", &seen_generation, error)) {
      if (sscanf(line, "CLASSGEN %63s %c", r->classes.generation, &extra) != 1)
        request_error(error, "CLASSGEN row");
    } else if (!strncmp(line, "K ", 2)) {
      if (sscanf(line, "K %63s %c", a, &extra) != 1 || r->classify_count >= CLASSIFY_MAX_ADDRESSES) {
        request_error(error, "K row");
        break;
      }
      if (!r->classify &&
          !(r->classify = fm_calloc(CLASSIFY_MAX_ADDRESSES, sizeof(*r->classify)))) {
        fm_error_set(error, errno, "classify allocation");
        break;
      }
      parse_address(a, &r->classify[r->classify_count++], error);
    } else if (!strncmp(line, "EVIDENCE ", 9)) {
      if (sscanf(line, "EVIDENCE %63s %c", a, &extra) != 1 ||
          r->evidence_count >= BUDGET_THREAT_REMOTES_MAX) {
        request_error(error, "EVIDENCE row");
        break;
      }
      if (!r->evidence &&
          !(r->evidence = fm_calloc(BUDGET_THREAT_REMOTES_MAX, sizeof(*r->evidence)))) {
        fm_error_set(error, errno, "evidence allocation");
        break;
      }
      parse_address(a, &r->evidence[r->evidence_count++], error);
    } else if (line[0] == 'Q' && sscanf(line, "Q %u %u %63s %u %63s %u %c", &id, &proto,
                                        a, &public_port, b, &remote_port, &extra) == 6) {
      if (r->query_count >= FM_MAX_EVENT_QUERIES || id != r->query_count || proto > 255 ||
          public_port > 65535 || remote_port > 65535) {
        request_error(error, "event query row");
        break;
      }
      struct event_query *query = &r->queries[r->query_count++];
      query->id = id;
      query->key.protocol = proto;
      if (parse_address(a, &query->key.public.a, error) &&
          parse_address(b, &query->key.remote.a, error)) {
        query->key.public.port = public_port;
        query->key.remote.port = remote_port;
      }
    } else if (line[0] == 'R' && sscanf(line, "R %63s %63s %u %c", a, b, &x, &extra) == 3) {
      struct range range = {.flags = x};
      if (parse_address(a, &range.lo, error) && parse_address(b, &range.hi, error) &&
          !context_add_range(ctx, range, error) && !error->code)
        request_error(error, "classification range capacity");
    } else if (line[0] == 'L' && sscanf(line, "L %63s %c", a, &extra) == 1) {
      struct addr local;
      if (parse_address(a, &local, error) && !context_add_local(ctx, local, error) && !error->code)
        context_overflow(r, 'L', CONTEXT_MAX_LOCAL);
    } else if (line[0] == 'N' && sscanf(line, "N %63s %u %15s %c", a, &x, device, &extra) == 3) {
      struct net net = {.prefix = x};
      strcpy(net.device, device);
      if (parse_address(a, &net.a, error) && x > (net.a.af == 4 ? 32u : 128u))
        request_error(error, "network prefix");
      else if (!error->code && !context_add_net(ctx, net, error) && !error->code)
        context_overflow(r, 'N', CONTEXT_MAX_NETWORKS);
    } else if (line[0] == 'A' && sscanf(line, "A %63s %15s %c", a, device, &extra) == 2) {
      struct assigned assigned;
      strcpy(assigned.device, device);
      if (parse_address(a, &assigned.a, error) && !context_add_assigned(ctx, assigned, error) &&
          !error->code)
        context_overflow(r, 'A', CONTEXT_MAX_ASSIGNED);
    } else if (line[0] == 'W' && sscanf(line, "W %15s %c", device, &extra) == 1) {
      strcpy(ctx->wan, device);
    } else if (line[0] == 'S' && sscanf(line, "S %u %u %u %c", &x, &y, &z, &extra) == 3) {
      if (x > 255 || y > 65535)
        request_error(error, "service row");
      else if (!context_add_service(ctx, (struct service){x, y, z}, error) && !error->code)
        request_error(error, "service row capacity");
    } else
      request_error(error, "configuration row");
  }
  free(line);
  if (!got_line && feof(stdin)) {
    *clean_eof = true;
    return false;
  }
  if (!error->code && !run)
    request_error(error, "incomplete configuration request");
  return !error->code && (r->refusal.code || context_prepare(ctx, error));
}

static bool begin(struct sample *s, struct fm_error *error) {
  if (s->begun)
    return true;
  s->begun = true;
  return history_begin(s->history, s->anchor, error);
}
/* The reader writes the anchor before sending its dump request, so it is
 * known by the first state callback; an empty table begins after the read.
 * The admission backstop stops the traversal as soon as the state count
 * passes the limit (the count can grow after the preflight). */
static bool add_state(const struct state *state, void *arg,
                      struct fm_error *error) {
  struct sample *s = arg;
  if (++s->states > s->state_limit) {
    s->over_limit = true;
    return fm_error_fail(error, FM_FAILURE_RESOURCES, ECANCELED, "PF state admission backstop");
  }
  return begin(s, error) && aggregate_add(s->aggregate, state, error);
}

static double monotonic_seconds(void) {
  struct timespec t;
  return clock_gettime(CLOCK_MONOTONIC, &t) ? 0.0 : t.tv_sec + t.tv_nsec / 1e9;
}
static void measure_process(struct telemetry *t) {
  struct rusage usage;
  if (!getrusage(RUSAGE_SELF, &usage)) {
    t->user_cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
    t->system_cpu = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
#ifdef __APPLE__
    t->max_rss = (uint64_t)usage.ru_maxrss;
#else
    t->max_rss = (uint64_t)usage.ru_maxrss * 1024;
#endif
  }
  struct fm_heap_usage heap = fm_heap_usage();
  t->heap_bytes = heap.bytes;
  t->heap_peak = heap.peak_bytes;
  t->heap_blocks = heap.blocks;
  t->heap_budget = heap.budget_bytes;
}

static bool refuse(struct engine *e, struct sample_outcome refusal, uint64_t seen,
                   struct telemetry *telemetry, struct fm_error *error) {
  /* A refused sample is not a helper failure; the next accepted one is a
   * baseline because the counters in between were never observed. */
  history_reset(e->history);
  ranking_reset(e->ranking);
  profiles_reset(e->profiles);
  tracker_reset(e->tracker);
  measure_process(telemetry);
  struct response response;
  if (!response_begin(&response, error))
    return false;
  if (!protocol_write_refusal(response.stream, refusal, seen, telemetry, error)) {
    response_discard(&response);
    return false;
  }
  return response_commit(&response, stdout, error);
}

static bool same_classes(const struct class_config *a, const struct class_config *b) {
  if (a->count != b->count || strcmp(a->generation, b->generation)) return false;
  for (size_t n = 0; n < a->count; n++)
    if (a->sets[n].category != b->sets[n].category || strcmp(a->sets[n].name, b->sets[n].name))
      return false;
  return true;
}
/* Reads the PF tables again only when the configuration or its generation
 * changed: never per sample. A failed load leaves no snapshot (and is
 * retried by the next request). */
static bool refresh_classifier(struct engine *e, const struct class_config *wanted,
                               struct fm_error *error) {
  if (e->classes_loaded && same_classes(&e->classes, wanted)) return true;
  classifier_destroy(e->classifier);
  e->classifier = NULL;
  e->classes_loaded = false;
  if (!wanted->count) {
    e->classes = *wanted;
    e->classes_loaded = true;
    return true;
  }
  struct class_config loaded = *wanted;
  e->classifier = classifier_load(loaded.sets, loaded.count, error);
  if (!e->classifier) return false;
  e->classes = loaded;
  e->classes_loaded = true;
  return true;
}

/* The sample's tracked-set report in the telemetry (PROTOCOL.md). */
static void telemetry_track(struct telemetry *t, const struct tracker_report *report,
                            struct aggregate_counts counts) {
  t->regime = report->regime;
  t->next_regime = report->next_regime;
  t->quality_discovery = report->discovery;
  t->quality_ranking = report->ranking;
  t->quality_attribution = report->attribution;
  t->discovery_error = report->discovery_error;
  t->flows_total = report->flows;
  t->flows_estimated = report->flows_estimated;
  t->tracked_flows = report->tracked;
  t->tracked_limit = report->limit;
  t->exit_threshold = report->exit_threshold;
  t->forced_limit = report->forced_limit;
  t->forced_flows = counts.forced;
  t->forced_refused = counts.forced_refused;
  t->candidate_limit = report->candidate_limit;
  t->candidate_evictions = counts.candidate_evictions;
  t->join_limit = report->join_limit;
  t->join_refused = counts.join_refused;
  t->untracked_states = counts.untracked_states;
  t->promoted = report->promoted;
}

/* The union of the profiles' selections (each flow once: profile 0's in its
 * order, then the flows each later profile adds) and what the tracked set
 * must know about them. */
static bool select_union(struct engine *e, const struct aggregate *a, double interval,
                         struct ranked_flow **rows, uint32_t **position, struct track_hints *hints,
                         struct fm_error *error) {
  size_t flows = aggregate_counts(a).flows, profiles = profiles_count(e->profiles);
  *rows = profiles ? fm_calloc(profiles * BUDGET_RANKED_FLOWS, sizeof(**rows)) : NULL;
  *position = flows ? fm_calloc(flows, sizeof(**position)) : NULL;
  if ((profiles && !*rows) || (flows && !*position))
    return fm_error_set(error, errno ? errno : ENOMEM, "profile union");
  size_t count = 0;
  bool states_full = true, created_full = true;
  double states_edge = INFINITY, created_edge = INFINITY;
  for (size_t n = 0; n < profiles; n++) {
    const struct profile *def = profiles_at(e->profiles, n);
    const struct selected *chosen;
    size_t selected = profiles_selection(e->profiles, n, &chosen);
    double least_states = INFINITY, least_created = INFINITY;
    for (size_t k = 0; k < selected; k++) {
      uint32_t flow = chosen[k].flow;
      double s = profiles_value(a, e->ranking, flow, PRIMITIVE_STATES, interval);
      double c = profiles_value(a, e->ranking, flow, PRIMITIVE_CREATED, interval);
      least_states = s < least_states ? s : least_states;
      least_created = c < least_created ? c : least_created;
      if ((*position)[flow]) continue;
      struct flow_rates rates;
      ranking_rates(e->ranking, flow, &rates);
      (*rows)[count] = (struct ranked_flow){flow, rates.rate_from_remote, rates.rate_to_remote,
                                            rates.packet_rate, rates.activity, chosen[k].score};
      (*position)[flow] = (uint32_t)++count;
    }
    bool full = selected == BUDGET_RANKED_FLOWS;
    if (!def->classic && def->weight[PRIMITIVE_STATES] > 0) {
      hints->states = true;
      states_full = states_full && full;
      states_edge = least_states < states_edge ? least_states : states_edge;
    }
    if (!def->classic && def->weight[PRIMITIVE_CREATED] > 0) {
      hints->created = true;
      created_full = created_full && full;
      created_edge = least_created < created_edge ? least_created : created_edge;
    }
  }
  hints->selected = *rows;
  hints->selected_count = count;
  hints->states_edge = states_full && hints->states ? states_edge : 0;
  hints->created_edge = created_full && hints->created ? created_edge : 0;
  return true;
}

static bool run_sample(struct engine *e, struct request *r, struct fm_error *error) {
  /* without PROFILE rows: Classic alone */
  if (!r->profile_count)
    r->profiles[r->profile_count++] = (struct profile){.classic = true};
  if (!profiles_configure(e->profiles, r->profiles, r->profile_count, error))
    return false;
  /* the snapshot persists across samples: it is loaded outside the sample
   * budget and its size comes off the state admission */
  if (!refresh_classifier(e, &r->classes, error))
    return false;
  uint64_t class_bytes = classifier_bytes(e->classifier);
  struct budget_limits shares = budget_limits(r->memory_budget, class_bytes);
  uint64_t state_limit = shares.states;
  struct telemetry telemetry = {.pid = (uint32_t)getpid(), .sequence = ++e->sequence,
                                .interval = -1, .state_limit = state_limit,
                                .classifier_bytes = class_bytes};
  fm_heap_set_budget(r->memory_budget);
#ifdef FM_TEST_HOOKS
  /* FM_TEST_HEAP_BUDGET=<bytes>:<sequence> exhausts the heap below the
   * derived state limit for that one request */
  unsigned long long test_budget, test_sequence;
  const char *hook = getenv("FM_TEST_HEAP_BUDGET");
  if (hook && sscanf(hook, "%llu:%llu", &test_budget, &test_sequence) == 2 &&
      test_sequence == e->sequence)
    fm_heap_set_budget(test_budget);
#endif
  fm_heap_reset_peak();
  uint64_t refused_before = fm_heap_usage().refused;
  if (r->refusal.code)
    return refuse(e, r->refusal, 0, &telemetry, error);
  if (pf_reader_state_count(&telemetry.preflight_states) &&
      telemetry.preflight_states > state_limit)
    return refuse(e, (struct sample_outcome){OUTCOME_REFUSED_STATES, 0,
                                             telemetry.preflight_states, state_limit},
                  0, &telemetry, error);
  struct sample sample = {.history = e->history, .state_limit = state_limit};
  /* IDS/block tuple matching streams through a bounded event sample (never an
   * O(states) map); without correlation nothing consumes tuples at all */
  struct event_sample *events =
      r->correlation ? event_sample_begin(e->events, r->queries, r->query_count, error) : NULL;
  sample.aggregate = !r->correlation || events
                         ? aggregate_create(r->ctx, e->history, events ? event_sample_observe : NULL,
                                            events, error)
                         : NULL;
  /* the tracked set: who is tracked richly, who only reaches discovery */
  struct admission admission;
  struct map evidence = {0};
  bool tracked = sample.aggregate && tracker_begin(e->tracker, e->ranking, shares, &admission, error);
  for (size_t n = 0; tracked && n < r->evidence_count; n++) {
    unsigned char key[17] = {r->evidence[n].af};
    memcpy(key + 1, r->evidence[n].b, 16);
    tracked = lookup(&evidence, key, sizeof(key), true, error) != NULL;
  }
  if (tracked) {
    admission.threat_mask = classifier_category(e->classifier, 'T');
    admission.evidence = &evidence;
    aggregate_set_classifier(sample.aggregate, e->classifier);
    aggregate_set_admission(sample.aggregate, &admission);
  }
  struct timespec wall = {0};
  /* presize the baseline from PF's own count (+10% for growth during the
   * dump) so the traversal does not rehash it */
  bool ok = tracked &&
            (!telemetry.preflight_states ||
             history_reserve(e->history, telemetry.preflight_states + telemetry.preflight_states / 10,
                             error)) &&
            (!r->snapshot || !clock_gettime(CLOCK_REALTIME, &wall) ||
             fm_error_fail(error, FM_FAILURE_INTERNAL, errno, "sample clock"));
  ok = ok && pf_reader_live(add_state, &sample, NULL, &sample.anchor, error) &&
       begin(&sample, error) && aggregate_finish(sample.aggregate, error);
  double read_done = monotonic_seconds();
  telemetry.dump_seconds = ok ? read_done - sample.anchor : 0;
  telemetry.interval = ok ? history_interval(e->history) : -1;
  ok = ok && ranking_update(e->ranking, sample.aggregate, sample.anchor,
                            telemetry.interval, error);
  /* every enabled profile's selection, and their union for the response */
  struct ranked_flow *selected = NULL;
  uint32_t *position = NULL;
  struct track_hints hints = {0};
  ok = ok && profiles_select(e->profiles, sample.aggregate, e->ranking, telemetry.interval,
                             BUDGET_RANKED_FLOWS, error) &&
       select_union(e, sample.aggregate, telemetry.interval, &selected, &position, &hints, error);
  struct tracker_report report = {0};
  ok = ok && tracker_finish(e->tracker, sample.aggregate, e->ranking, sample.anchor,
                            telemetry.interval, &hints, &report, error);
  map_clear(&evidence);
  if (ok) {
    telemetry_track(&telemetry, &report, aggregate_counts(sample.aggregate));
    struct aggregate_usage usage = aggregate_usage(sample.aggregate);
    telemetry.baseline_bytes = history_bytes(e->history);
    telemetry.tracked_bytes = usage.tracked;
    telemetry.candidate_bytes = usage.candidates;
    telemetry.join_bytes = usage.join;
    telemetry.ranking_bytes = ranking_bytes(e->ranking);
    telemetry.discovery_bytes = tracker_bytes(e->tracker);
  }
  struct threat_limits limits = {r->evidence, r->evidence_count, r->threat_remotes,
                                 r->candidates_per_kind, classifier_category(e->classifier, 'T')};
  struct threat_summary *threats =
      ok && r->threats ? threat_summary_create(sample.aggregate, limits, error) : NULL;
  ok = ok && (!r->threats || threats);
  struct event_match *matches =
      ok && r->query_count ? fm_calloc(r->query_count, sizeof(*matches)) : NULL;
  ok = ok && (!r->query_count || matches || fm_error_set(error, errno, "event matches"));
  size_t match_count = 0;
  if (ok && events)
    match_count = event_sample_finish(e->events, events, sample.anchor, matches, r->query_count,
                                      error);
  else if (ok)
    event_history_clear(e->events); /* nothing consumes it: no IDS, no queries */
  event_sample_destroy(events);
  ok = ok && !error->code;
  struct response response = {0};
  if (ok) {
    telemetry.processing_seconds = monotonic_seconds() - read_done;
    telemetry.skipped_af_translation = aggregate_counts(sample.aggregate).skipped_af_translation;
    telemetry.event_history_evicted = event_history_evicted(e->events);
    measure_process(&telemetry);
    ok = response_begin(&response, error);
    struct class_report classes = {e->classifier, r->classify, r->classify_count};
    struct ranked_output ranked = {selected, hints.selected_count, e->profiles, position};
    if (ok && !protocol_write_ranked(response.stream, sample.aggregate, &ranked, threats,
                                     matches, match_count, &classes, r->candidates_per_kind,
                                     &telemetry, error)) {
      response_discard(&response);
      ok = false;
    } else if (ok)
      ok = response_commit(&response, stdout, error);
  }
  fm_free(matches);
  fm_free(selected);
  fm_free(position);
  threat_summary_destroy(threats);
  if (ok)
    history_commit(e->history);
  else if (sample.begun)
    history_abort(e->history);
  /* A budget refusal (state backstop or refused allocation) is an outcome,
   * not a failure: the helper answers it and stays. */
  bool over_memory = !ok && error->failure_class == FM_FAILURE_RESOURCES &&
                     fm_heap_usage().refused > refused_before;
  if (!ok && (sample.over_limit || over_memory)) {
    uint64_t heap_peak = fm_heap_usage().peak_bytes;
    aggregate_destroy(sample.aggregate);
    memset(error, 0, sizeof(*error));
    struct sample_outcome refusal =
        sample.over_limit
            ? (struct sample_outcome){OUTCOME_REFUSED_STATES, 0, sample.states, state_limit}
            : (struct sample_outcome){OUTCOME_REFUSED_MEMORY, 0, heap_peak, r->memory_budget};
    return refuse(e, refusal, sample.states, &telemetry, error);
  }
  if (ok && r->snapshot)
    ok = snapshot_session(stdin, stdout, r->ctx, sample.aggregate, e->ranking, e->sequence,
                          wall.tv_sec + wall.tv_nsec / 1e9, &telemetry, error);
  aggregate_destroy(sample.aggregate);
  return ok;
}

static void close_engine(struct engine *e) {
  history_destroy(e->history);
  ranking_destroy(e->ranking);
  tracker_destroy(e->tracker);
  event_history_destroy(e->events);
  profiles_destroy(e->profiles);
  classifier_destroy(e->classifier);
}

/* A fresh 128-bit hash key per helper process (arc4random_buf cannot fail).
 * Test builds (FM_TEST_HOOKS) may fix it with FM_TEST_HASH_KEY=<32 hex digits>
 * to prove outputs do not depend on it. */
static void seed_hash(void) {
  uint8_t key[16];
  arc4random_buf(key, sizeof(key));
#ifdef FM_TEST_HOOKS
  const char *fixed = getenv("FM_TEST_HASH_KEY");
  for (unsigned n = 0; fixed && n < sizeof(key); n++) {
    unsigned byte;
    if (sscanf(fixed + 2 * n, "%2x", &byte) != 1)
      break;
    key[n] = (uint8_t)byte;
  }
#endif
  index_set_hash_key(key);
}

#ifndef __VERSION__
#define __VERSION__ "unknown"
#endif
static int print_version(void) {
  printf("{\"collector\":\"firewallmap-collector\",\"protocol\":%u,"
         "\"pf_state_version\":%u,\"freebsd_version\":%u,\"compiler\":\"%s\"}\n",
         (unsigned)FM_PROTOCOL_VERSION, pf_reader_state_version(), (unsigned)BUILD_FREEBSD_VERSION,
         __VERSION__);
  return 0;
}
static bool count_state(const struct state *state, void *arg, struct fm_error *error) {
  (void)state;
  (void)error;
  (*(uint64_t *)arg)++;
  return true;
}
/* --selftest: can this helper read this kernel's PF states? One GETSTATES dump
 * with full structural and ABI validation, no aggregation. Prints one JSON
 * line; exit status 0 compatible, 3 incompatible PF ABI, 1 any other failure.
 * With no states the ABI version cannot be checked; the result says so and
 * the first real sample checks it. */
static int self_test(void) {
  struct fm_error error = {0};
  uint64_t preflight = 0, states = 0;
  bool status = pf_reader_state_count(&preflight);
  bool ok = pf_reader_live(count_state, &states, NULL, NULL, &error);
  const char *classes[] = {"", "structural", "internal", "incompatible", "resources", "request"};
  if (!ok) {
    char message[sizeof(error.message) * 6 + 1], *p = message;
    for (const char *c = error.message; *c; c++) /* JSON-safe: drop quotes and controls */
      if (*c != '"' && *c != '\\' && (unsigned char)*c >= 32) *p++ = *c;
    *p = 0;
    printf("{\"ok\":false,\"class\":\"%s\",\"error\":\"%s\"}\n",
           error.failure_class > 0 && error.failure_class <= 5 ? classes[error.failure_class] : "unknown",
           message);
    return error.failure_class == FM_FAILURE_INCOMPATIBLE ? 3 : 1;
  }
  printf("{\"ok\":true,\"states\":%llu,\"abi_checked\":%s,\"preflight\":%s}\n",
         (unsigned long long)states, states ? "true" : "false", status ? "true" : "false");
  return 0;
}

int main(int argc, char **argv) {
  umask(0077);
  if (argc == 2 && !strcmp(argv[1], "--version"))
    return print_version();
  if (argc == 2 && !strcmp(argv[1], "--selftest"))
    return self_test();
  if (argc != 1) {
    fprintf(stderr, "usage: firewallmap-collector [--version | --selftest]\n");
    return 2;
  }
  seed_hash();
  struct fm_error error = {0};
  struct engine engine = {
      .history = history_create(&error),
      .ranking = ranking_create(BUDGET_RANKED_FLOWS, FADE_SECONDS, RATE_SMOOTHING, &error),
      .tracker = tracker_create(FADE_SECONDS, RATE_SMOOTHING, &error),
      .profiles = profiles_create(&error),
      .events = event_history_create(&error)};
  if (!engine.history || !engine.ranking || !engine.tracker || !engine.profiles || !engine.events) {
    fprintf(stderr, "firewallmap-collector: %s\n", error.message);
    close_engine(&engine);
    return 1;
  }
  if (printf("FMCOLLECTOR protocol=%u pf_state_version=%u freebsd_version=%u\n",
             (unsigned)FM_PROTOCOL_VERSION, pf_reader_state_version(),
             (unsigned)BUILD_FREEBSD_VERSION) < 0 ||
      fflush(stdout)) {
    close_engine(&engine);
    return 1;
  }
  int status = 0;
  for (;;) {
    memset(&error, 0, sizeof(error));
    /* parsing is bounded by the row maxima; each sample sets its own budget */
    fm_heap_set_budget(0);
    bool clean_eof = false;
    struct request *request = fm_calloc(1, sizeof(*request));
    if (request) {
      request->ctx = context_create(&error);
      request->memory_budget = BUDGET_MEMORY_DEFAULT;
      request->candidates_per_kind = BUDGET_CANDIDATES_DEFAULT;
      request->threat_remotes = BUDGET_THREAT_REMOTES_DEFAULT;
      request->correlation = true;
    }
    bool ok = request && request->ctx && read_request(request, &clean_eof, &error) &&
              run_sample(&engine, request, &error);
    if (!request || !request->ctx)
      fm_error_set(&error, ENOMEM, "request allocation");
    if (request) {
      context_destroy(request->ctx);
      fm_free(request->evidence);
      fm_free(request->classify);
    }
    fm_free(request);
    if (ok)
      continue;
    if (!clean_eof) {
      fprintf(stderr, "firewallmap-collector: %s\n", error.message);
      protocol_write_failure(stdout, &error);
      status = 1;
    }
    break;
  }
  close_engine(&engine);
  return status;
}
