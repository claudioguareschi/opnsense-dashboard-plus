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
#include "event_correlation.h"
#include "history.h"
#include "pf_reader.h"
#include "protocol.h"
#include "ranking.h"
#include "response.h"
#include "snapshot.h"
#include "threat_summary.h"
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

/* Live ranking policy: the map shows at most this many flows; a flow fades
 * over this many seconds once its counters stop; rates are smoothed with
 * this weight on the newest interval. */
#define RANKED_FLOWS 150
#define FADE_SECONDS 20.0
#define RATE_SMOOTHING 0.5
/* Request row maxima beyond the context arrays (PROTOCOL.md). */
#define MAX_EVIDENCE_ROWS 20000

struct engine {
  struct history *history;
  struct ranking *ranking;
  struct event_history *events;
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
  struct sample_outcome refusal;
};
struct sample {
  struct aggregate *aggregate;
  struct history *history;
  double anchor;
  bool begun;
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
 * silently dropped. The first overflowing kind is reported. */
static bool context_slot(struct request *r, char kind, size_t *used, size_t limit) {
  if (*used < limit)
    return true;
  if (!r->refusal.code)
    r->refusal = (struct sample_outcome){OUTCOME_REFUSED_CONTEXT, (uint32_t)kind, 0, limit};
  if (r->refusal.context_kind == (uint32_t)kind)
    r->refusal.actual = r->refusal.actual ? r->refusal.actual + 1 : limit + 1;
  return false;
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
static bool read_request(struct request *r, bool *clean_eof, struct fm_error *error) {
  char *line = NULL;
  size_t capacity = 0;
  bool header = false, run = false, got_line = false;
  bool seen_threats = false, seen_snapshot = false, seen_budget = false,
       seen_correlation = false;
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
          !candidates || remotes > MAX_EVIDENCE_ROWS)
        request_error(error, "BUDGET row");
      r->memory_budget = memory;
      r->candidates_per_kind = candidates;
      r->threat_remotes = remotes;
    } else if (keyword(line, "CORRELATION", &seen_correlation, error)) {
      if (sscanf(line, "CORRELATION %u %c", &x, &extra) != 1 || x > 1)
        request_error(error, "CORRELATION row");
      r->correlation = x;
    } else if (!strncmp(line, "EVIDENCE ", 9)) {
      if (sscanf(line, "EVIDENCE %63s %c", a, &extra) != 1 || r->evidence_count >= MAX_EVIDENCE_ROWS) {
        request_error(error, "EVIDENCE row");
        break;
      }
      if (!r->evidence && !(r->evidence = fm_calloc(MAX_EVIDENCE_ROWS, sizeof(*r->evidence)))) {
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
      if (ctx->nr >= sizeof(ctx->ranges) / sizeof(*ctx->ranges)) {
        request_error(error, "classification range capacity");
        break;
      }
      if (parse_address(a, &ctx->ranges[ctx->nr].lo, error) &&
          parse_address(b, &ctx->ranges[ctx->nr].hi, error))
        ctx->ranges[ctx->nr++].flags = x;
    } else if (line[0] == 'L' && sscanf(line, "L %63s %c", a, &extra) == 1) {
      if (context_slot(r, 'L', &ctx->nl, sizeof(ctx->local) / sizeof(*ctx->local)))
        parse_address(a, &ctx->local[ctx->nl++], error);
    } else if (line[0] == 'N' && sscanf(line, "N %63s %u %15s %c", a, &x, device, &extra) == 3) {
      if (context_slot(r, 'N', &ctx->nn, sizeof(ctx->nets) / sizeof(*ctx->nets))) {
        struct net *n = &ctx->nets[ctx->nn];
        if (parse_address(a, &n->a, error) && x > (n->a.af == 4 ? 32u : 128u))
          request_error(error, "network prefix");
        n->prefix = x;
        strcpy(n->device, device);
        ctx->nn++;
      }
    } else if (line[0] == 'A' && sscanf(line, "A %63s %15s %c", a, device, &extra) == 2) {
      if (context_slot(r, 'A', &ctx->na, sizeof(ctx->assigned) / sizeof(*ctx->assigned))) {
        struct assigned *v = &ctx->assigned[ctx->na];
        parse_address(a, &v->a, error);
        strcpy(v->device, device);
        ctx->na++;
      }
    } else if (line[0] == 'W' && sscanf(line, "W %15s %c", device, &extra) == 1) {
      strcpy(ctx->wan, device);
    } else if (line[0] == 'S' && sscanf(line, "S %u %u %u %c", &x, &y, &z, &extra) == 3) {
      if (ctx->ns >= sizeof(ctx->services) / sizeof(*ctx->services) || x > 255 || y > 65535) {
        request_error(error, "service row");
        break;
      }
      ctx->services[ctx->ns++] = (struct service){x, y, z};
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
  return !error->code;
}

static bool begin(struct sample *s, struct fm_error *error) {
  if (s->begun)
    return true;
  s->begun = true;
  return history_begin(s->history, s->anchor, error);
}
/* The reader writes the anchor before sending its dump request, so it is
 * known by the first state callback; an empty table begins after the read. */
static bool add_state(const struct state *state, void *arg,
                      struct fm_error *error) {
  struct sample *s = arg;
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

static bool refuse(struct engine *e, const struct request *r,
                   struct telemetry *telemetry, struct fm_error *error) {
  /* A refused sample is not a helper failure; the next accepted one is a
   * baseline because the counters in between were never observed. */
  history_reset(e->history);
  ranking_reset(e->ranking);
  measure_process(telemetry);
  struct response response;
  if (!response_begin(&response, error))
    return false;
  if (!protocol_write_refusal(response.stream, r->refusal, 0, telemetry, error)) {
    response_discard(&response);
    return false;
  }
  return response_commit(&response, stdout, error);
}

static bool run_sample(struct engine *e, struct request *r, struct fm_error *error) {
  struct telemetry telemetry = {.pid = (uint32_t)getpid(), .sequence = ++e->sequence,
                                .interval = -1};
  fm_heap_reset_peak();
  if (r->refusal.code)
    return refuse(e, r, &telemetry, error);
  struct sample sample = {.history = e->history};
  sample.aggregate = aggregate_create(r->ctx, e->history, error);
  if (!sample.aggregate)
    return false;
  struct timespec wall = {0};
  bool ok = !r->snapshot || !clock_gettime(CLOCK_REALTIME, &wall) ||
            fm_error_fail(error, FM_FAILURE_INTERNAL, errno, "sample clock");
  ok = ok && pf_reader_live(add_state, &sample, NULL, &sample.anchor, error) &&
       begin(&sample, error) && aggregate_finish(sample.aggregate, error);
  double read_done = monotonic_seconds();
  telemetry.dump_seconds = ok ? read_done - sample.anchor : 0;
  telemetry.interval = ok ? history_interval(e->history) : -1;
  ok = ok && ranking_update(e->ranking, sample.aggregate, sample.anchor,
                            telemetry.interval, error);
  struct threat_summary *threats =
      ok && r->threats ? threat_summary_create(sample.aggregate, error) : NULL;
  ok = ok && (!r->threats || threats);
  struct event_match *matches =
      ok && r->query_count ? fm_calloc(r->query_count, sizeof(*matches)) : NULL;
  ok = ok && (!r->query_count || matches || fm_error_set(error, errno, "event matches"));
  ok = ok && event_history_update(e->events, sample.aggregate, sample.anchor, error);
  size_t match_count = ok ? event_history_match(e->events, sample.aggregate, r->queries,
                                                r->query_count, matches, r->query_count,
                                                error)
                          : 0;
  ok = ok && !error->code;
  struct response response = {0};
  if (ok) {
    telemetry.processing_seconds = monotonic_seconds() - read_done;
    measure_process(&telemetry);
    ok = response_begin(&response, error);
    if (ok && !protocol_write_ranked(response.stream, sample.aggregate, e->ranking, threats,
                                     matches, match_count, &telemetry, error)) {
      response_discard(&response);
      ok = false;
    } else if (ok)
      ok = response_commit(&response, stdout, error);
  }
  fm_free(matches);
  threat_summary_destroy(threats);
  if (ok)
    history_commit(e->history);
  else if (sample.begun)
    history_abort(e->history);
  if (ok && r->snapshot)
    ok = snapshot_session(stdin, stdout, r->ctx, sample.aggregate, e->ranking, e->sequence,
                          wall.tv_sec + wall.tv_nsec / 1e9, &telemetry, error);
  aggregate_destroy(sample.aggregate);
  return ok;
}

static void close_engine(struct engine *e) {
  history_destroy(e->history);
  ranking_destroy(e->ranking);
  event_history_destroy(e->events);
}

int main(void) {
  umask(0077);
  struct fm_error error = {0};
  struct engine engine = {
      .history = history_create(&error),
      .ranking = ranking_create(RANKED_FLOWS, FADE_SECONDS, RATE_SMOOTHING, &error),
      .events = event_history_create(&error)};
  if (!engine.history || !engine.ranking || !engine.events) {
    fprintf(stderr, "firewallmap-native: %s\n", error.message);
    close_engine(&engine);
    return 1;
  }
  if (printf("FMNATIVE5 pf_state_version=%u freebsd_version=%u\n",
             pf_reader_state_version(), (unsigned)BUILD_FREEBSD_VERSION) < 0 ||
      fflush(stdout)) {
    close_engine(&engine);
    return 1;
  }
  int status = 0;
  for (;;) {
    memset(&error, 0, sizeof(error));
    bool clean_eof = false;
    struct request *request = fm_calloc(1, sizeof(*request));
    if (request)
      request->ctx = fm_calloc(1, sizeof(*request->ctx));
    bool ok = request && request->ctx && read_request(request, &clean_eof, &error) &&
              run_sample(&engine, request, &error);
    if (!request || !request->ctx)
      fm_error_set(&error, ENOMEM, "request allocation");
    if (request) {
      fm_free(request->ctx);
      fm_free(request->evidence);
    }
    fm_free(request);
    if (ok)
      continue;
    if (!clean_eof) {
      fprintf(stderr, "firewallmap-native: %s\n", error.message);
      protocol_write_failure(stdout, &error);
      status = 1;
    }
    break;
  }
  close_engine(&engine);
  return status;
}
