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

/* Persistent sample worker. Each request is a versioned, compact context
 * followed by RUN; results are framed FMAGG3 streams on stdout. */
#include "aggregate.h"
#include "event_correlation.h"
#include "history.h"
#include "pf_reader.h"
#include "protocol.h"
#include "ranking.h"
#include "threat_summary.h"
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

struct sample {
  struct aggregate *aggregate;
  uint64_t count;
};

static bool parse_address(const char *text, struct addr *out,
                          struct fm_error *error) {
  memset(out, 0, sizeof(*out));
  out->af = strchr(text, ':') ? 6 : 4;
  if (inet_pton(out->af == 4 ? AF_INET : AF_INET6, text, out->b) != 1)
    return fm_error_set(error, EINVAL, "invalid context address");
  return true;
}

static bool read_context(struct context *ctx, double *elapsed, bool *want_threats,
                         struct event_query *queries, size_t *query_count,
                         bool *clean_eof, struct fm_error *error) {
  char *line = NULL;
  size_t capacity = 0;
  bool header = false, have_elapsed = false, run = false;
  bool ok = false;
  bool got_line = false;
  while (getline(&line, &capacity, stdin) >= 0) {
    got_line = true;
    char a[64], b[64], device[FM_INTERFACE_SIZE];
    unsigned x, y, z, id, proto, public_port, remote_port;
    if (!header) {
      if (strcmp(line, "FMCONF1\n"))
        fm_error_set(error, EPROTO, "configuration version");
      else
        header = true;
    } else if (!strncmp(line, "E ", 2)) {
      char *end = NULL;
      *elapsed = strtod(line + 2, &end);
      if (!end || (strcmp(end, "\n") && strcmp(end, "")) ||
          !isfinite(*elapsed) || *elapsed < -1 || have_elapsed)
        fm_error_set(error, EPROTO, "configuration elapsed time");
      else
        have_elapsed = true;
    } else if (!strcmp(line, "T 1\n") && !*want_threats) {
      *want_threats = true;
    } else if (line[0] == 'Q' && sscanf(line, "Q %u %u %63s %u %63s %u", &id, &proto,
                                        a, &public_port, b, &remote_port) == 6 &&
               *query_count < FM_MAX_EVENT_QUERIES && id == *query_count &&
               proto <= 255 && public_port <= 65535 && remote_port <= 65535) {
      struct event_query *query = &queries[(*query_count)++];
      query->id = id;
      query->key.protocol = proto;
      if (!parse_address(a, &query->key.public.a, error) ||
          !parse_address(b, &query->key.remote.a, error))
        break;
      query->key.public.port = public_port;
      query->key.remote.port = remote_port;
    } else if (!strcmp(line, "RUN\n")) {
      run = true;
      break;
    } else if (line[0] == 'R' && sscanf(line, "R %63s %63s %u", a, b, &x) == 3 &&
               ctx->nr < 512) {
      if (!parse_address(a, &ctx->ranges[ctx->nr].lo, error) ||
          !parse_address(b, &ctx->ranges[ctx->nr].hi, error))
        break;
      ctx->ranges[ctx->nr++].flags = x;
    } else if (line[0] == 'L' && sscanf(line, "L %63s", a) == 1 &&
               ctx->nl < 256) {
      if (!parse_address(a, &ctx->local[ctx->nl++], error))
        break;
    } else if (line[0] == 'N' && sscanf(line, "N %63s %u %15s", a, &x, device) == 3 &&
               ctx->nn < 512) {
      struct net *n = &ctx->nets[ctx->nn];
      if (!parse_address(a, &n->a, error) || x > (n->a.af == 4 ? 32u : 128u))
        break;
      n->prefix = x;
      strcpy(n->device, device);
      ctx->nn++;
    } else if (line[0] == 'A' && sscanf(line, "A %63s %15s", a, device) == 2 &&
               ctx->na < 512) {
      struct assigned *v = &ctx->assigned[ctx->na];
      if (!parse_address(a, &v->a, error))
        break;
      strcpy(v->device, device);
      ctx->na++;
    } else if (line[0] == 'W' && sscanf(line, "W %15s", device) == 1) {
      strcpy(ctx->wan, device);
    } else if (line[0] == 'S' && sscanf(line, "S %u %u %u", &x, &y, &z) == 3 &&
               ctx->ns < 256 && x <= 255 && y <= 65535) {
      ctx->services[ctx->ns++] = (struct service){x, y, z};
    } else {
      fm_error_set(error, EPROTO, "configuration row or capacity");
      break;
    }
  }
  if (!got_line && feof(stdin)) {
    *clean_eof = true;
    free(line);
    return false;
  }
  if (!error->code && !run)
    fm_error_set(error, EPROTO, "incomplete configuration request");
  if (!error->code && !have_elapsed)
    fm_error_set(error, EPROTO, "missing configuration elapsed time");
  if (!error->code)
    ok = true;
  free(line);
  return ok;
}

static bool add_state(const struct state *state, void *arg,
                      struct fm_error *error) {
  struct sample *sample = arg;
  sample->count++;
  return aggregate_add(sample->aggregate, state, error);
}

static bool run_sample(struct history *history, struct ranking *ranking,
                       struct event_history *events,
                       bool *clean_eof, struct fm_error *error) {
  struct context *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return fm_error_set(error, errno, "configuration allocation");
  double elapsed = -1;
  bool want_threats = false;
  struct event_query queries[FM_MAX_EVENT_QUERIES];
  size_t query_count = 0;
  if (!read_context(ctx, &elapsed, &want_threats, queries, &query_count,
                    clean_eof, error)) {
    free(ctx);
    return false;
  }
  if (elapsed < 0) {
    history_reset(history);
    ranking_reset(ranking);
  }
  if (!history_begin(history, elapsed, error)) {
    free(ctx);
    return false;
  }
  struct aggregate *aggregate = aggregate_create(ctx, history, error);
  if (!aggregate) {
    history_abort(history);
    free(ctx);
    return false;
  }
  struct sample sample = {.aggregate = aggregate};
  struct timespec now;
  bool ok = pf_reader_live(add_state, &sample, NULL, error) &&
            aggregate_finish(aggregate, error);
  if (ok && clock_gettime(CLOCK_MONOTONIC, &now))
    ok = fm_error_set(error, errno, "monotonic clock");
  if (ok)
    ok = ranking_update(ranking, aggregate, now.tv_sec + now.tv_nsec / 1e9,
                        elapsed, error);
  struct threat_summary *threats = ok && want_threats
      ? threat_summary_create(aggregate, error) : NULL;
  if (ok && want_threats && !threats) ok = false;
  size_t match_count = 0;
  struct event_match *matches = query_count ? calloc(query_count, sizeof(*matches)) : NULL;
  if (ok && query_count && !matches)
    ok = fm_error_set(error, errno, "event matches allocation");
  if (ok)
    ok = event_history_update(events, aggregate, now.tv_sec + now.tv_nsec / 1e9, error);
  if (ok)
    match_count = event_history_match(events, aggregate, queries, query_count, matches, query_count, error);
  if (ok && error->code) ok = false;
  if (ok)
    ok = protocol_write_ranked(stdout, aggregate, ranking, threats,
                               matches, match_count, error);
  free(matches);
  threat_summary_destroy(threats);
  if (ok)
    history_commit(history);
  else
    history_abort(history);
  aggregate_destroy(aggregate);
  free(ctx);
  return ok;
}

int main(void) {
  umask(0077);
  struct fm_error error = {0};
  struct history *history = history_create(&error);
  struct ranking *ranking = ranking_create(150, 20.0, 0.5, &error);
  struct event_history *events = event_history_create(&error);
  if (!history || !ranking || !events) {
    fprintf(stderr, "firewallmap-native: %s\n", error.message);
    history_destroy(history);
    ranking_destroy(ranking);
    event_history_destroy(events);
    return 1;
  }
  if (fputs("FMNATIVE3\n", stdout) == EOF || fflush(stdout)) {
    history_destroy(history);
    return 1;
  }
  for (;;) {
    memset(&error, 0, sizeof(error));
    bool clean_eof = false;
    if (!run_sample(history, ranking, events, &clean_eof, &error)) {
      if (clean_eof)
        break;
      fprintf(stderr, "firewallmap-native: %s\n", error.message);
      history_destroy(history);
      ranking_destroy(ranking);
      event_history_destroy(events);
      return 1;
    }
  }
  history_destroy(history);
  ranking_destroy(ranking);
  event_history_destroy(events);
  return 0;
}
