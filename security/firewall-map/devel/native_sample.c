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

/* Development driver. Link this file with all native modules and libm. */
#include "../native/aggregate.h"
#include "../native/pf_reader.h"
#include "../native/protocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_FRAME 4096
struct sample {
  struct aggregate *aggregate;
  FILE *capture;
  uint64_t count;
  struct fm_error error;
};

static bool read_exact(FILE *f, void *data, size_t size) {
  return fread(data, 1, size, f) == size;
}
static bool state_callback(const struct state *state, void *arg,
                           struct fm_error *error) {
  struct sample *sample = arg;
  if (sample->capture) {
    unsigned char b[MAX_FRAME], *p = b;
    protocol_put(&p, state->id, 8);
    protocol_put(&p, state->creator, 4);
    *p++ = state->direction;
    memcpy(p, state->iface, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    memcpy(p, state->orig, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    protocol_put(&p, state->age, 4);
    for (unsigned n = 0; n < 2; n++) protocol_put(&p, state->bytes[n], 8);
    for (unsigned n = 0; n < 2; n++) protocol_put(&p, state->packets[n], 8);
    memcpy(p, state->peer, 2); p += 2;
    for (unsigned k = 0; k < 2; k++) {
      *p++ = state->key[k].proto;
      for (unsigned e = 0; e < 2; e++) {
        protocol_address_put(&p, state->key[k].e[e].a);
        protocol_put(&p, state->key[k].e[e].port, 2);
      }
    }
    protocol_put(&p, state->expire, 4);
    protocol_put(&p, state->rule, 4);
    size_t label_len = strlen(state->label);
    protocol_put(&p, label_len, 2);
    memcpy(p, state->label, label_len); p += label_len;
    if (!protocol_frame(sample->capture, b, p - b, NULL, error))
      return false;
    sample->count++;
    return true;
  }
  sample->count++;
  return aggregate_add(sample->aggregate, state, error);
}

static bool parse_address(const char *text, struct addr *out,
                          struct fm_error *error) {
  memset(out, 0, sizeof(*out));
  out->af = strchr(text, ':') ? 6 : 4;
  if (inet_pton(out->af == 4 ? AF_INET : AF_INET6, text, out->b) != 1)
    return fm_error_set(error, EINVAL, "invalid context address");
  return true;
}
static bool read_context(const char *path, struct context *ctx,
                         struct fm_error *error) {
  FILE *f = fopen(path, "r");
  if (!f) return fm_error_set(error, errno, "open context");
  char line[512], a[64], b[64], device[FM_INTERFACE_SIZE];
  unsigned x, y, z;
  while (fgets(line, sizeof(line), f)) {
    if (line[0] == 'R' && sscanf(line, "R %63s %63s %u", a, b, &x) == 3 &&
        ctx->nr < 512) {
      if (!parse_address(a, &ctx->ranges[ctx->nr].lo, error) ||
          !parse_address(b, &ctx->ranges[ctx->nr].hi, error)) goto fail;
      ctx->ranges[ctx->nr++].flags = x;
    } else if (line[0] == 'L' && sscanf(line, "L %63s", a) == 1 && ctx->nl < 256) {
      if (!parse_address(a, &ctx->local[ctx->nl++], error)) goto fail;
    } else if (line[0] == 'N' && sscanf(line, "N %63s %u %15s", a, &x, device) == 3 && ctx->nn < 512) {
      struct net *n = &ctx->nets[ctx->nn];
      if (!parse_address(a, &n->a, error) || x > (n->a.af == 4 ? 32u : 128u)) goto fail;
      n->prefix = x; strcpy(n->device, device); ctx->nn++;
    } else if (line[0] == 'A' && sscanf(line, "A %63s %15s", a, device) == 2 && ctx->na < 512) {
      struct assigned *v = &ctx->assigned[ctx->na];
      if (!parse_address(a, &v->a, error)) goto fail;
      strcpy(v->device, device); ctx->na++;
    } else if (line[0] == 'W' && sscanf(line, "W %15s", device) == 1) {
      strcpy(ctx->wan, device);
    } else if (line[0] == 'S' && sscanf(line, "S %u %u %u", &x, &y, &z) == 3 &&
               ctx->ns < 256 && x <= 255 && y <= 65535) {
      ctx->services[ctx->ns++] = (struct service){x, y, z};
    } else {
      fm_error_set(error, EPROTO, "invalid context row or capacity");
      goto fail;
    }
  }
  if (ferror(f)) { fm_error_set(error, EIO, "read context"); goto fail; }
  fclose(f);
  return true;
fail:
  fclose(f);
  return false;
}

static bool read_fixture(const char *path, struct sample *sample,
                         struct fm_error *error) {
  FILE *f = fopen(path, "rb");
  if (!f) return fm_error_set(error, errno, "open state fixture");
  unsigned char magic[8];
  if (!read_exact(f, magic, 8) || memcmp(magic, "FMPFS2\0", 8)) {
    fm_error_set(error, EPROTO, "state fixture header"); goto fail;
  }
  for (;;) {
    unsigned char length[4], b[MAX_FRAME];
    if (!read_exact(f, length, sizeof(length))) {
      fm_error_set(error, EPROTO, "state fixture truncated"); goto fail;
    }
    const unsigned char *p = length;
    size_t n = protocol_get(&p, 4);
    if (n == 0) {
      unsigned char footer[8];
      if (!read_exact(f, footer, 8)) {
        fm_error_set(error, EPROTO, "state fixture completion"); goto fail;
      }
      const unsigned char *footer_pos = footer;
      if (protocol_get(&footer_pos, 8) != sample->count || fgetc(f) != EOF) {
        fm_error_set(error, EPROTO, "state fixture completion"); goto fail;
      }
      fclose(f); return true;
    }
    if (n > sizeof(b) || n < 171 || !read_exact(f, b, n)) {
      fm_error_set(error, EPROTO, "state fixture frame"); goto fail;
    }
    struct state s = {0}; p = b;
    s.id = protocol_get(&p, 8); s.creator = protocol_get(&p, 4); s.direction = *p++;
    memcpy(s.iface, p, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    memcpy(s.orig, p, FM_INTERFACE_SIZE); p += FM_INTERFACE_SIZE;
    s.age = protocol_get(&p, 4);
    for (unsigned i = 0; i < 2; i++) s.bytes[i] = protocol_get(&p, 8);
    for (unsigned i = 0; i < 2; i++) s.packets[i] = protocol_get(&p, 8);
    memcpy(s.peer, p, 2); p += 2;
    for (unsigned k = 0; k < 2; k++) {
      s.key[k].proto = *p++;
      for (unsigned e = 0; e < 2; e++) {
        s.key[k].e[e].a.af = *p++;
        memcpy(s.key[k].e[e].a.b, p, 16); p += 16;
        s.key[k].e[e].port = protocol_get(&p, 2);
      }
    }
    s.expire = protocol_get(&p, 4); s.rule = protocol_get(&p, 4);
    size_t label_len = protocol_get(&p, 2);
    if (label_len >= sizeof(s.label) || (size_t)(b + n - p) != label_len ||
        memchr(p, 0, label_len)) {
      fm_error_set(error, EPROTO, "state fixture label"); goto fail;
    }
    memcpy(s.label, p, label_len);
    if (!state_callback(&s, sample, error)) goto fail;
  }
fail:
  fclose(f);
  return false;
}

static bool write_capture_footer(FILE *f, uint64_t count,
                                 struct fm_error *error) {
  unsigned char footer[8], *p = footer;
  protocol_put(&p, count, 8);
  return protocol_frame(f, "", 0, NULL, error) &&
         fwrite(footer, 1, sizeof(footer), f) == sizeof(footer);
}
static int report_error(const struct fm_error *error) {
  fprintf(stderr, "%s: %s\n", error->message, strerror(error->code));
  return 1;
}
static bool process_fixture(const char *input, const char *output_path,
                            const struct context *ctx, struct history *history,
                            double elapsed, bool deltas,
                            struct fm_error *error) {
  if (!history_begin(history, elapsed, error)) return false;
  struct aggregate *aggregate = aggregate_create(ctx, history, error);
  if (!aggregate) { history_abort(history); return false; }
  struct sample sample = {.aggregate = aggregate};
  if (!read_fixture(input, &sample, error) ||
      !aggregate_finish(aggregate, error)) {
    history_abort(history);
    aggregate_destroy(aggregate);
    return false;
  }
  FILE *output = fopen(output_path, "wb");
  if (!output || !protocol_write(output, aggregate, deltas, error)) {
    if (output) fclose(output);
    history_abort(history);
    aggregate_destroy(aggregate);
    return false;
  }
  if (fclose(output)) {
    fm_error_set(error, errno, "close aggregate output");
    history_abort(history);
    aggregate_destroy(aggregate);
    return false;
  }
  history_commit(history);
  aggregate_destroy(aggregate);
  return true;
}

static bool read_queries(const char *path,
                         struct event_query queries[FM_MAX_EVENT_QUERIES],
                         size_t *count, struct fm_error *error) {
  FILE *file = fopen(path, "r");
  if (!file)
    return fm_error_set(error, errno, "open event query fixture");
  char line[256], public[64], remote[64];
  unsigned id, protocol, public_port, remote_port;
  while (fgets(line, sizeof(line), file)) {
    if (sscanf(line, "Q %u %u %63s %u %63s %u", &id, &protocol, public,
               &public_port, remote, &remote_port) != 6 ||
        *count >= FM_MAX_EVENT_QUERIES || id != *count || protocol > 255 ||
        public_port > 65535 || remote_port > 65535) {
      fm_error_set(error, EPROTO, "event query fixture row");
      fclose(file);
      return false;
    }
    struct event_query *query = &queries[(*count)++];
    query->id = id;
    query->key.protocol = protocol;
    if (!parse_address(public, &query->key.public.a, error) ||
        !parse_address(remote, &query->key.remote.a, error)) {
      fclose(file);
      return false;
    }
    query->key.public.port = public_port;
    query->key.remote.port = remote_port;
  }
  bool ok = !ferror(file);
  fclose(file);
  return ok || fm_error_set(error, EIO, "read event query fixture");
}

static int correlate_fixture(const char *context_path, const char *input_path,
                             const char *query_path, const char *output_path,
                             struct fm_error *error) {
  struct context *context = calloc(1, sizeof(*context));
  struct history *history = history_create(error);
  struct ranking *ranking = ranking_create(150, 20.0, 0.5, error);
  struct event_history *events = event_history_create(error);
  if (!context || !history || !ranking || !events ||
      !read_context(context_path, context, error) ||
      !history_begin(history, -1, error))
    goto fail;
  struct aggregate *aggregate = aggregate_create(context, history, error);
  if (!aggregate)
    goto fail_history;
  struct sample sample = {.aggregate = aggregate};
  if (!read_fixture(input_path, &sample, error) ||
      !aggregate_finish(aggregate, error) ||
      !event_history_update(events, aggregate, 100.0, error)) {
    aggregate_destroy(aggregate);
    goto fail_history;
  }
  struct event_query queries[FM_MAX_EVENT_QUERIES];
  struct event_match matches[FM_MAX_EVENT_QUERIES];
  size_t query_count = 0;
  if (!read_queries(query_path, queries, &query_count, error) ||
      !ranking_update(ranking, aggregate, 100.0, -1.0, error)) {
    aggregate_destroy(aggregate);
    goto fail_history;
  }
  size_t match_count = event_history_match(events, aggregate, queries,
                                            query_count, matches,
                                            FM_MAX_EVENT_QUERIES, error);
  if (error->code) {
    aggregate_destroy(aggregate);
    goto fail_history;
  }
  FILE *output = fopen(output_path, "wb");
  bool ok = output && protocol_write_ranked(output, aggregate, ranking, NULL,
                                             matches, match_count, error);
  if (output && fclose(output) && !error->code)
    fm_error_set(error, errno, "close event match fixture");
  aggregate_destroy(aggregate);
  if (!ok || error->code)
    goto fail_history;
  history_commit(history);
  history_destroy(history);
  ranking_destroy(ranking);
  event_history_destroy(events);
  free(context);
  return 0;

fail_history:
  history_abort(history);
fail:
  history_destroy(history);
  ranking_destroy(ranking);
  event_history_destroy(events);
  free(context);
  return report_error(error);
}

int main(int argc, char **argv) {
  umask(0077);
  struct timespec begin, end;
  clock_gettime(CLOCK_MONOTONIC, &begin);
  if (argc < 2) return 2;
  struct fm_error error = {0};
  if (argc == 6 && !strcmp(argv[1], "correlate"))
    return correlate_fixture(argv[2], argv[3], argv[4], argv[5], &error);
  if (!strcmp(argv[1], "sequence")) {
    if (argc < 8 || (argc - 4) % 2) return 2;
    struct context *ctx = calloc(1, sizeof(*ctx));
    struct history *history = history_create(&error);
    if (!ctx || !history || !read_context(argv[2], ctx, &error))
      return report_error(&error);
    for (int arg = 4, sample_no = 0; arg < argc; arg += 2, sample_no++) {
      char *end = NULL;
      double elapsed = strtod(argv[arg + 1], &end);
      if (!end || *end || elapsed < -1 || !isfinite(elapsed)) {
        fm_error_set(&error, EINVAL, "sample elapsed time");
        break;
      }
      char path[1024];
      if (snprintf(path, sizeof(path), "%s.%d", argv[3], sample_no) >=
          (int)sizeof(path)) {
        fm_error_set(&error, ENAMETOOLONG, "aggregate output path");
        break;
      }
      if (!process_fixture(argv[arg], path, ctx, history, elapsed, true,
                           &error)) break;
    }
    history_destroy(history); free(ctx);
    return error.code ? report_error(&error) : 0;
  }
  if (!strcmp(argv[1], "reader") || !strcmp(argv[1], "wire")) {
    if (argc != 5 && argc != 6) return 2;
    FILE *capture = fopen(argv[4], "wb");
    if (!capture) return report_error(&(struct fm_error){errno, "open capture"});
    if (fwrite("FMPFS2\0", 1, 8, capture) != 8) return 1;
    struct sample sample = {.capture = capture};
    FILE *raw = argc == 6 && !strcmp(argv[1], "reader")
                    ? fopen(argv[5], "wb") : NULL;
    bool ok = !strcmp(argv[1], "reader")
                  ? pf_reader_live(state_callback, &sample, raw, &error)
                  : argc == 6 && pf_reader_wire(argv[5], state_callback,
                                                &sample, &error);
    if (raw && fclose(raw) && !error.code)
      fm_error_set(&error, errno, "close raw capture");
    if (!ok || !write_capture_footer(capture, sample.count, &error) ||
        fclose(capture)) return report_error(&error);
    return 0;
  }
  if (argc != 5 || (strcmp(argv[1], "live") && strcmp(argv[1], "fixture"))) return 2;
  struct context *ctx = calloc(1, sizeof(*ctx));
  if (!ctx || !read_context(argv[2], ctx, &error)) return report_error(&error);
  struct history *history = history_create(&error);
  if (!history || !history_begin(history, -1, &error)) return report_error(&error);
  struct aggregate *aggregate = aggregate_create(ctx, history, &error);
  if (!aggregate) return report_error(&error);
  struct sample sample = {.aggregate = aggregate};
  bool ok = !strcmp(argv[1], "live")
                ? pf_reader_live(state_callback, &sample, NULL, &error)
                : read_fixture(argv[4], &sample, &error);
  if (!ok || !aggregate_finish(aggregate, &error)) {
    history_abort(history); aggregate_destroy(aggregate); free(ctx);
    history_destroy(history); return report_error(&error);
  }
  history_commit(history);
  FILE *output = fopen(argv[3], "wb");
  if (!output || !protocol_write(output, aggregate, false, &error)) {
    if (output) fclose(output);
    aggregate_destroy(aggregate); history_destroy(history); free(ctx);
    return report_error(&error);
  }
  fclose(output);
  struct aggregate_counts counts = aggregate_counts(aggregate);
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  clock_gettime(CLOCK_MONOTONIC, &end);
  double elapsed_ms = (end.tv_sec - begin.tv_sec) * 1000.0 +
                      (end.tv_nsec - begin.tv_nsec) / 1000000.0;
  long rss_kib = usage.ru_maxrss;
#ifdef __APPLE__
  rss_kib /= 1024;
#endif
  fprintf(stderr, "states=%llu retained=%llu mapped=%llu flows=%zu candidates=%zu correlations=%zu history_bytes=%zu aggregate_bytes=%zu peak_rss_kib=%ld elapsed_ms=%.3f\n",
          (unsigned long long)counts.seen, (unsigned long long)counts.retained,
          (unsigned long long)counts.mapped, counts.flows, counts.candidates,
          aggregate_correlation_count(aggregate), history_bytes(history),
          aggregate_bytes(aggregate), rss_kib, elapsed_ms);
  aggregate_destroy(aggregate); history_destroy(history); free(ctx);
  return 0;
}
