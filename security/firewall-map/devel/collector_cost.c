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

/* Development benchmark: the collector's per-state cost by stage, on a recorded kernel dump.
 *
 *   collector_cost record <wire>
 *   collector_cost <context> <wire> <copies> <samples>
 *   collector_cost <context> <wire> <copies> <samples> <recorded|grouped|adversarial>
 *
 * record writes a raw GETSTATES recording of the running firewall (read-only); every sample replays it
 * <copies> times, each copy's states given their own IDs and ports, so a small table becomes a
 * large one with the same attribute mix. Each sample is timed three ways over the same states:
 * decode only (the netlink reader), decode + normalization, and the full path (normalization,
 * baseline history, tracked-flow aggregation and attribution, as the collector's sample pass
 * runs it without a tracked-set limit). Prints nanoseconds per state; the first sample is a
 * baseline (no history), the later ones are steady state. FreeBSD only (the wire reader).
 *
 * With an order, the states are decoded once into memory and only the work after decoding is
 * timed (normalization, history, aggregation, attribution: aggregate_add), in one of three
 * orders: as recorded; grouped (each flow's states together, equal attribution values adjacent:
 * the best locality); adversarial (flows interleaved, and each flow's states alternating between
 * its distinct attribution values: the fewest repeats). A digest of every flow total and
 * attribution value (weight, first-seen, association) shows whether two builds agree exactly.
 * Copies change only ports from 32768 up (ephemeral ports), so services stay as recorded. */
#include "../collector/aggregate.h"
#include "../collector/context.h"
#include "../collector/history.h"
#include "../collector/pf_reader.h"
#include "../collector/state.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/resource.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netlink/netlink.h>
#include <netlink/netlink_generic.h>
#include <netpfil/pf/pf_nl.h>

enum stage { DECODE, NORMALIZE, FULL };
struct run {
  enum stage stage;
  unsigned copy;
  const struct context *ctx;
  struct aggregate *aggregate;
  uint64_t states;
};

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static bool parse_address(const char *text, struct addr *out) {
  memset(out, 0, sizeof(*out));
  out->af = strchr(text, ':') ? 6 : 4;
  return inet_pton(out->af == 4 ? AF_INET : AF_INET6, text, out->b) == 1;
}
static bool read_context(const char *path, struct context *ctx, struct fm_error *error) {
  FILE *f = fopen(path, "r");
  if (!f) return fm_error_set(error, errno, "open context");
  char line[512], a[64], b[64], device[FM_INTERFACE_SIZE];
  unsigned x, y, z;
  bool ok = true;
  while (ok && fgets(line, sizeof(line), f)) {
    if (line[0] == 'R' && sscanf(line, "R %63s %63s %u", a, b, &x) == 3) {
      struct range r = {.flags = x};
      ok = parse_address(a, &r.lo) && parse_address(b, &r.hi) && context_add_range(ctx, r, error);
    } else if (line[0] == 'L' && sscanf(line, "L %63s", a) == 1) {
      struct addr local;
      ok = parse_address(a, &local) && context_add_local(ctx, local, error);
    } else if (line[0] == 'N' && sscanf(line, "N %63s %u %15s", a, &x, device) == 3) {
      struct net n = {.prefix = x};
      strcpy(n.device, device);
      ok = parse_address(a, &n.a) && context_add_net(ctx, n, error);
    } else if (line[0] == 'A' && sscanf(line, "A %63s %15s", a, device) == 2) {
      struct assigned v;
      strcpy(v.device, device);
      ok = parse_address(a, &v.a) && context_add_assigned(ctx, v, error);
    } else if (line[0] == 'W' && sscanf(line, "W %15s", device) == 1) {
      strcpy(ctx->wan, device);
    } else if (line[0] == 'S' && sscanf(line, "S %u %u %u", &x, &y, &z) == 3) {
      ok = context_add_service(ctx, (struct service){x, y, z}, error);
    }
  }
  fclose(f);
  return (ok || fm_error_set(error, EPROTO, "context row")) && context_prepare(ctx, error);
}

/* A copy of a recorded state, made distinct: its own ID, and its own ports (so its own tuples
 * and correlation keys, on the same flows). */
static bool replay(const struct state *recorded, void *arg, struct fm_error *error) {
  struct run *run = arg;
  struct state s = *recorded;
  s.id += (uint64_t)run->copy << 40;
  for (unsigned k = 0; k < 2; k++)
    for (unsigned e = 0; e < 2; e++)
      if (s.key[k].e[e].port >= 32768)
        s.key[k].e[e].port = (uint16_t)(32768 + (s.key[k].e[e].port - 32768 + run->copy * 7919u) % 32768);
  run->states++;
  if (run->stage == DECODE) return true;
  if (run->stage == NORMALIZE) {
    struct state_view view;
    return state_normalize(&s, run->ctx, &view, error);
  }
  return aggregate_add(run->aggregate, &s, error);
}

/* The recording in memory: its frames, sequence and family (FMNLLE1). */
struct frames {
  unsigned char **data;
  size_t *size, count;
  uint32_t seq;
  int family;
};
static bool load(const char *path, struct frames *out) {
  FILE *f = fopen(path, "rb");
  unsigned char header[16], length[4];
  if (!f || fread(header, 1, 16, f) != 16) return false;
  /* big-endian, as the recorder writes them (protocol_put) */
  out->seq = (uint32_t)header[8] << 24 | (uint32_t)header[9] << 16 | (uint32_t)header[10] << 8 | header[11];
  out->family = (int)((uint32_t)header[12] << 24 | (uint32_t)header[13] << 16 | (uint32_t)header[14] << 8 | header[15]);
  while (fread(length, 1, 4, f) == 4) {
    uint32_t n = (uint32_t)length[0] << 24 | (uint32_t)length[1] << 16 | (uint32_t)length[2] << 8 | length[3];
    out->data = realloc(out->data, (out->count + 1) * sizeof(*out->data));
    out->size = realloc(out->size, (out->count + 1) * sizeof(*out->size));
    out->data[out->count] = malloc(n);
    if (fread(out->data[out->count], 1, n, f) != n) return false;
    out->size[out->count++] = n;
  }
  fclose(f);
  return true;
}
/* A lower bound: every attribute walked (keys and peers too), nothing decoded or checked. */
static uint64_t walk_attributes(const unsigned char *p, size_t n, bool nested) {
  uint64_t count = 0;
  while (n >= sizeof(struct nlattr)) {
    struct nlattr a;
    memcpy(&a, p, sizeof(a));
    if (a.nla_len < sizeof(a) || NLA_ALIGN(a.nla_len) > n) break;
    unsigned type = a.nla_type & NLA_TYPE_MASK;
    count++;
    if (nested && (type == PF_ST_KEY_WIRE || type == PF_ST_KEY_STACK || type == PF_ST_PEER_SRC ||
                   type == PF_ST_PEER_DST))
      count += walk_attributes(p + sizeof(a), a.nla_len - sizeof(a), false);
    size_t step = NLA_ALIGN(a.nla_len);
    p += step;
    n -= step;
  }
  return count;
}
static uint64_t walk(const unsigned char *p, size_t n, uint64_t *states) {
  uint64_t count = 0;
  while (n >= sizeof(struct nlmsghdr)) {
    const struct nlmsghdr *h = (const void *)p;
    if (h->nlmsg_len < sizeof(*h) || NLMSG_ALIGN(h->nlmsg_len) > n) break;
    if (h->nlmsg_type != NLMSG_DONE && h->nlmsg_type != NLMSG_ERROR) {
      (*states)++;
      size_t head = sizeof(*h) + sizeof(struct genlmsghdr);
      count += walk_attributes(p + head, h->nlmsg_len - head, true);
    }
    size_t step = NLMSG_ALIGN(h->nlmsg_len);
    p += step;
    n -= step;
  }
  return count;
}

/* -------- the work after decoding, on states decoded into memory -------- */
struct entry {
  struct state s;
  unsigned char flow[FM_FLOW_KEY_SIZE];
  unsigned char signature[64]; /* the attribution values of the state */
  uint32_t rank;               /* position within its flow's value group (adversarial order) */
};
struct collection {
  struct entry *items;
  size_t count, capacity;
  struct run run;
};
static bool collect(const struct state *recorded, void *arg, struct fm_error *error) {
  struct collection *c = arg;
  struct state s = *recorded;
  for (unsigned k = 0; k < 2; k++)
    for (unsigned e = 0; e < 2; e++)
      if (s.key[k].e[e].port >= 32768)
        s.key[k].e[e].port = (uint16_t)(32768 + (s.key[k].e[e].port - 32768 + c->run.copy * 7919u) % 32768);
  s.id += (uint64_t)c->run.copy << 40;
  if (c->count == c->capacity) {
    c->capacity = c->capacity ? c->capacity * 2 : 4096;
    c->items = realloc(c->items, c->capacity * sizeof(*c->items));
  }
  struct entry *it = &c->items[c->count];
  memset(it, 0, sizeof(*it));
  it->s = s;
  struct state_view v;
  if (!state_normalize(&s, c->run.ctx, &v, error)) return false;
  if (v.mapped) state_flow_key(it->flow, v.local, v.remote);
  unsigned char *p = it->signature;
  *p++ = v.pf.proto;
  memcpy(p, v.inside.a.b, 16); p += 16;
  memcpy(p, s.original_interface, 16); p += 16;
  *p++ = (unsigned char)(v.service_port >> 8); *p++ = (unsigned char)v.service_port;
  memcpy(p, v.remote_endpoint.a.b, 16); p += 16;
  *p++ = (unsigned char)(v.remote_endpoint.port >> 8); *p++ = (unsigned char)v.remote_endpoint.port;
  c->count++;
  return true;
}
static int by_flow_then_values(const void *x, const void *y) {
  const struct entry *a = x, *b = y;
  int c = memcmp(a->flow, b->flow, FM_FLOW_KEY_SIZE);
  return c ? c : memcmp(a->signature, b->signature, sizeof(a->signature));
}
static int adversarial(const void *x, const void *y) {
  const struct entry *a = x, *b = y;
  /* first every flow's first value, then every flow's second value...: each flow's consecutive
   * states differ, and consecutive states belong to different flows */
  if (a->rank != b->rank) return a->rank < b->rank ? -1 : 1;
  int c = memcmp(a->flow, b->flow, FM_FLOW_KEY_SIZE);
  return c ? c : memcmp(a->signature, b->signature, sizeof(a->signature));
}
static void order(struct collection *c, const char *how) {
  if (!strcmp(how, "recorded")) return;
  qsort(c->items, c->count, sizeof(*c->items), by_flow_then_values);
  if (!strcmp(how, "grouped")) return;
  /* rank: within a flow, the n-th state of each value goes to round n, the values interleaved */
  for (size_t n = 0, start = 0; n <= c->count; n++) {
    if (n < c->count && !memcmp(c->items[n].flow, c->items[start].flow, FM_FLOW_KEY_SIZE)) continue;
    /* items[start, n): one flow, sorted by value; spread each value's repeats over rounds */
    uint32_t round = 0;
    for (size_t k = start; k < n; k++) {
      bool same = k > start && !memcmp(c->items[k].signature, c->items[k - 1].signature, sizeof(c->items[k].signature));
      round = same ? round + 1 : 0;
      c->items[k].rank = round;
    }
    start = n;
  }
  qsort(c->items, c->count, sizeof(*c->items), adversarial);
}
static uint64_t mix(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = data;
  for (size_t k = 0; k < n; k++) h = (h ^ p[k]) * UINT64_C(0x100000001b3);
  return h;
}
static uint64_t digest(const struct aggregate *a) {
  uint64_t h = UINT64_C(0xcbf29ce484222325);
  struct aggregate_counts counts = aggregate_counts(a);
  for (size_t n = 0; n < counts.flows; n++) {
    const struct flow *f = aggregate_flow(a, n);
    h = mix(h, &f->local, sizeof(f->local));
    h = mix(h, &f->remote, sizeof(f->remote));
    uint64_t totals[] = {f->states, f->bytes_from_remote, f->bytes_to_remote, f->remote_initiated_weight,
                         f->local_initiated_weight, f->remote_initiated_states, f->local_initiated_states, f->first,
                         f->created, f->oldest, f->youngest, f->delta.bytes_from_remote, f->delta.bytes_to_remote,
                         f->delta.packets, f->evicted};
    h = mix(h, totals, sizeof(totals));
  }
  for (size_t n = 0; n < counts.candidates; n++) {
    struct candidate_view v;
    if (!aggregate_candidate(a, n, &v)) continue;
    uint64_t fields[] = {v.flow, v.kind, v.len, v.seq, v.weight, v.association};
    h = mix(h, fields, sizeof(fields));
    h = mix(h, v.data, v.len);
  }
  uint64_t tail[] = {counts.candidates, counts.candidate_evictions, counts.join_refused, counts.flows};
  return mix(h, tail, sizeof(tail));
}
static int post_decode(const char *context, const char *wire, unsigned copies, unsigned samples, const char *how) {
  struct fm_error error = {0};
  struct context *ctx = context_create(&error);
  struct history *history = ctx && read_context(context, ctx, &error) ? history_create(&error) : NULL;
  struct collection c = {.run = {.ctx = ctx}};
  for (c.run.copy = 0; history && c.run.copy < copies && !error.code; c.run.copy++)
    pf_reader_wire(wire, collect, &c, &error);
  if (!history || error.code) {
    fprintf(stderr, "collector_cost: %s\n", error.message);
    return 1;
  }
  order(&c, how);
  double clock = 1000;
  for (unsigned sample = 1; sample <= samples; sample++) {
    clock += 2;
    struct aggregate *a = history_begin(history, clock, &error) ? aggregate_create(ctx, history, NULL, NULL, &error) : NULL;
    if (!a) break;
    double started = now();
    for (size_t n = 0; n < c.count && !error.code; n++) aggregate_add(a, &c.items[n].s, &error);
    double added = now();
    if (!error.code) aggregate_finish(a, &error);
    double finished = now();
    if (error.code) {
      history_abort(history);
      aggregate_destroy(a);
      break;
    }
    history_commit(history);
    struct aggregate_counts counts = aggregate_counts(a);
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    printf("%s sample %u: %zu states, %zu flows, %zu candidates | after decode %.0f ns/state, finish %.1f ms | "
           "digest %016llx | max RSS %ld KiB\n",
           how, sample, c.count, counts.flows, counts.candidates, (added - started) * 1e9 / (c.count ? c.count : 1),
           (finished - added) * 1e3, (unsigned long long)digest(a), (long)usage.ru_maxrss);
    aggregate_destroy(a);
  }
  if (error.code) {
    fprintf(stderr, "collector_cost: %s\n", error.message);
    return 1;
  }
  free(c.items);
  history_destroy(history);
  context_destroy(ctx);
  return 0;
}

static bool ignore(const struct state *s, void *arg, struct fm_error *error) {
  (void)s;
  (void)error;
  (*(uint64_t *)arg)++;
  return true;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "record")) {
    struct fm_error error = {0};
    uint64_t states = 0;
    FILE *raw = fopen(argv[2], "wb");
    bool ok = raw && pf_reader_live(ignore, &states, raw, NULL, &error);
    if (raw && fclose(raw) && ok) ok = fm_error_set(&error, errno, "close recording");
    if (!ok) {
      fprintf(stderr, "collector_cost: %s\n", raw ? error.message : "open recording");
      return 1;
    }
    printf("%llu states recorded\n", (unsigned long long)states);
    return 0;
  }
  if (argc == 6)
    return post_decode(argv[1], argv[2], (unsigned)strtoul(argv[3], NULL, 10), (unsigned)strtoul(argv[4], NULL, 10),
                       argv[5]);
  if (argc != 5) {
    fprintf(stderr, "usage: collector_cost record <wire> | collector_cost <context> <wire> <copies> <samples> "
                    "[recorded|grouped|adversarial]\n");
    return 2;
  }
  unsigned copies = (unsigned)strtoul(argv[3], NULL, 10), samples = (unsigned)strtoul(argv[4], NULL, 10);
  struct fm_error error = {0};
  struct context *ctx = context_create(&error);
  struct history *history = ctx && read_context(argv[1], ctx, &error) ? history_create(&error) : NULL;
  if (!history) {
    fprintf(stderr, "collector_cost: %s\n", error.message);
    return 1;
  }
  /* the recording in memory: the decoder alone, and the bare attribute walk */
  struct frames frames = {0};
  if (!load(argv[2], &frames)) {
    fprintf(stderr, "collector_cost: cannot load %s\n", argv[2]);
    return 1;
  }
  uint64_t decoded = 0, walked = 0, attributes = 0;
  double started = now();
  for (unsigned copy = 0; copy < copies && !error.code; copy++)
    for (size_t n = 0; n < frames.count && !error.code; n++) {
      bool done;
      pf_reader_decode_datagram(frames.data[n], frames.size[n], frames.seq, frames.family, ignore, &decoded,
                                &done, &error);
    }
  double decode_ns = (now() - started) * 1e9 / (decoded ? decoded : 1);
  started = now();
  for (unsigned copy = 0; copy < copies; copy++)
    for (size_t n = 0; n < frames.count; n++) attributes += walk(frames.data[n], frames.size[n], &walked);
  double walk_ns = (now() - started) * 1e9 / (walked ? walked : 1);
  printf("in memory: %llu states, %.1f attributes each | ns/state: decoder %.0f, bare walk %.0f\n",
         (unsigned long long)decoded, walked ? (double)attributes / walked : 0, decode_ns, walk_ns);
  double clock = 1000;
  for (unsigned sample = 1; sample <= samples; sample++) {
    double per[3] = {0};
    uint64_t states = 0;
    for (int stage = DECODE; stage <= FULL; stage++) {
      struct run run = {.stage = stage, .ctx = ctx};
      if (stage == FULL) {
        clock += 2;
        if (!history_begin(history, clock, &error) ||
            !(run.aggregate = aggregate_create(ctx, history, NULL, NULL, &error)))
          break;
      }
      double started = now();
      for (run.copy = 0; run.copy < copies && !error.code; run.copy++)
        if (!pf_reader_wire(argv[2], replay, &run, &error)) break;
      if (stage == FULL && !error.code) aggregate_finish(run.aggregate, &error);
      per[stage] = (now() - started) * 1e9 / (run.states ? run.states : 1);
      states = run.states;
      if (stage == FULL) {
        if (!error.code) history_commit(history);
        else history_abort(history);
        struct aggregate_counts counts = aggregate_counts(run.aggregate);
        printf("sample %u: %llu states, %zu flows, %zu candidates | ns/state: decode %.0f, normalize %.0f, "
               "history+aggregate %.0f, total %.0f\n",
               sample, (unsigned long long)states, counts.flows, counts.candidates, per[DECODE],
               per[NORMALIZE] - per[DECODE], per[FULL] - per[NORMALIZE], per[FULL]);
        aggregate_destroy(run.aggregate);
      }
      if (error.code) break;
    }
    if (error.code) {
      fprintf(stderr, "collector_cost: %s\n", error.message);
      return 1;
    }
  }
  history_destroy(history);
  context_destroy(ctx);
  return 0;
}
