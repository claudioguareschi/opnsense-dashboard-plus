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


/* Offline benchmark of bounded discovery against an exact oracle (0.60 plan,
 * Milestone 3). Synthetic corpora, no PF: each corpus is a stream of (flow,
 * byte delta) states. For several summary capacities `m` and stream orders it
 * reports top-150 recall against the exact byte-delta ranking, how many of the
 * exact top 150 were certainly found (lower bound above the 151st estimate),
 * whether the 150th position was mathematically indeterminate, the error
 * floor, CPU per state and summary memory.
 *
 *   cc -O2 -I collector devel/discovery_bench.c collector/discovery.c \
 *      collector/index.c collector/siphash.c collector/alloc.c collector/error.c -lm
 *   ./a.out [corpus...]
 */
#include "../collector/discovery.h"
#include "../collector/index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOP 150

struct corpus {
  const char *name;
  unsigned states, flows;
  int shape; /* 0 zipf, 1 flat, 2 one huge flow of tiny states, 3 scan, 4 near-equal tops */
};
static const struct corpus corpora[] = {
    {"806k/40k zipf (8 GB default)", 806000, 40000, 0},
    {"1.6M/80k zipf (16 GB default)", 1600000, 80000, 0},
    {"3.26M/160k zipf (32 GB default)", 3260000, 160000, 0},
    {"1M/10k zipf", 1000000, 10000, 0},
    {"1M/1M flat", 1000000, 1000000, 1},
    {"5M/50k zipf", 5000000, 50000, 0},
    {"5M/5M flat", 5000000, 5000000, 1},
    {"1M, one flow of 300k tiny states", 1000000, 100000, 2},
    {"1M scan (each state its own flow)", 1000000, 1000000, 3},
    {"1M/100k near-equal top 200", 1000000, 100000, 4},
};

static uint64_t rng;
static uint64_t next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}
struct state_row {
  uint32_t flow;
  uint32_t weight;
};
static void key_of(uint32_t n, unsigned char key[FM_FLOW_KEY_SIZE]) {
  memset(key, 0, FM_FLOW_KEY_SIZE);
  key[0] = 4;
  memcpy(key + 1, &n, sizeof(n));
  key[17] = 4;
  key[18] = 9;
}
static uint64_t *exact;
static int by_exact(const void *l, const void *r) {
  uint32_t a = *(const uint32_t *)l, b = *(const uint32_t *)r;
  return exact[a] != exact[b] ? (exact[a] > exact[b] ? -1 : 1) : (a > b) - (a < b);
}

/* Flow traffic (sum of its states' deltas), then each state's share. 70% of
 * states are idle (delta 0), as on a real table. */
static struct state_row *build(const struct corpus *c, size_t *count) {
  struct state_row *rows = malloc(sizeof(*rows) * c->states);
  for (unsigned n = 0; n < c->states; n++) {
    uint32_t flow;
    uint64_t weight;
    switch (c->shape) {
    case 0: { /* zipf-like popularity: state counts and traffic both skewed */
      double u = (double)(next() % 1000000 + 1) / 1000001.0;
      flow = (uint32_t)((double)c->flows * u * u * u);
      weight = (next() % 10 < 7) ? 0 : (uint64_t)(40000.0 / (1.0 + flow)) + next() % 1500;
      break;
    }
    case 1:
      flow = (uint32_t)(next() % c->flows);
      weight = next() % 10 < 7 ? 0 : 1 + next() % 1500;
      break;
    case 2:
      flow = n < 300000 ? 0 : 1 + (uint32_t)(next() % (c->flows - 1));
      weight = n < 300000 ? 1 + next() % 3 : (next() % 10 < 7 ? 0 : 1 + next() % 1500);
      break;
    case 3:
      flow = n;
      weight = next() % 4 ? 0 : 60 + next() % 100;
      break;
    default:
      flow = n % 20 == 0 ? (uint32_t)(next() % 200) : 200 + (uint32_t)(next() % (c->flows - 200));
      weight = n % 20 == 0 ? 5000 + next() % 100 : (next() % 10 < 7 ? 0 : 1 + next() % 1500);
      break;
    }
    rows[n] = (struct state_row){flow, (uint32_t)weight};
  }
  *count = c->states;
  return rows;
}

int main(int argc, char **argv) {
  uint8_t hash_key[16] = {7, 1, 2};
  index_set_hash_key(hash_key);
  static const size_t capacities[] = {16384, 32768, 65536};
  static const char *orders[] = {"generated", "shuffled", "heavy last"};
  printf("%-34s %-10s %6s %7s %7s %6s %9s %8s %7s\n", "corpus", "order", "m", "recall", "certain",
         "indet", "floor", "ns/state", "MiB");
  for (size_t c = 0; c < sizeof(corpora) / sizeof(*corpora); c++) {
    if (argc > 1 && !strstr(corpora[c].name, argv[1])) continue;
    rng = 0x2545F4914F6CDD1Du + c;
    size_t count;
    struct state_row *rows = build(&corpora[c], &count);
    exact = calloc(corpora[c].flows, sizeof(*exact));
    for (size_t n = 0; n < count; n++) exact[rows[n].flow] += rows[n].weight;
    uint32_t *order = malloc(sizeof(*order) * corpora[c].flows);
    for (uint32_t f = 0; f < corpora[c].flows; f++) order[f] = f;
    qsort(order, corpora[c].flows, sizeof(*order), by_exact);
    for (int o = 0; o < 3; o++) {
      if (o == 1)
        for (size_t n = count - 1; n > 0; n--) {
          size_t k = next() % (n + 1);
          struct state_row t = rows[n];
          rows[n] = rows[k];
          rows[k] = t;
        }
      if (o == 2) { /* adversarial: every state of the true top 150 comes last */
        unsigned char *top = calloc(corpora[c].flows, 1);
        for (int n = 0; n < TOP && n < (int)corpora[c].flows; n++) top[order[n]] = 1;
        size_t w = 0;
        struct state_row *sorted = malloc(sizeof(*sorted) * count);
        for (size_t n = 0; n < count; n++)
          if (!top[rows[n].flow]) sorted[w++] = rows[n];
        for (size_t n = 0; n < count; n++)
          if (top[rows[n].flow]) sorted[w++] = rows[n];
        memcpy(rows, sorted, sizeof(*rows) * count);
        free(sorted);
        free(top);
      }
      for (size_t m = 0; m < sizeof(capacities) / sizeof(*capacities); m++) {
        struct fm_error error = {0};
        struct summary *s = summary_create(capacities[m], &error);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (size_t n = 0; n < count; n++) {
          unsigned char key[FM_FLOW_KEY_SIZE];
          key_of(rows[n].flow, key);
          if (rows[n].weight) summary_add(s, key, index_hash(key, sizeof(key)), rows[n].weight);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        struct summary_entry top[TOP + 1];
        size_t got = summary_top(s, top, TOP + 1);
        /* recall: exact top-150 flows (with traffic) present in the summary's top 150 */
        size_t wanted = 0, found = 0, certain = 0;
        uint64_t next_estimate = got > TOP ? top[TOP].count : 0;
        for (int n = 0; n < TOP && n < (int)corpora[c].flows; n++) {
          if (!exact[order[n]]) break;
          wanted++;
          unsigned char key[FM_FLOW_KEY_SIZE];
          key_of(order[n], key);
          for (size_t k = 0; k < got && k < TOP; k++)
            if (!memcmp(top[k].key, key, sizeof(key))) {
              found++;
              certain += top[k].count - top[k].error > next_estimate;
              break;
            }
        }
        /* the 150th position is indeterminate when its lower bound does not
         * exceed the next estimate or the floor of absent keys */
        bool indeterminate = got >= TOP && (top[TOP - 1].count - top[TOP - 1].error <= next_estimate ||
                                            top[TOP - 1].count - top[TOP - 1].error <= summary_floor(s));
        double seconds = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        printf("%-34s %-10s %6zu %6.1f%% %6.1f%% %6s %9llu %8.1f %7.1f\n", corpora[c].name, orders[o],
               capacities[m], wanted ? 100.0 * (double)found / (double)wanted : 100.0,
               wanted ? 100.0 * (double)certain / (double)wanted : 100.0, indeterminate ? "yes" : "no",
               (unsigned long long)summary_floor(s), seconds * 1e9 / (double)count,
               (double)summary_bytes(s) / 1048576.0);
        summary_destroy(s);
      }
    }
    free(order);
    free(exact);
    free(rows);
  }
  return 0;
}
