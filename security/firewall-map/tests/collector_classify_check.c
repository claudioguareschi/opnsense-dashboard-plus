/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
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

/* Property check of collector/classify.c: for random PF-like tables (nested
 * prefixes, duplicates, negated entries, both families, prefix lengths 0 to
 * full), every lookup must equal a naive longest-prefix match over each set.
 * Built and run by tests/test_collector_classify.py; prints "ok" or the
 * first mismatch. */
#include "../collector/classify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng = 0x2545f4914f6cdd1du;
static uint64_t next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}

/* naive: the longest prefix of the set covering a decides (negated excludes) */
static bool member(const struct class_entry *entries, size_t n, struct addr a) {
  int best = -1;
  bool in = false;
  unsigned width = a.af == 4 ? 32 : 128;
  for (size_t i = 0; i < n; i++) {
    const struct class_entry *e = &entries[i];
    if (e->a.af != a.af || e->prefix > width) continue;
    bool covers = true;
    for (unsigned bit = 0; bit < e->prefix && covers; bit++)
      covers = ((e->a.b[bit / 8] >> (7 - bit % 8)) & 1) == ((a.b[bit / 8] >> (7 - bit % 8)) & 1);
    if (covers && (int)e->prefix >= best) {
      best = e->prefix; /* equal length: the later entry wins, as in the compiler */
      in = !e->negated;
    }
  }
  return in;
}

/* addresses near a few random "hot" bases so prefixes actually nest */
static struct addr random_addr(unsigned af, const struct addr *bases) {
  struct addr a = bases[next() % 4];
  a.af = af;
  unsigned bytes = af == 4 ? 4 : 16, flips = next() % 3;
  for (unsigned f = 0; f < flips; f++) a.b[bytes - 1 - next() % 2] ^= (unsigned char)(1u << (next() % 8));
  if (next() % 5 == 0) a.b[next() % bytes] = (unsigned char)next();
  for (unsigned n = bytes; n < 16; n++) a.b[n] = 0;
  return a;
}

int main(void) {
  for (int round = 0; round < 400; round++) {
    size_t sets = 1 + next() % 6;
    struct class_set meta[8];
    struct class_entry *entries[8];
    size_t counts[8];
    struct addr bases[2][4];
    for (int f = 0; f < 2; f++)
      for (int b = 0; b < 4; b++) {
        memset(&bases[f][b], 0, sizeof(bases[f][b]));
        for (int n = 0; n < 16; n++) bases[f][b].b[n] = (unsigned char)next();
      }
    for (size_t s = 0; s < sets; s++) {
      meta[s] = (struct class_set){.id = (unsigned)(s * 7 + round) % 64, .category = "TCO"[s % 3],
                                   .status = next() % 9 ? CLASS_OK : CLASS_MISSING};
      for (size_t t = 0; t < s; t++)
        if (meta[t].id == meta[s].id) meta[s].id = (meta[s].id + 1 + (unsigned)t) % 64;
      counts[s] = next() % 40;
      entries[s] = calloc(counts[s] + 1, sizeof(struct class_entry));
      for (size_t e = 0; e < counts[s]; e++) {
        unsigned af = next() % 3 ? 4 : 6, width = af == 4 ? 32 : 128;
        struct class_entry *x = &entries[s][e];
        x->a = random_addr(af, bases[af == 6]);
        unsigned roll = (unsigned)(next() % 10);
        x->prefix = (unsigned char)(roll == 0 ? 0 : roll < 3 ? width : width - next() % (width / 2));
        x->negated = next() % 4 == 0;
        if (e && next() % 8 == 0) { *x = entries[s][e - 1]; x->negated = !x->negated; } /* duplicate */
      }
    }
    /* ids must be distinct for a meaningful mask */
    for (size_t s = 0; s < sets; s++)
      for (size_t t = 0; t < s; t++)
        if (meta[t].id == meta[s].id) { printf("test setup: duplicate id\n"); return 1; }
    struct fm_error error = {0};
    struct classifier *c = classifier_build(meta, sets, (const struct class_entry *const *)entries, counts, &error);
    if (!c) { printf("build failed: %s\n", error.message); return 1; }
    for (int probe = 0; probe < 3000; probe++) {
      unsigned af = next() % 3 ? 4 : 6;
      struct addr a = random_addr(af, bases[af == 6]);
      if (next() % 7 == 0 && sets && counts[0]) a = entries[0][next() % counts[0]].a; /* exact bases */
      uint64_t want = 0;
      for (size_t s = 0; s < sets; s++)
        if (meta[s].status == CLASS_OK && member(entries[s], counts[s], a))
          want |= UINT64_C(1) << meta[s].id;
      uint64_t got = classifier_lookup(c, a);
      if (got != want) {
        printf("round %d af %u: mask %llx, want %llx\n", round, a.af, (unsigned long long)got,
               (unsigned long long)want);
        for (size_t s = 0; s < sets; s++) {
          printf("  set %zu id %u status %d member %d entries:", s, meta[s].id, meta[s].status,
                 member(entries[s], counts[s], a));
          for (size_t e = 0; e < counts[s]; e++)
            if (entries[s][e].a.af == a.af)
              printf(" %s%u.%u.%u.%u/%u", entries[s][e].negated ? "!" : "", entries[s][e].a.b[0],
                     entries[s][e].a.b[1], entries[s][e].a.b[2], entries[s][e].a.b[3], entries[s][e].prefix);
          printf("\n");
        }
        printf("  addr %u.%u.%u.%u\n", a.b[0], a.b[1], a.b[2], a.b[3]);
        return 1;
      }
    }
    uint64_t threat = 0;
    for (size_t s = 0; s < sets; s++) if (meta[s].category == 'T') threat |= UINT64_C(1) << meta[s].id;
    if (classifier_category(c, 'T') != threat) { printf("category mask\n"); return 1; }
    classifier_destroy(c);
    for (size_t s = 0; s < sets; s++) free(entries[s]);
  }
  if (classifier_lookup(NULL, (struct addr){.af = 4}) != 0) { printf("null snapshot\n"); return 1; }
  printf("ok\n");
  return 0;
}
