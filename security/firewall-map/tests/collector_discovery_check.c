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


/* Property check of collector/discovery.c against exact counts: Space-Saving
 * estimates never undercount, overcount by at most their error, bound every
 * absent key by the floor, are exact without evictions, and do not depend on
 * the hash key; the cardinality estimate stays within 5%. Built and run by
 * tests/test_collector_discovery.py; prints "ok" or the first violation. */
#include "../collector/discovery.h"
#include "../collector/index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYS 20000

static uint64_t rng;
static uint64_t next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}
static void key_of(unsigned n, unsigned char key[FM_FLOW_KEY_SIZE]) {
  memset(key, 0, FM_FLOW_KEY_SIZE);
  key[0] = 4;
  memcpy(key + 1, &n, sizeof(n));
  key[17] = 4;
}

static uint64_t exact[KEYS];

/* One stream: `count` updates over `keys` keys drawn by `shape`. */
static int run(const char *name, size_t capacity, unsigned keys, unsigned count, int shape,
               uint64_t seed, struct summary_entry *top, size_t *top_count) {
  struct fm_error error = {0};
  struct summary *s = summary_create(capacity, &error);
  if (!s) {
    printf("%s: create failed\n", name);
    return 1;
  }
  memset(exact, 0, sizeof(exact));
  rng = seed;
  for (unsigned n = 0; n < count; n++) {
    unsigned k;
    if (shape == 0) k = (unsigned)(next() % keys);                       /* flat */
    else if (shape == 1) k = (unsigned)((next() % keys) * (next() % keys) / keys); /* skewed */
    else k = n % 7 == 0 ? (unsigned)(next() % 5) : (unsigned)(next() % keys); /* few heavy */
    uint64_t weight = 1 + next() % 1500;
    unsigned char key[FM_FLOW_KEY_SIZE];
    key_of(k, key);
    summary_add(s, key, index_hash(key, sizeof(key)), weight, 1);
    exact[k] += weight;
  }
  uint64_t floor = summary_floor(s);
  bool evicted = summary_evictions(s) > 0;
  for (unsigned k = 0; k < keys; k++) {
    unsigned char key[FM_FLOW_KEY_SIZE];
    key_of(k, key);
    const struct summary_entry *e = summary_find(s, key, index_hash(key, sizeof(key)));
    if (!e) {
      if (exact[k] > floor || (!evicted && exact[k])) {
        printf("%s: key %u absent with %llu > floor %llu\n", name, k, (unsigned long long)exact[k],
               (unsigned long long)floor);
        return 1;
      }
      continue;
    }
    if (e->count < exact[k] || e->count - e->error > exact[k] || (!evicted && e->count != exact[k])) {
      printf("%s: key %u estimate %llu error %llu exact %llu\n", name, k, (unsigned long long)e->count,
             (unsigned long long)e->error, (unsigned long long)exact[k]);
      return 1;
    }
  }
  *top_count = summary_top(s, top, 150);
  for (size_t n = 1; n < *top_count; n++)
    if (top[n].count > top[n - 1].count) {
      printf("%s: top order\n", name);
      return 1;
    }
  summary_reset(s);
  if (summary_count(s) || summary_floor(s)) {
    printf("%s: reset\n", name);
    return 1;
  }
  /* the same keys again after a reset: every one is new, counted once */
  for (unsigned k = 0; k < keys && k < capacity; k++) {
    unsigned char key[FM_FLOW_KEY_SIZE];
    key_of(k, key);
    summary_add(s, key, index_hash(key, sizeof(key)), 1, 1);
  }
  if (summary_count(s) != (keys < capacity ? keys : capacity) || summary_evictions(s)) {
    printf("%s: %zu keys after a reset\n", name, summary_count(s));
    return 1;
  }
  summary_destroy(s);
  return 0;
}

int main(void) {
  static struct summary_entry first[150], second[150];
  static const struct {
    const char *name;
    size_t capacity;
    unsigned keys;
    int shape;
  } cases[] = {
      {"fits", 4096, 3000, 0},  {"flat", 1024, KEYS, 0}, {"skewed", 1024, KEYS, 1},
      {"heavy", 512, KEYS, 2},  {"tiny", 1, 50, 1},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(*cases); c++) {
    size_t a, b;
    uint8_t hash_key[16] = {1};
    index_set_hash_key(hash_key);
    if (run(cases[c].name, cases[c].capacity, cases[c].keys, 200000, cases[c].shape, 0x9e3779b97f4a7c15u + c,
            first, &a))
      return 1;
    hash_key[0] = 99;
    hash_key[7] = 3;
    index_set_hash_key(hash_key);
    if (run(cases[c].name, cases[c].capacity, cases[c].keys, 200000, cases[c].shape, 0x9e3779b97f4a7c15u + c,
            second, &b))
      return 1;
    if (a != b || memcmp(first, second, a * sizeof(*first))) {
      printf("%s: result depends on the hash key\n", cases[c].name);
      return 1;
    }
  }
  /* cardinality */
  static const unsigned sizes[] = {0, 1, 100, 3000, 50000, 1000000};
  for (size_t n = 0; n < sizeof(sizes) / sizeof(*sizes); n++) {
    struct cardinality c;
    cardinality_reset(&c);
    for (unsigned k = 0; k < sizes[n]; k++) {
      unsigned char key[FM_FLOW_KEY_SIZE];
      key_of(k, key);
      cardinality_add(&c, key);
      if (k % 3 == 0) cardinality_add(&c, key); /* duplicates do not count */
    }
    double estimate = (double)cardinality_estimate(&c), want = sizes[n];
    if (estimate < want * 0.95 - 1 || estimate > want * 1.05 + 1) {
      printf("cardinality %u estimated %.0f\n", sizes[n], estimate);
      return 1;
    }
  }
  printf("ok\n");
  return 0;
}
