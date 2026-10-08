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

/* Property check of native/context.c: the indexed lookups must equal a naive
 * first-match scan in Python's row order, for random networks (duplicate
 * prefixes on several devices included), exclusions, ranges and addresses.
 * Built and run by tests/test_native_context.py; prints "ok" or a mismatch. */
#include "../native/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned seed = 12345;
static unsigned next(void) {
  seed = seed * 1103515245u + 12345u;
  return seed >> 8;
}
static struct addr random_address(unsigned char af) {
  struct addr a = {.af = af};
  for (unsigned n = 0; n < (af == 4 ? 4u : 16u); n++)
    a.b[n] = (unsigned char)(n < 2 ? 10 + next() % 3 : next());
  return a;
}
static int naive_prefix(struct addr a, const struct net *n) {
  if (a.af != n->a.af) return 0;
  unsigned whole = n->prefix / 8, bits = n->prefix % 8;
  return !memcmp(a.b, n->a.b, whole) &&
         (!bits || ((a.b[whole] ^ n->a.b[whole]) & (0xff << (8 - bits))) == 0);
}
static const char *naive_device(const struct context *ctx, struct addr a, const char *excluded) {
  for (size_t n = 0; n < ctx->nn; n++)
    if ((!excluded || strcmp(ctx->nets[n].device, excluded)) && naive_prefix(a, &ctx->nets[n]))
      return ctx->nets[n].device;
  return NULL;
}
static int compare_prefix(const void *a, const void *b) {
  const struct net *x = a, *y = b;
  return (int)y->prefix - (int)x->prefix;
}

int main(void) {
  const char *devices[] = {"lan0", "lan1", "wan0", "vlan5"};
  for (unsigned round = 0; round < 200; round++) {
    struct fm_error error = {0};
    struct context *ctx = context_create(&error);
    struct net nets[200];
    size_t count = 20 + next() % 180;
    for (size_t n = 0; n < count; n++) {
      unsigned char af = next() % 3 ? 4 : 6;
      nets[n].a = random_address(af);
      nets[n].prefix = af == 4 ? 8 + next() % 25 : 32 + next() % 97;
      strcpy(nets[n].device, devices[next() % 4]);
      if (n && next() % 5 == 0) { /* the same prefix again on another device */
        nets[n] = nets[n - 1];
        strcpy(nets[n].device, devices[next() % 4]);
      }
    }
    /* Python's order: most specific first, stable for equal prefixes */
    for (size_t i = 1; i < count; i++)
      for (size_t j = i; j > 0 && compare_prefix(&nets[j - 1], &nets[j]) > 0; j--) {
        struct net swap = nets[j];
        nets[j] = nets[j - 1];
        nets[j - 1] = swap;
      }
    for (size_t n = 0; n < count; n++)
      context_add_net(ctx, nets[n], &error);
    for (unsigned n = 0; n < 40; n++) {
      struct addr local = random_address(next() % 2 ? 4 : 6);
      context_add_local(ctx, local, &error);
    }
    /* ranges: v4 /8 blocks with alternating flags, then one v6 range */
    for (unsigned n = 0; n < 32; n++) {
      struct range r = {.flags = n % 3};
      r.lo.af = r.hi.af = 4;
      r.lo.b[0] = (unsigned char)(n * 8);
      r.hi.b[0] = (unsigned char)(n * 8 + 7);
      memset(r.hi.b + 1, 0xff, 3);
      context_add_range(ctx, r, &error);
    }
    if (!context_prepare(ctx, &error)) {
      printf("prepare failed: %s\n", error.message);
      return 1;
    }
    for (unsigned probe = 0; probe < 2000; probe++) {
      struct addr a = probe % 2 && ctx->nl ? ctx->local[next() % ctx->nl] : random_address(next() % 3 ? 4 : 6);
      if (probe % 7 == 0) a = nets[next() % count].a;
      const char *excluded = next() % 2 ? devices[next() % 4] : NULL;
      const char *expected = naive_device(ctx, a, excluded), *actual = context_device(ctx, a, excluded);
      if ((expected == NULL) != (actual == NULL) || (expected && strcmp(expected, actual))) {
        printf("device mismatch in round %u\n", round);
        return 1;
      }
      bool local = false;
      for (size_t n = 0; n < ctx->nl; n++) local |= address_equal(a, ctx->local[n]);
      if (local != context_is_local(ctx, a)) {
        printf("local mismatch in round %u\n", round);
        return 1;
      }
      unsigned flags = 0;
      for (size_t n = 0; n < ctx->nr; n++)
        if (a.af == ctx->ranges[n].lo.af && memcmp(a.b, ctx->ranges[n].lo.b, 16) >= 0 &&
            memcmp(a.b, ctx->ranges[n].hi.b, 16) <= 0) {
          flags = ctx->ranges[n].flags;
          break;
        }
      if (flags != address_flags(ctx, a)) {
        printf("flags mismatch in round %u\n", round);
        return 1;
      }
    }
    context_destroy(ctx);
  }
  printf("ok\n");
  return 0;
}
