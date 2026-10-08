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

/* Written from the SipHash specification (https://www.aumasson.jp/siphash/). */
#include "siphash.h"

static uint64_t rotate(uint64_t value, unsigned bits) {
  return (value << bits) | (value >> (64 - bits));
}
static uint64_t load64(const uint8_t *p) {
  uint64_t value = 0;
  for (unsigned n = 0; n < 8; n++)
    value |= (uint64_t)p[n] << (8 * n);
  return value;
}
struct sip {
  uint64_t v0, v1, v2, v3;
};
static void round_(struct sip *s) {
  s->v0 += s->v1;
  s->v1 = rotate(s->v1, 13);
  s->v1 ^= s->v0;
  s->v0 = rotate(s->v0, 32);
  s->v2 += s->v3;
  s->v3 = rotate(s->v3, 16);
  s->v3 ^= s->v2;
  s->v0 += s->v3;
  s->v3 = rotate(s->v3, 21);
  s->v3 ^= s->v0;
  s->v2 += s->v1;
  s->v1 = rotate(s->v1, 17);
  s->v1 ^= s->v2;
  s->v2 = rotate(s->v2, 32);
}
uint64_t siphash(const uint8_t key[16], const void *data, size_t length,
                 unsigned compression, unsigned finalization) {
  uint64_t k0 = load64(key), k1 = load64(key + 8);
  struct sip s = {k0 ^ UINT64_C(0x736f6d6570736575), k1 ^ UINT64_C(0x646f72616e646f6d),
                  k0 ^ UINT64_C(0x6c7967656e657261), k1 ^ UINT64_C(0x7465646279746573)};
  const uint8_t *p = data;
  size_t whole = length - length % 8;
  for (size_t offset = 0; offset < whole; offset += 8) {
    uint64_t m = load64(p + offset);
    s.v3 ^= m;
    for (unsigned n = 0; n < compression; n++)
      round_(&s);
    s.v0 ^= m;
  }
  uint64_t last = (uint64_t)length << 56;
  for (size_t n = 0; n < length % 8; n++)
    last |= (uint64_t)p[whole + n] << (8 * n);
  s.v3 ^= last;
  for (unsigned n = 0; n < compression; n++)
    round_(&s);
  s.v0 ^= last;
  s.v2 ^= 0xff;
  for (unsigned n = 0; n < finalization; n++)
    round_(&s);
  return s.v0 ^ s.v1 ^ s.v2 ^ s.v3;
}
