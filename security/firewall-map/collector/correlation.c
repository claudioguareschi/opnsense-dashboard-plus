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

#include "correlation.h"
#include "index.h"
#include "alloc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct correlation {
  struct map keys;
  struct correlation_value *values;
  size_t allocated;
};
static size_t encode(unsigned char *out, struct outside_key key) {
  unsigned char *p = out;
  *p++ = key.protocol;
  for (unsigned n = 0; n < 2; n++) {
    const struct endpoint *endpoint = n ? &key.remote : &key.public;
    *p++ = endpoint->a.af;
    memcpy(p, endpoint->a.b, 16); p += 16;
    uint16_t port = htons(endpoint->port);
    memcpy(p, &port, 2); p += 2;
  }
  return (size_t)(p - out);
}
struct correlation *correlation_create(struct fm_error *error) {
  struct correlation *c = fm_calloc(1, sizeof(*c));
  if (!c) fm_error_set(error, errno, "correlation allocation");
  return c;
}
void correlation_destroy(struct correlation *c) {
  if (!c) return;
  map_clear(&c->keys);
  fm_free(c->values);
  fm_free(c);
}
bool correlation_add(struct correlation *c, struct outside_key key,
                     const struct correlation_value *value,
                     struct fm_error *error) {
  if ((key.public.a.af != 4 && key.public.a.af != 6) ||
      (key.remote.a.af != 4 && key.remote.a.af != 6))
    return fm_error_set(error, EINVAL, "correlation address family");
  unsigned char encoded[39];
  size_t length = encode(encoded, key);
  struct item *item = lookup(&c->keys, encoded, length, true, error);
  if (!item) return false;
  size_t index = item->id;
  if (c->keys.used > c->allocated) {
    size_t capacity = c->keys.allocated;
    if (capacity > SIZE_MAX / sizeof(*c->values))
      return fm_error_set(error, EOVERFLOW, "correlation value capacity");
    void *next = fm_realloc(c->values, capacity * sizeof(*c->values));
    if (!next) return fm_error_set(error, errno, "correlation values");
    c->values = next;
    c->allocated = capacity;
  }
  correlation_merge(&c->values[index], item->count > 0, value);
  item->count++;
  return true;
}

void correlation_merge(struct correlation_value *current, bool seen,
                       const struct correlation_value *value) {
  bool ambiguous = seen && (current->ambiguous ||
                            current->has_inside != value->has_inside ||
                            (current->has_inside &&
                             !endpoint_equal(current->inside, value->inside)));
  *current = *value;
  current->ambiguous = ambiguous;
}

bool correlation_observe(void *c, const struct outside_key *key,
                         const struct correlation_value *value,
                         struct fm_error *error) {
  return correlation_add(c, *key, value, error);
}

size_t outside_key_encode(unsigned char out[OUTSIDE_KEY_SIZE], struct outside_key key) {
  return encode(out, key);
}
bool correlation_lookup(const struct correlation *c, struct outside_key key,
                        struct correlation_value *value) {
  if ((key.public.a.af != 4 && key.public.a.af != 6) ||
      (key.remote.a.af != 4 && key.remote.a.af != 6))
    return false;
  unsigned char encoded[39];
  size_t length = encode(encoded, key);
  const struct item *item = map_find(&c->keys, encoded, length);
  if (!item) return false;
  *value = c->values[item->id];
  return true;
}
size_t correlation_count(const struct correlation *c) { return c->keys.used; }
size_t correlation_bytes(const struct correlation *c) {
  return map_bytes(&c->keys) + c->allocated * sizeof(*c->values);
}
bool correlation_at(const struct correlation *c, size_t n,
                    struct outside_key *key,
                    struct correlation_value *value) {
  if (n >= c->keys.used) return false;
  const struct item *item = c->keys.order[n];
  const unsigned char *p = item->key;
  key->protocol = *p++;
  struct endpoint *endpoints[] = {&key->public, &key->remote};
  for (unsigned i = 0; i < 2; i++) {
    endpoints[i]->a.af = *p++;
    memcpy(endpoints[i]->a.b, p, 16); p += 16;
    uint16_t port;
    memcpy(&port, p, 2); p += 2;
    endpoints[i]->port = ntohs(port);
  }
  *value = c->values[item->id];
  return true;
}
