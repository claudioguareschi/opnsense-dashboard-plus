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

#include "index.h"
#include "alloc.h"
#include "siphash.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
static uint8_t hash_key[16];
void index_set_hash_key(const uint8_t key[16]) { memcpy(hash_key, key, sizeof(hash_key)); }
static uint64_t hash(const void *data, size_t len) {
  return siphash13(hash_key, data, len);
}
uint64_t index_hash(const void *data, size_t len) { return hash(data, len); }
static bool resize(struct map *m, struct fm_error *error) {
  size_t capacity = m->capacity ? m->capacity * 2 : 64;
  if (capacity < m->capacity || capacity > SIZE_MAX / sizeof(*m->buckets))
    return fm_error_set(error, EOVERFLOW, "index capacity");
  struct item **buckets = fm_calloc(capacity, sizeof(*buckets));
  if (!buckets)
    return fm_error_set(error, errno, "index buckets");
  for (size_t n = 0; n < m->used; n++) {
    struct item *i = m->order[n];
    i->next = buckets[i->hash % capacity];
    buckets[i->hash % capacity] = i;
  }
  fm_free(m->buckets);
  m->buckets = buckets;
  m->capacity = capacity;
  return true;
}
static struct item *find(const struct map *m, const void *key, size_t len,
                         uint64_t h) {
  if (m->capacity)
    for (struct item *i = m->buckets[h % m->capacity]; i; i = i->next)
      if (i->hash == h && i->len == len && !memcmp(i->key, key, len))
        return i;
  return NULL;
}
const struct item *map_find(const struct map *m, const void *key, size_t len) {
  return find(m, key, len, hash(key, len));
}
const struct item *map_find_hashed(const struct map *m, const void *key, size_t len,
                                   uint64_t h) {
  return find(m, key, len, h);
}
struct item *map_insert(struct map *m, const void *key, size_t len, struct fm_error *error) {
  uint64_t h = hash(key, len);
  struct item *found = find(m, key, len, h);
  if (found)
    return found;
  if ((!m->capacity || m->used >= m->capacity * 3 / 4) && !resize(m, error))
    return NULL;
  if (m->used == m->allocated) {
    size_t n = m->allocated ? m->allocated * 2 : 64;
    if (n < m->allocated || n > SIZE_MAX / sizeof(*m->order)) {
      fm_error_set(error, EOVERFLOW, "index order capacity");
      return NULL;
    }
    void *p = fm_realloc(m->order, n * sizeof(*m->order));
    if (!p) {
      fm_error_set(error, errno, "index order");
      return NULL;
    }
    m->order = p;
    m->allocated = n;
  }
  if (len > SIZE_MAX - sizeof(struct item)) {
    fm_error_set(error, EOVERFLOW, "index key");
    return NULL;
  }
  struct item *i = fm_calloc(1, sizeof(*i) + len);
  if (!i) {
    fm_error_set(error, errno, "index item");
    return NULL;
  }
  memcpy(i->key, key, len);
  i->len = len;
  i->hash = h;
  i->seq = UINT64_MAX;
  i->id = m->used;
  m->order[m->used++] = i;
  i->next = m->buckets[h % m->capacity];
  m->buckets[h % m->capacity] = i;
  return i;
}
void map_clear(struct map *m) {
  for (size_t n = 0; n < m->used; n++)
    fm_free(m->order[n]);
  fm_free(m->order);
  fm_free(m->buckets);
  memset(m, 0, sizeof(*m));
}
size_t map_bytes(const struct map *m) {
  size_t bytes = (m->capacity + m->allocated) * sizeof(void *);
  for (size_t n = 0; n < m->used; n++)
    bytes += sizeof(struct item) + m->order[n]->len;
  return bytes;
}
