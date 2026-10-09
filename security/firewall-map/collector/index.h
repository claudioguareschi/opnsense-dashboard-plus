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

#ifndef FM_INDEX_H
#define FM_INDEX_H
#include "error.h"
#include <stdint.h>
/* An insertion-ordered hash map of byte-string keys.
 *
 * Ownership: the map owns each item and its copied key. `id` is the item's
 * dense insertion index (0, 1, 2, ...), assigned by the map and never changed;
 * callers that need a dense identity use it. `value`, `count` and `seq` belong
 * to the caller and start as 0, 0 and UINT64_MAX; the map never reads them.
 * Iteration in insertion order goes through order[0..used). */
struct item {
  struct item *next;
  uint64_t hash, seq, count, value;
  size_t id, len;
  unsigned char key[];
};
struct map {
  struct item **buckets, **order;
  size_t capacity, used, allocated;
};
/* Keys every map's hash (SipHash-1-3). Keys include network-chosen addresses
 * and ports, so the helper sets a fresh random key once at start (main) before
 * any map is used; nothing hashed outlives the process. Iteration order never
 * depends on the hash, so output is identical under any key. */
void index_set_hash_key(const uint8_t key[16]);
/* The same keyed hash, for fixed-capacity tables built on it. */
uint64_t index_hash(const void *, size_t);
/* The item for a key: the existing one, or a new one inserted (its id the
 * next insertion index, value/count/seq at 0, 0, UINT64_MAX); NULL only
 * when the insertion fails (error set). */
struct item *map_insert(struct map *, const void *, size_t, struct fm_error *);
/* Lookup without insertion; never fails, never modifies the map. */
const struct item *map_find(const struct map *, const void *, size_t);
/* The same, with the key's index_hash already computed. */
const struct item *map_find_hashed(const struct map *, const void *, size_t, uint64_t);
void map_clear(struct map *);
size_t map_bytes(const struct map *);
#endif
