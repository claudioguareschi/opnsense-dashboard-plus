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

#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Every block carries its requested size in a header padded to max_align_t, so
 * the returned pointer keeps malloc's alignment guarantee. */
union header {
  size_t size;
  max_align_t align;
};
static struct fm_heap_usage usage;

static bool admit(size_t old_size, size_t new_size) {
  if (new_size <= old_size || !usage.budget_bytes)
    return true;
  uint64_t growth = new_size - old_size;
  if (usage.bytes > usage.budget_bytes || growth > usage.budget_bytes - usage.bytes) {
    usage.refused++;
    errno = ENOMEM;
    return false;
  }
  return true;
}
static void account(size_t old_size, size_t new_size) {
  usage.bytes = usage.bytes - old_size + new_size;
  if (usage.bytes > usage.peak_bytes)
    usage.peak_bytes = usage.bytes;
}
void *fm_malloc(size_t size) {
  if (size > SIZE_MAX - sizeof(union header)) {
    errno = ENOMEM;
    return NULL;
  }
  if (!admit(0, size))
    return NULL;
  union header *block = malloc(sizeof(*block) + size);
  if (!block)
    return NULL;
  block->size = size;
  account(0, size);
  usage.blocks++;
  return block + 1;
}
void *fm_calloc(size_t count, size_t size) {
  if (size && count > SIZE_MAX / size) {
    errno = ENOMEM;
    return NULL;
  }
  void *pointer = fm_malloc(count * size);
  if (pointer)
    memset(pointer, 0, count * size);
  return pointer;
}
void *fm_realloc(void *pointer, size_t size) {
  if (!pointer)
    return fm_malloc(size);
  union header *block = (union header *)pointer - 1;
  size_t old_size = block->size;
  if (size > SIZE_MAX - sizeof(*block)) {
    errno = ENOMEM;
    return NULL;
  }
  if (!admit(old_size, size))
    return NULL;
  union header *grown = realloc(block, sizeof(*block) + size);
  if (!grown)
    return NULL;
  grown->size = size;
  account(old_size, size);
  return grown + 1;
}
void fm_free(void *pointer) {
  if (!pointer)
    return;
  union header *block = (union header *)pointer - 1;
  account(block->size, 0);
  usage.blocks--;
  free(block);
}
void fm_heap_set_budget(uint64_t budget_bytes) { usage.budget_bytes = budget_bytes; }
struct fm_heap_usage fm_heap_usage(void) { return usage; }
void fm_heap_reset_peak(void) { usage.peak_bytes = usage.bytes; }
