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

#ifndef FM_ALLOC_H
#define FM_ALLOC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Accounted heap for every engine allocation. Callers use only these four
 * functions; the accounting strategy (today a size header in front of each
 * block) is private to alloc.c and may be replaced without touching callers.
 * A failed allocation leaves errno set (ENOMEM also when the budget refuses). */
void *fm_malloc(size_t size);
void *fm_calloc(size_t count, size_t size);
void *fm_realloc(void *pointer, size_t size);
void fm_free(void *pointer);

struct fm_heap_usage {
  uint64_t bytes, peak_bytes, blocks, budget_bytes, refused;
};
/* 0 disables the budget. The budget bounds requested bytes, not allocator
 * overhead; refusals are counted so a sample can report why it failed. */
void fm_heap_set_budget(uint64_t budget_bytes);
struct fm_heap_usage fm_heap_usage(void);
/* Starts a new peak window (each sample reports its own peak). */
void fm_heap_reset_peak(void);
#endif
