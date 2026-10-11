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

#ifndef FM_CLASSIFY_H
#define FM_CLASSIFY_H
#include "context.h"
#include "error.h"
#include <stdint.h>

/* Classification sets: PF tables given Firewall Map meaning,
 * compiled into an immutable snapshot that answers, for an address, which
 * sets contain it (one bit per set ID). Membership is PF's own: the longest
 * matching prefix of a table decides, and a negated entry ("!net") excludes.
 * The snapshot is replaced only between samples. */
#define CLASSIFY_MAX_SETS 64
#define CLASSIFY_MAX_TABLE_ENTRIES 500000
#define CLASSIFY_MAX_TOTAL_ENTRIES 1000000
#define CLASSIFY_NAME_SIZE 32 /* PF_TABLE_NAME_SIZE */
#define CLASSIFY_MAX_ADDRESSES 20000

struct class_entry {
  struct addr a;
  unsigned char prefix;
  bool negated;
};
/* Per-set load status (FMAGG5 class-set record). */
enum class_status {
  CLASS_OK = 0,
  CLASS_MISSING = 1,   /* no such PF table (alias absent or not loaded) */
  CLASS_TOO_LARGE = 2, /* over the per-table or total entry cap: not used */
  CLASS_UNREADABLE = 3 /* the PF table could not be read */
};
struct class_set {
  unsigned id;           /* bit number, < CLASSIFY_MAX_SETS */
  char category;         /* 'T' threat, 'C' country, 'O' operational */
  char name[CLASSIFY_NAME_SIZE];
  enum class_status status;
  uint64_t entries;      /* table entries read (when OK) */
};
struct classifier;

/* Builds a snapshot from explicit entries (one array per set, in sets[]
 * order). Takes ownership of nothing. */
struct classifier *classifier_build(const struct class_set *sets, size_t set_count,
                                    const struct class_entry *const *entries,
                                    const size_t *entry_counts, struct fm_error *);
/* Builds a snapshot by reading each set's PF table (FreeBSD; elsewhere every
 * set is reported missing). Statuses are written into sets[]. */
struct classifier *classifier_load(struct class_set *sets, size_t set_count, struct fm_error *);
void classifier_destroy(struct classifier *);
/* The most accounted memory a build can need at the entry caps (bytes),
 * besides the classifier it replaces: the explicit bound a refresh runs
 * under (main.c), with the collector's memory budget. */
size_t classifier_build_bound(void);
/* Set mask for address; 0 for a NULL snapshot. */
uint64_t classifier_lookup(const struct classifier *, struct addr);
/* Mask of the sets in a category. */
uint64_t classifier_category(const struct classifier *, char category);
size_t classifier_set_count(const struct classifier *);
const struct class_set *classifier_set(const struct classifier *, size_t);
size_t classifier_bytes(const struct classifier *);
#endif
