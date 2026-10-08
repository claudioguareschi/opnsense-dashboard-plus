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

#include "classify.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef __FreeBSD__
#include <fcntl.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#if defined(FM_TEST_HOOKS) && !defined(__FreeBSD__)
#include <arpa/inet.h>
#include <stdio.h>
#endif

typedef unsigned __int128 u128;

/* A disjoint address interval and the sets containing it. */
struct span4 {
  uint32_t lo, hi;
  uint64_t mask;
};
struct span6 {
  u128 lo, hi;
  uint64_t mask;
};
struct classifier {
  struct class_set sets[CLASSIFY_MAX_SETS];
  size_t set_count;
  struct span4 *v4;
  struct span6 *v6;
  size_t n4, n6;
};

/* A prefix as a closed interval, with whether it includes or excludes. */
struct prefix {
  u128 lo, hi;
  unsigned length;
  bool member;
  size_t order; /* position in the table: duplicates resolve deterministically */
};
struct interval {
  u128 lo, hi;
};
struct intervals {
  struct interval *items;
  size_t count, capacity;
};

static u128 key_of(struct addr a) {
  u128 key = 0;
  unsigned bytes = a.af == 4 ? 4 : 16;
  for (unsigned n = 0; n < bytes; n++)
    key = key << 8 | a.b[n];
  return key;
}

static bool grow(void **items, size_t *capacity, size_t size, size_t needed,
                 struct fm_error *error) {
  if (needed <= *capacity)
    return true;
  size_t next = *capacity ? *capacity : 64;
  while (next < needed) {
    if (next > SIZE_MAX / 2 / size)
      return fm_error_set(error, EOVERFLOW, "classification capacity");
    next *= 2;
  }
  void *p = fm_realloc(*items, next * size);
  if (!p)
    return fm_error_set(error, ENOMEM, "classification allocation");
  *items = p;
  *capacity = next;
  return true;
}

static int compare_prefix(const void *left, const void *right) {
  const struct prefix *a = left, *b = right;
  if (a->lo != b->lo)
    return a->lo < b->lo ? -1 : 1;
  if (a->length != b->length)
    return a->length < b->length ? -1 : 1;
  return a->order < b->order ? -1 : a->order > b->order;
}

/* Appends a member interval, merging with an adjacent previous one. */
static bool emit(struct intervals *out, u128 lo, u128 hi, bool member, struct fm_error *error) {
  if (!member || lo > hi)
    return true;
  if (out->count && out->items[out->count - 1].hi + 1 == lo && out->items[out->count - 1].hi < hi) {
    out->items[out->count - 1].hi = hi;
    return true;
  }
  if (!grow((void **)&out->items, &out->capacity, sizeof(*out->items), out->count + 1, error))
    return false;
  out->items[out->count++] = (struct interval){lo, hi};
  return true;
}

/* Member intervals of one set: CIDR prefixes nest or are disjoint, so a
 * sweep in (start, shorter-first) order with a stack of enclosing prefixes
 * finds, for every point, its longest matching prefix. */
static bool compile_set(struct prefix *p, size_t n, u128 max, struct intervals *out,
                        struct fm_error *error) {
  qsort(p, n, sizeof(*p), compare_prefix);
  struct prefix stack[130];
  size_t depth = 0;
  u128 cursor = 0;
  for (size_t i = 0; i < n; i++) {
    const struct prefix *e = &p[i];
    if (depth && stack[depth - 1].lo == e->lo && stack[depth - 1].hi == e->hi) {
      stack[depth - 1].member = e->member; /* duplicate prefix: the later entry wins */
      continue;
    }
    while (depth && stack[depth - 1].hi < e->lo) {
      if (!emit(out, cursor, stack[depth - 1].hi, stack[depth - 1].member, error))
        return false;
      cursor = stack[depth - 1].hi + 1;
      depth--;
    }
    if (depth && cursor < e->lo && !emit(out, cursor, e->lo - 1, stack[depth - 1].member, error))
      return false;
    cursor = e->lo;
    if (depth == sizeof(stack) / sizeof(*stack))
      return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "classification nesting");
    stack[depth++] = *e;
  }
  while (depth) {
    if (!emit(out, cursor, stack[depth - 1].hi, stack[depth - 1].member, error))
      return false;
    if (stack[depth - 1].hi == max)
      break; /* every enclosing prefix ends here too */
    cursor = stack[depth - 1].hi + 1;
    depth--;
  }
  return true;
}

struct event {
  u128 at;
  unsigned bit;
  bool start;
};
static int compare_event(const void *left, const void *right) {
  const struct event *a = left, *b = right;
  return a->at < b->at ? -1 : a->at > b->at;
}

/* Merges every set's member intervals into disjoint spans with set masks. */
static bool merge(struct intervals *per_set, const unsigned *bits, size_t sets, u128 max, bool v4,
                  struct classifier *c, struct fm_error *error) {
  size_t total = 0;
  for (size_t s = 0; s < sets; s++)
    total += per_set[s].count * 2;
  struct event *events = total ? fm_calloc(total, sizeof(*events)) : NULL;
  if (total && !events)
    return fm_error_set(error, ENOMEM, "classification events");
  size_t n = 0;
  for (size_t s = 0; s < sets; s++)
    for (size_t r = 0; r < per_set[s].count; r++) {
      events[n++] = (struct event){per_set[s].items[r].lo, bits[s], true};
      if (per_set[s].items[r].hi < max)
        events[n++] = (struct event){per_set[s].items[r].hi + 1, bits[s], false};
    }
  qsort(events, n, sizeof(*events), compare_event);
  size_t capacity = 0, count = 0;
  void *spans = NULL;
  uint64_t mask = 0;
  u128 from = 0;
  bool ok = true;
  for (size_t i = 0; i < n && ok;) {
    u128 at = events[i].at;
    if (mask && at > from) {
      if (v4) {
        struct span4 *s = spans;
        if (count && s[count - 1].mask == mask && (u128)s[count - 1].hi + 1 == from)
          s[count - 1].hi = (uint32_t)(at - 1);
        else if ((ok = grow(&spans, &capacity, sizeof(*s), count + 1, error)))
          ((struct span4 *)spans)[count++] = (struct span4){(uint32_t)from, (uint32_t)(at - 1), mask};
      } else {
        struct span6 *s = spans;
        if (count && s[count - 1].mask == mask && s[count - 1].hi + 1 == from)
          s[count - 1].hi = at - 1;
        else if ((ok = grow(&spans, &capacity, sizeof(*s), count + 1, error)))
          ((struct span6 *)spans)[count++] = (struct span6){from, at - 1, mask};
      }
    }
    for (; i < n && events[i].at == at; i++) {
      if (events[i].start)
        mask |= UINT64_C(1) << events[i].bit;
      else
        mask &= ~(UINT64_C(1) << events[i].bit);
    }
    from = at;
  }
  if (ok && mask) {
    if (v4) {
      struct span4 *s = spans;
      if (count && s[count - 1].mask == mask && (u128)s[count - 1].hi + 1 == from)
        s[count - 1].hi = (uint32_t)max;
      else if ((ok = grow(&spans, &capacity, sizeof(*s), count + 1, error)))
        ((struct span4 *)spans)[count++] = (struct span4){(uint32_t)from, (uint32_t)max, mask};
    } else {
      struct span6 *s = spans;
      if (count && s[count - 1].mask == mask && s[count - 1].hi + 1 == from)
        s[count - 1].hi = max;
      else if ((ok = grow(&spans, &capacity, sizeof(*s), count + 1, error)))
        ((struct span6 *)spans)[count++] = (struct span6){from, max, mask};
    }
  }
  fm_free(events);
  if (!ok) {
    fm_free(spans);
    return false;
  }
  if (v4) {
    c->v4 = spans;
    c->n4 = count;
  } else {
    c->v6 = spans;
    c->n6 = count;
  }
  return true;
}

void classifier_destroy(struct classifier *c) {
  if (!c)
    return;
  fm_free(c->v4);
  fm_free(c->v6);
  fm_free(c);
}

struct classifier *classifier_build(const struct class_set *sets, size_t set_count,
                                    const struct class_entry *const *entries,
                                    const size_t *entry_counts, struct fm_error *error) {
  if (set_count > CLASSIFY_MAX_SETS) {
    fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "classification set count");
    return NULL;
  }
  struct classifier *c = fm_calloc(1, sizeof(*c));
  if (!c) {
    fm_error_set(error, ENOMEM, "classifier allocation");
    return NULL;
  }
  c->set_count = set_count;
  memcpy(c->sets, sets, set_count * sizeof(*sets));
  struct intervals per_set[2][CLASSIFY_MAX_SETS];
  unsigned bits[CLASSIFY_MAX_SETS];
  memset(per_set, 0, sizeof(per_set));
  struct prefix *prefixes = NULL;
  size_t prefix_capacity = 0;
  bool ok = true;
  for (size_t s = 0; s < set_count && ok; s++) {
    bits[s] = sets[s].id;
    if (sets[s].status != CLASS_OK)
      continue;
    for (unsigned family = 0; family < 2 && ok; family++) {
      unsigned af = family ? 6 : 4, width = family ? 128 : 32;
      u128 max = family ? ~(u128)0 : (u128)UINT32_MAX;
      size_t n = 0;
      for (size_t e = 0; e < entry_counts[s] && ok; e++) {
        const struct class_entry *entry = &entries[s][e];
        if (entry->a.af != af || entry->prefix > width)
          continue;
        if (!(ok = grow((void **)&prefixes, &prefix_capacity, sizeof(*prefixes), n + 1, error)))
          break;
        u128 host = entry->prefix == width ? 0 : (max >> entry->prefix);
        u128 lo = key_of(entry->a) & ~host & max;
        prefixes[n] = (struct prefix){lo, lo | host, entry->prefix, !entry->negated, n};
        n++;
      }
      ok = ok && compile_set(prefixes, n, max, &per_set[family][s], error);
    }
  }
  ok = ok && merge(per_set[0], bits, set_count, (u128)UINT32_MAX, true, c, error) &&
       merge(per_set[1], bits, set_count, ~(u128)0, false, c, error);
  for (size_t s = 0; s < set_count; s++) {
    fm_free(per_set[0][s].items);
    fm_free(per_set[1][s].items);
  }
  fm_free(prefixes);
  if (!ok) {
    classifier_destroy(c);
    return NULL;
  }
  return c;
}

#ifdef __FreeBSD__
/* One coherent copy of a PF table (DIOCRGETADDRS: probe the size, then copy;
 * retry if the table grew in between). */
static enum class_status read_table(int fd, const char *name, struct class_entry **out,
                                    size_t *count, size_t budget, struct fm_error *error) {
  struct pfioc_table io;
  struct pfr_addr *buffer = NULL;
  int size = 0;
  for (int attempt = 0; attempt < 4; attempt++) {
    memset(&io, 0, sizeof(io));
    strlcpy(io.pfrio_table.pfrt_name, name, sizeof(io.pfrio_table.pfrt_name));
    io.pfrio_esize = sizeof(struct pfr_addr);
    io.pfrio_buffer = buffer;
    io.pfrio_size = size;
    if (ioctl(fd, DIOCRGETADDRS, &io)) {
      int code = errno;
      fm_free(buffer);
      return code == ESRCH || code == ENOENT ? CLASS_MISSING : CLASS_UNREADABLE;
    }
    if (io.pfrio_size <= size)
      break;
    if ((size_t)io.pfrio_size > CLASSIFY_MAX_TABLE_ENTRIES || (size_t)io.pfrio_size > budget) {
      fm_free(buffer);
      return CLASS_TOO_LARGE;
    }
    fm_free(buffer);
    size = io.pfrio_size + io.pfrio_size / 16 + 16;
    buffer = fm_calloc((size_t)size, sizeof(*buffer));
    if (!buffer) {
      fm_error_set(error, ENOMEM, "PF table copy");
      return CLASS_UNREADABLE;
    }
    if (attempt == 3) {
      fm_free(buffer);
      return CLASS_UNREADABLE; /* kept growing: try again next generation */
    }
  }
  size_t n = (size_t)io.pfrio_size;
  struct class_entry *entries = n ? fm_calloc(n, sizeof(*entries)) : NULL;
  if (n && !entries) {
    fm_free(buffer);
    fm_error_set(error, ENOMEM, "PF table entries");
    return CLASS_UNREADABLE;
  }
  size_t kept = 0;
  for (size_t i = 0; i < n; i++) {
    const struct pfr_addr *a = &buffer[i];
    if (a->pfra_af != AF_INET && a->pfra_af != AF_INET6)
      continue;
    struct class_entry *e = &entries[kept++];
    memset(e, 0, sizeof(*e));
    e->a.af = a->pfra_af == AF_INET ? 4 : 6;
    memcpy(e->a.b, &a->pfra_u, e->a.af == 4 ? 4 : 16);
    e->prefix = a->pfra_net;
    e->negated = a->pfra_not != 0;
  }
  fm_free(buffer);
  *out = entries;
  *count = kept;
  return CLASS_OK;
}
#elif defined(FM_TEST_HOOKS)
/* Test builds: FM_TEST_CLASS_DIR/<name>.txt in `pfctl -t NAME -T show` form. */
static enum class_status read_table_file(const char *name, struct class_entry **out,
                                         size_t *count, size_t budget, struct fm_error *error) {
  const char *dir = getenv("FM_TEST_CLASS_DIR");
  char path[1024], line[128];
  if (!dir || snprintf(path, sizeof(path), "%s/%s.txt", dir, name) >= (int)sizeof(path))
    return CLASS_MISSING;
  FILE *f = fopen(path, "r");
  if (!f)
    return CLASS_MISSING;
  struct class_entry *entries = NULL;
  size_t n = 0, capacity = 0;
  while (fgets(line, sizeof(line), f)) {
    char *text = line;
    while (*text == ' ' || *text == '\t')
      text++;
    bool negated = *text == '!';
    text += negated;
    text[strcspn(text, " \t\r\n")] = 0;
    if (!*text)
      continue;
    char *slash = strchr(text, '/');
    struct class_entry e = {.negated = negated};
    if (slash)
      *slash = 0;
    if (inet_pton(AF_INET, text, e.a.b) == 1)
      e.a.af = 4;
    else if (inet_pton(AF_INET6, text, e.a.b) == 1)
      e.a.af = 6;
    else
      continue;
    e.prefix = slash ? (unsigned char)atoi(slash + 1) : (e.a.af == 4 ? 32 : 128);
    if (n >= CLASSIFY_MAX_TABLE_ENTRIES || n >= budget) {
      fclose(f);
      fm_free(entries);
      return CLASS_TOO_LARGE;
    }
    if (!grow((void **)&entries, &capacity, sizeof(*entries), n + 1, error)) {
      fclose(f);
      fm_free(entries);
      return CLASS_UNREADABLE;
    }
    entries[n++] = e;
  }
  fclose(f);
  *out = entries;
  *count = n;
  return CLASS_OK;
}
#endif

struct classifier *classifier_load(struct class_set *sets, size_t set_count, struct fm_error *error) {
  if (set_count > CLASSIFY_MAX_SETS) {
    fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "classification set count");
    return NULL;
  }
  struct class_entry *entries[CLASSIFY_MAX_SETS] = {0};
  size_t counts[CLASSIFY_MAX_SETS] = {0}, total = 0;
#ifdef __FreeBSD__
  int fd = open("/dev/pf", O_RDONLY);
#endif
  for (size_t s = 0; s < set_count; s++) {
    size_t budget = CLASSIFY_MAX_TOTAL_ENTRIES - total;
#ifdef __FreeBSD__
    sets[s].status = fd < 0 ? CLASS_UNREADABLE
                            : read_table(fd, sets[s].name, &entries[s], &counts[s], budget, error);
#elif defined(FM_TEST_HOOKS)
    sets[s].status = read_table_file(sets[s].name, &entries[s], &counts[s], budget, error);
#else
    (void)budget;
    sets[s].status = CLASS_MISSING;
#endif
    if (error->code)
      break;
    sets[s].entries = sets[s].status == CLASS_OK ? counts[s] : 0;
    total += counts[s];
  }
#ifdef __FreeBSD__
  if (fd >= 0)
    close(fd);
#endif
  struct classifier *c = error->code ? NULL
                                     : classifier_build(sets, set_count,
                                                        (const struct class_entry *const *)entries,
                                                        counts, error);
  for (size_t s = 0; s < set_count; s++)
    fm_free(entries[s]);
  return c;
}

uint64_t classifier_lookup(const struct classifier *c, struct addr a) {
  if (!c)
    return 0;
  u128 key = key_of(a);
  size_t lo = 0, hi = a.af == 4 ? c->n4 : c->n6;
  /* the last span starting at or before key */
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    u128 start = a.af == 4 ? (u128)c->v4[mid].lo : c->v6[mid].lo;
    if (start <= key)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (!lo)
    return 0;
  if (a.af == 4)
    return key <= c->v4[lo - 1].hi ? c->v4[lo - 1].mask : 0;
  return key <= c->v6[lo - 1].hi ? c->v6[lo - 1].mask : 0;
}

uint64_t classifier_category(const struct classifier *c, char category) {
  uint64_t mask = 0;
  for (size_t s = 0; c && s < c->set_count; s++)
    if (c->sets[s].category == category)
      mask |= UINT64_C(1) << c->sets[s].id;
  return mask;
}

size_t classifier_set_count(const struct classifier *c) { return c ? c->set_count : 0; }
const struct class_set *classifier_set(const struct classifier *c, size_t n) {
  return c && n < c->set_count ? &c->sets[n] : NULL;
}
size_t classifier_bytes(const struct classifier *c) {
  return c ? sizeof(*c) + c->n4 * sizeof(*c->v4) + c->n6 * sizeof(*c->v6) : 0;
}
