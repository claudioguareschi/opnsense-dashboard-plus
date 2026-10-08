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

#include "context.h"
#include "alloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct context *context_create(struct fm_error *error) {
  struct context *ctx = fm_calloc(1, sizeof(*ctx));
  if (!ctx)
    fm_error_set(error, errno, "context allocation");
  return ctx;
}
void context_destroy(struct context *ctx) {
  if (!ctx)
    return;
  for (size_t n = 0; n < ctx->ngroups; n++)
    fm_free(ctx->groups[n].entries);
  fm_free(ctx->groups);
  fm_free(ctx->ranges);
  fm_free(ctx->local);
  fm_free(ctx->nets);
  fm_free(ctx->assigned);
  fm_free(ctx->services);
  fm_free(ctx->local_sorted);
  fm_free(ctx->wan_sorted);
  fm_free(ctx->local_device);
  fm_free(ctx->services_sorted);
  fm_free(ctx);
}

/* Arrays grow to the next power of two (at least 16) whenever their count
 * reaches one, never beyond the kind's maximum. */
static bool append(void **items, size_t *count, size_t maximum, size_t size,
                   const void *item, struct fm_error *error) {
  if (*count >= maximum)
    return false;
  if (!*count || (*count >= 16 && !(*count & (*count - 1)))) {
    size_t capacity = *count ? *count * 2 : 16;
    if (capacity > maximum)
      capacity = maximum;
    void *grown = fm_realloc(*items, capacity * size);
    if (!grown)
      return fm_error_set(error, errno, "context rows");
    *items = grown;
  }
  memcpy((char *)*items + *count * size, item, size);
  (*count)++;
  return true;
}
bool context_add_range(struct context *c, struct range v, struct fm_error *e) {
  return append((void **)&c->ranges, &c->nr, CONTEXT_MAX_RANGES, sizeof(v), &v, e);
}
bool context_add_local(struct context *c, struct addr v, struct fm_error *e) {
  return append((void **)&c->local, &c->nl, CONTEXT_MAX_LOCAL, sizeof(v), &v, e);
}
bool context_add_net(struct context *c, struct net v, struct fm_error *e) {
  return append((void **)&c->nets, &c->nn, CONTEXT_MAX_NETWORKS, sizeof(v), &v, e);
}
bool context_add_assigned(struct context *c, struct assigned v, struct fm_error *e) {
  return append((void **)&c->assigned, &c->na, CONTEXT_MAX_ASSIGNED, sizeof(v), &v, e);
}
bool context_add_service(struct context *c, struct service v, struct fm_error *e) {
  return append((void **)&c->services, &c->ns, CONTEXT_MAX_SERVICES, sizeof(v), &v, e);
}

bool address_equal(struct addr a, struct addr b) {
  return a.af == b.af && !memcmp(a.b, b.b, 16);
}
static int address_compare(const struct addr *a, const struct addr *b) {
  return a->af != b->af ? (a->af < b->af ? -1 : 1) : memcmp(a->b, b->b, 16);
}
static int compare_addresses(const void *a, const void *b) {
  return address_compare(a, b);
}
static bool contains(const struct addr *items, size_t count, struct addr a) {
  return items && bsearch(&a, items, count, sizeof(*items), compare_addresses);
}
static struct addr mask(struct addr a, unsigned prefix) {
  unsigned whole = prefix / 8, bits = prefix % 8;
  struct addr masked = {.af = a.af};
  memcpy(masked.b, a.b, whole);
  if (bits)
    masked.b[whole] = a.b[whole] & (0xff << (8 - bits));
  return masked;
}
static int compare_entries(const void *left, const void *right) {
  const struct net_entry *a = left, *b = right;
  int order = address_compare(&a->masked, &b->masked);
  return order ? order : a->order < b->order ? -1 : a->order > b->order;
}
static int compare_services(const void *left, const void *right) {
  const struct service *a = left, *b = right;
  if (a->proto != b->proto)
    return a->proto < b->proto ? -1 : 1;
  return a->port < b->port ? -1 : a->port > b->port;
}

static bool build_groups(struct context *ctx, struct fm_error *error) {
  /* Python sends the most specific networks first; first-match semantics are
   * longest-prefix semantics only if that order holds, so it is checked. */
  for (size_t n = 1; n < ctx->nn; n++)
    if (ctx->nets[n].prefix > ctx->nets[n - 1].prefix)
      return fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "networks not most specific first");
  for (size_t n = 0; n < ctx->nn;) {
    size_t end = n;
    while (end < ctx->nn && ctx->nets[end].prefix == ctx->nets[n].prefix)
      end++;
    for (unsigned char af = 4; af <= 6; af += 2) {
      size_t count = 0;
      for (size_t i = n; i < end; i++)
        count += ctx->nets[i].a.af == af;
      if (!count)
        continue;
      void *grown = fm_realloc(ctx->groups, (ctx->ngroups + 1) * sizeof(*ctx->groups));
      if (!grown)
        return fm_error_set(error, errno, "network index");
      ctx->groups = grown;
      struct net_group *group = &ctx->groups[ctx->ngroups++];
      *group = (struct net_group){.af = af, .prefix = ctx->nets[n].prefix,
                                  .entries = fm_calloc(count, sizeof(*group->entries))};
      if (!group->entries)
        return fm_error_set(error, errno, "network index");
      for (size_t i = n; i < end; i++)
        if (ctx->nets[i].a.af == af)
          group->entries[group->count++] =
              (struct net_entry){mask(ctx->nets[i].a, ctx->nets[i].prefix), i};
      qsort(group->entries, group->count, sizeof(*group->entries), compare_entries);
    }
    n = end;
  }
  return true;
}

bool context_prepare(struct context *ctx, struct fm_error *error) {
  for (size_t n = 0; n < ctx->nr; n++) {
    const struct range *r = &ctx->ranges[n];
    if (r->lo.af != r->hi.af || address_compare(&r->lo, &r->hi) > 0 ||
        (n && address_compare(&ctx->ranges[n - 1].hi, &r->lo) >= 0))
      return fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "classification ranges unsorted or overlapping");
  }
  if (ctx->nl) {
    ctx->local_sorted = fm_malloc(ctx->nl * sizeof(*ctx->local_sorted));
    ctx->local_device = fm_calloc(ctx->nl, sizeof(*ctx->local_device));
    if (!ctx->local_sorted || !ctx->local_device)
      return fm_error_set(error, errno, "local address index");
    memcpy(ctx->local_sorted, ctx->local, ctx->nl * sizeof(*ctx->local));
    qsort(ctx->local_sorted, ctx->nl, sizeof(*ctx->local_sorted), compare_addresses);
  }
  for (size_t n = 0; n < ctx->na; n++)
    ctx->nwan += !strcmp(ctx->assigned[n].device, ctx->wan);
  if (ctx->nwan) {
    ctx->wan_sorted = fm_malloc(ctx->nwan * sizeof(*ctx->wan_sorted));
    if (!ctx->wan_sorted)
      return fm_error_set(error, errno, "WAN address index");
    for (size_t n = 0, w = 0; n < ctx->na; n++)
      if (!strcmp(ctx->assigned[n].device, ctx->wan))
        ctx->wan_sorted[w++] = ctx->assigned[n].a;
    qsort(ctx->wan_sorted, ctx->nwan, sizeof(*ctx->wan_sorted), compare_addresses);
  }
  if (ctx->ns) {
    ctx->services_sorted = fm_malloc(ctx->ns * sizeof(*ctx->services_sorted));
    if (!ctx->services_sorted)
      return fm_error_set(error, errno, "service index");
    memcpy(ctx->services_sorted, ctx->services, ctx->ns * sizeof(*ctx->services));
    /* qsort is not stable: duplicates are rejected instead of ordered */
    qsort(ctx->services_sorted, ctx->ns, sizeof(*ctx->services_sorted), compare_services);
    for (size_t n = 1; n < ctx->ns; n++)
      if (!compare_services(&ctx->services_sorted[n - 1], &ctx->services_sorted[n]))
        return fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "duplicate service row");
  }
  if (!build_groups(ctx, error))
    return false;
  for (size_t n = 0; n < ctx->nl; n++)
    ctx->local_device[n] = context_device(ctx, ctx->local[n], NULL);
  return true;
}

unsigned address_flags(const struct context *ctx, struct addr a) {
  size_t low = 0, high = ctx->nr;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    const struct range *r = &ctx->ranges[middle];
    if (address_compare(&a, &r->lo) < 0)
      high = middle;
    else if (address_compare(&a, &r->hi) > 0)
      low = middle + 1;
    else
      return r->flags;
  }
  return 0;
}
bool context_is_local(const struct context *ctx, struct addr a) {
  return contains(ctx->local_sorted, ctx->nl, a);
}
bool context_is_wan_address(const struct context *ctx, struct addr a) {
  return contains(ctx->wan_sorted, ctx->nwan, a);
}
const char *context_device(const struct context *ctx, struct addr a, const char *excluded) {
  for (size_t g = 0; g < ctx->ngroups; g++) {
    const struct net_group *group = &ctx->groups[g];
    if (group->af != a.af)
      continue;
    struct addr key = mask(a, group->prefix);
    /* first entry with this masked address (entries are sorted by it) */
    size_t low = 0, high = group->count;
    while (low < high) {
      size_t middle = low + (high - low) / 2;
      if (address_compare(&group->entries[middle].masked, &key) < 0)
        low = middle + 1;
      else
        high = middle;
    }
    for (size_t n = low; n < group->count && address_equal(group->entries[n].masked, key); n++) {
      const char *device = ctx->nets[group->entries[n].order].device;
      if (!excluded || strcmp(device, excluded))
        return device;
    }
  }
  return NULL;
}
unsigned context_service_group(const struct context *ctx, unsigned proto, unsigned port) {
  struct service key = {proto, port, 0};
  const struct service *found =
      ctx->services_sorted
          ? bsearch(&key, ctx->services_sorted, ctx->ns, sizeof(key), compare_services)
          : NULL;
  return found ? found->group : 0;
}
