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


#include "profile.h"
#include "alloc.h"
#include "json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef unsigned __int128 u128;
/* An address span [lo, hi] with its multiplier (spans are disjoint, sorted). */
struct asset_span {
  u128 lo, hi;
  double multiplier;
};
/* The quality features by keyword, their fixed scales (the value at which a
 * feature contributes weight x log 2), and whether activity fades them. */
static const struct {
  const char *key;
  double scale;
  bool traffic;
} FEATURES[FEATURE_COUNT] = {
    {"byte_rate", 10000, true},     {"packet_rate", 10, true},    {"active_states", 10, false},
    {"new_state_rate", 1, false},   {"flow_volume", 1000000, true}, {"pf_blocked", 10, false},
    {"threat_intelligence", 1, false}, {"ids_evidence", 1, false},
};

/* -------- profile loading -------- */

static bool why(char *out, size_t size, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(out, size, format, arguments);
  va_end(arguments);
  return false;
}
/* An object's members must all be among `allowed`. */
static bool only_keys(const struct json *object, const char *const *allowed, size_t count, const char *where,
                      char *out, size_t size) {
  for (const struct json *m = object->child; m; m = m->next) {
    bool known = false;
    for (size_t n = 0; n < count && !known; n++) known = !strcmp(m->key, allowed[n]);
    if (!known) return why(out, size, "unknown %s \"%s\"", where, m->key);
  }
  return true;
}
static const struct json *member(const struct json *object, const char *key, enum json_type type,
                                 const char *where, char *out, size_t size) {
  const struct json *m = json_member(object, key);
  if (!m) return why(out, size, "%s: missing \"%s\"", where, key), NULL;
  if (m->type != type) return why(out, size, "%s: \"%s\" has the wrong type", where, key), NULL;
  return m;
}
static bool uuid_valid(const char *text) {
  if (strlen(text) != 36) return false;
  for (int n = 0; n < 36; n++) {
    char c = text[n];
    bool dash = n == 8 || n == 13 || n == 18 || n == 23;
    if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}
struct rule {
  unsigned char af, length;
  u128 lo, hi;
  double multiplier;
};
static u128 key_of(struct addr a) {
  u128 key = 0;
  for (int n = 0; n < (a.af == 4 ? 4 : 16); n++) key = (key << 8) | a.b[n];
  return key;
}
/* "address/length", canonical: the host bits are zero. */
static bool cidr(const char *text, struct rule *r) {
  char address[64];
  const char *slash = strchr(text, '/');
  if (!slash || (size_t)(slash - text) >= sizeof(address)) return false;
  memcpy(address, text, (size_t)(slash - text));
  address[slash - text] = 0;
  char *end;
  long length = strtol(slash + 1, &end, 10);
  if (*end || end == slash + 1 || slash[1] == '+' || slash[1] == '-' || (slash[1] == '0' && slash[2])) return false;
  struct addr a = {0};
  a.af = strchr(address, ':') ? 6 : 4;
  if (inet_pton(a.af == 4 ? AF_INET : AF_INET6, address, a.b) != 1) return false;
  unsigned bits = a.af == 4 ? 32 : 128;
  if (length < 0 || length > (long)bits) return false;
  u128 key = key_of(a), host = length == (long)bits ? 0 : (((u128)1 << (bits - (unsigned)length)) - 1);
  if (key & host) return false;
  *r = (struct rule){a.af, (unsigned char)length, key, key | host, 0};
  return true;
}
static int by_start(const void *left, const void *right) {
  const u128 *a = left, *b = right;
  return *a < *b ? -1 : *a > *b;
}
/* Disjoint spans of one family, each with the multiplier of its longest
 * matching rule; spans at the default multiplier are left out. */
static bool compile_spans(const struct rule *rules, size_t count, unsigned char af, double fallback,
                          struct asset_span **out, size_t *out_count) {
  u128 top = af == 4 ? (u128)0xffffffffu : ~(u128)0;
  size_t family = 0;
  for (size_t n = 0; n < count; n++) family += rules[n].af == af;
  *out = NULL;
  *out_count = 0;
  if (!family) return true;
  u128 *points = fm_calloc(2 * family + 1, sizeof(*points));
  struct asset_span *spans = points ? fm_calloc(2 * family + 1, sizeof(*spans)) : NULL;
  if (!spans) {
    fm_free(points);
    return false;
  }
  size_t used = 0;
  points[used++] = 0;
  for (size_t n = 0; n < count; n++) {
    if (rules[n].af != af) continue;
    points[used++] = rules[n].lo;
    if (rules[n].hi != top) points[used++] = rules[n].hi + 1;
  }
  qsort(points, used, sizeof(*points), by_start);
  size_t unique = 0;
  for (size_t n = 0; n < used; n++)
    if (!unique || points[n] != points[unique - 1]) points[unique++] = points[n];
  size_t made = 0;
  for (size_t n = 0; n < unique; n++) {
    u128 lo = points[n], hi = n + 1 < unique ? points[n + 1] - 1 : top;
    /* the elementary span lies wholly inside or outside every rule */
    int longest = -1;
    double multiplier = fallback;
    for (size_t k = 0; k < count; k++)
      if (rules[k].af == af && rules[k].lo <= lo && hi <= rules[k].hi && (int)rules[k].length > longest) {
        longest = rules[k].length;
        multiplier = rules[k].multiplier;
      }
    if (longest < 0) continue;
    if (made && spans[made - 1].hi + 1 == lo && spans[made - 1].multiplier == multiplier)
      spans[made - 1].hi = hi;
    else
      spans[made++] = (struct asset_span){lo, hi, multiplier};
  }
  fm_free(points);
  *out = spans;
  *out_count = made;
  return true;
}

static bool weights(const struct json *object, struct profile *p, char *out, size_t size) {
  double total = 0;
  for (const struct json *m = object->child; m; m = m->next) {
    int feature = -1;
    for (int k = 0; k < FEATURE_COUNT; k++)
      if (!strcmp(m->key, FEATURES[k].key)) feature = k;
    if (feature < 0) return why(out, size, "weights: unknown feature \"%s\"", m->key);
    if (m->type != JSON_NUMBER) return why(out, size, "weights: \"%s\" is not a number", m->key);
    if (m->number < 0 || m->number > 100) return why(out, size, "weights: \"%s\" is outside 0-100", m->key);
    p->weight[feature] = m->number;
    total += m->number;
  }
  for (int k = 0; k < FEATURE_COUNT; k++)
    if (!json_member(object, FEATURES[k].key)) return why(out, size, "weights: missing \"%s\"", FEATURES[k].key);
  if (fabs(total - 100) > 1e-9) return why(out, size, "weights total %g, not 100", total);
  return true;
}
static bool assets(const struct json *object, struct profile *p, char *out, size_t size) {
  static const char *const keys[] = {"default_multiplier", "rules"};
  if (!only_keys(object, keys, 2, "asset_importance member", out, size)) return false;
  const struct json *fallback = member(object, "default_multiplier", JSON_NUMBER, "asset_importance", out, size);
  const struct json *list = fallback ? member(object, "rules", JSON_ARRAY, "asset_importance", out, size) : NULL;
  if (!list) return false;
  if (!(fallback->number >= PROFILE_MULTIPLIER_MIN && fallback->number <= PROFILE_MULTIPLIER_MAX))
    return why(out, size, "asset_importance: default_multiplier out of range");
  if (list->count > PROFILE_ASSET_RULES_MAX)
    return why(out, size, "asset_importance: more than %d rules", PROFILE_ASSET_RULES_MAX);
  p->default_multiplier = fallback->number;
  struct rule *rules = list->count ? fm_calloc(list->count, sizeof(*rules)) : NULL;
  if (list->count && !rules) return why(out, size, "asset_importance: allocation");
  size_t count = 0;
  bool ok = true;
  static const char *const rule_keys[] = {"cidr", "multiplier"};
  for (const struct json *item = list->child; ok && item; item = item->next) {
    if (item->type != JSON_OBJECT) {
      ok = why(out, size, "asset_importance: a rule is not an object");
      break;
    }
    const struct json *text, *multiplier;
    if (!(ok = only_keys(item, rule_keys, 2, "asset rule member", out, size))) break;
    if (!(text = member(item, "cidr", JSON_STRING, "asset rule", out, size)) ||
        !(multiplier = member(item, "multiplier", JSON_NUMBER, "asset rule", out, size))) {
      ok = false;
      break;
    }
    struct rule r;
    if (!cidr(text->string, &r)) {
      ok = why(out, size, "asset rule: malformed CIDR \"%s\"", text->string);
      break;
    }
    if (!(multiplier->number >= PROFILE_MULTIPLIER_MIN && multiplier->number <= PROFILE_MULTIPLIER_MAX)) {
      ok = why(out, size, "asset rule %s: multiplier out of range", text->string);
      break;
    }
    r.multiplier = multiplier->number;
    /* the same prefix twice: the same multiplier is one rule, another is a conflict */
    bool duplicate = false;
    for (size_t k = 0; k < count && !duplicate; k++)
      if (rules[k].af == r.af && rules[k].length == r.length && rules[k].lo == r.lo) {
        duplicate = true;
        if (rules[k].multiplier != r.multiplier)
          ok = why(out, size, "asset rule %s: the same prefix with two multipliers", text->string);
      }
    if (ok && !duplicate) rules[count++] = r;
  }
  p->min_multiplier = p->default_multiplier;
  for (size_t k = 0; k < count; k++)
    if (rules[k].multiplier < p->min_multiplier) p->min_multiplier = rules[k].multiplier;
  if (ok) {
    p->asset_rules = count;
    ok = (compile_spans(rules, count, 4, p->default_multiplier, &p->spans4, &p->spans4_count) &&
          compile_spans(rules, count, 6, p->default_multiplier, &p->spans6, &p->spans6_count)) ||
         why(out, size, "asset_importance: allocation");
  }
  fm_free(rules);
  return ok;
}
static bool visibility(const struct json *object, struct profile *p, char *out, size_t size) {
  static const char *const keys[] = {"s3_min_percent", "s2_min_percent", "s1_min_percent"};
  if (!only_keys(object, keys, 3, "security_visibility member", out, size)) return false;
  double total = 0;
  for (int c = SECURITY_S3, k = 0; c >= SECURITY_S1; c--, k++) {
    const struct json *m = member(object, keys[k], JSON_NUMBER, "security_visibility", out, size);
    if (!m) return false;
    if (m->number < 0 || m->number > 100) return why(out, size, "security_visibility: %s outside 0-100", keys[k]);
    p->floor_percent[c] = m->number;
    total += m->number;
  }
  return total <= 100 || why(out, size, "security_visibility: floors total %g%%, over 100", total);
}

bool profile_compile(const char *text, size_t length, struct profile *p, char *out, size_t size) {
  memset(p, 0, sizeof(*p));
  struct fm_error error = {0};
  struct json_document *document = json_parse(text, length, &error);
  if (!document) return why(out, size, "profile: %s", error.message);
  const struct json *root = json_root(document), *version, *profile, *uuid, *name, *direction, *part;
  static const char *const root_keys[] = {"schema_version", "profile"};
  static const char *const profile_keys[] = {"uuid", "name", "weights", "asset_importance", "security_visibility",
                                             "direction"};
  bool ok = root->type == JSON_OBJECT || why(out, size, "profile: not a JSON object");
  ok = ok && only_keys(root, root_keys, 2, "member", out, size) &&
       (version = member(root, "schema_version", JSON_NUMBER, "profile file", out, size)) &&
       (version->number == PROFILE_SCHEMA_VERSION ||
        why(out, size, "unsupported schema_version %g (expected %d)", version->number, PROFILE_SCHEMA_VERSION)) &&
       (profile = member(root, "profile", JSON_OBJECT, "profile file", out, size)) &&
       only_keys(profile, profile_keys, 6, "profile member", out, size) &&
       (uuid = member(profile, "uuid", JSON_STRING, "profile", out, size)) &&
       (uuid_valid(uuid->string) || why(out, size, "profile: uuid \"%s\" is not a lowercase UUID", uuid->string)) &&
       (name = member(profile, "name", JSON_STRING, "profile", out, size)) &&
       (name->string[0] || why(out, size, "profile: empty name")) &&
       (part = member(profile, "weights", JSON_OBJECT, "profile", out, size)) && weights(part, p, out, size) &&
       (part = member(profile, "asset_importance", JSON_OBJECT, "profile", out, size)) &&
       assets(part, p, out, size) &&
       (part = member(profile, "security_visibility", JSON_OBJECT, "profile", out, size)) &&
       visibility(part, p, out, size) &&
       (direction = member(profile, "direction", JSON_STRING, "profile", out, size)) &&
       (!strcmp(direction->string, "equal") ||
        why(out, size, "profile: direction \"%s\" is not supported (schema v1: \"equal\")", direction->string));
  if (ok) memcpy(p->uuid, uuid->string, 37);
  json_free(document);
  if (!ok) profile_release(p);
  return ok;
}

bool profile_load(const char *path, struct profile *p, char *out, size_t size) {
  FILE *f = fopen(path, "rb");
  if (!f) return why(out, size, "profile %s: %s", path, strerror(errno));
  char *text = fm_calloc(PROFILE_FILE_MAX + 1, 1);
  size_t length = text ? fread(text, 1, PROFILE_FILE_MAX + 1, f) : 0;
  bool read_error = ferror(f);
  fclose(f);
  if (!text) return why(out, size, "profile: allocation");
  bool ok = !read_error || why(out, size, "profile %s: read error", path);
  ok = ok && (length <= PROFILE_FILE_MAX || why(out, size, "profile %s: larger than %u bytes", path, PROFILE_FILE_MAX));
  ok = ok && profile_compile(text, length, p, out, size);
  fm_free(text);
  return ok;
}
void profile_release(struct profile *p) {
  fm_free(p->spans4);
  fm_free(p->spans6);
  p->spans4 = p->spans6 = NULL;
  p->spans4_count = p->spans6_count = 0;
}
double profile_asset(const struct profile *p, struct addr a) {
  const struct asset_span *spans = a.af == 4 ? p->spans4 : p->spans6;
  size_t lo = 0, hi = a.af == 4 ? p->spans4_count : p->spans6_count;
  u128 key = key_of(a);
  while (lo < hi) { /* the first span ending at or after key */
    size_t mid = lo + (hi - lo) / 2;
    if (spans[mid].hi < key) lo = mid + 1;
    else hi = mid;
  }
  size_t count = a.af == 4 ? p->spans4_count : p->spans6_count;
  return lo < count && spans[lo].lo <= key ? spans[lo].multiplier : p->default_multiplier;
}
uint64_t profile_unit(const struct profile *p, double multiplier) {
  if (!p->asset_rules) return 1;
  double unit = round(PROFILE_DISCOVERY_UNIT * multiplier / p->min_multiplier);
  return unit < 1 ? 1 : unit >= 1.8e19 ? UINT64_MAX : (uint64_t)unit;
}
double profile_unit_multiplier(const struct profile *p, uint64_t unit) {
  if (!p->asset_rules) return p->default_multiplier;
  return (double)unit * p->min_multiplier / PROFILE_DISCOVERY_UNIT;
}

/* -------- ranking -------- */

struct ranker {
  const struct profile *active;
  /* this sample's selection and the flow keys of the previous one
   * (incumbency), at most `limit` each */
  struct selected *selection;
  size_t selected, capacity;
  struct map previous; /* last selection's flow keys (presence only) */
  /* every tracked flow's effective score this sample */
  double *scores;
  size_t scores_capacity, scores_count;
  /* scratch: bounded heaps (general, and one per security class S1-S3) */
  struct candidate_row *general, *reserved[4];
  size_t scratch;
};
struct candidate_row {
  uint32_t flow;
  double score;
  uint64_t order;
};

struct ranker *ranker_create(struct fm_error *error) {
  struct ranker *p = fm_calloc(1, sizeof(*p));
  if (!p) fm_error_set(error, errno, "ranker allocation");
  return p;
}
void ranker_reset(struct ranker *p) {
  map_clear(&p->previous);
  p->selected = 0;
}
void ranker_destroy(struct ranker *p) {
  if (!p) return;
  ranker_reset(p);
  fm_free(p->selection);
  fm_free(p->scores);
  fm_free(p->general);
  for (int c = SECURITY_S1; c <= SECURITY_S3; c++) fm_free(p->reserved[c]);
  fm_free(p);
}
void ranker_configure(struct ranker *p, const struct profile *active) { p->active = active; }
const struct profile *ranker_profile(const struct ranker *p) { return p->active; }
size_t ranker_selection(const struct ranker *p, const struct selected **out) {
  *out = p->selection;
  return p->selected;
}
double ranker_score(const struct ranker *p, size_t flow) {
  return flow < p->scores_count ? p->scores[flow] : 0;
}

static double feature_value(const struct flow *f, const struct flow_rates *rates,
                            enum profile_feature feature, double interval) {
  switch (feature) {
  case FEATURE_BYTE_RATE: return rates->rate_from_remote + rates->rate_to_remote;
  case FEATURE_PACKET_RATE: return rates->packet_rate;
  case FEATURE_ACTIVE_STATES: return (double)f->states;
  case FEATURE_NEW_STATE_RATE: return interval > 0 ? (double)f->created / interval : 0;
  case FEATURE_FLOW_VOLUME: return (double)rates->volume;
  case FEATURE_PF_BLOCKED: return (double)f->evidence.blocked_hits;
  case FEATURE_THREAT_INTELLIGENCE: return f->evidence.mask & EVIDENCE_THREAT_LIST ? 1 : 0;
  case FEATURE_IDS_EVIDENCE:
    return f->evidence.mask & EVIDENCE_IDS_HIGH ? 2 : f->evidence.mask & EVIDENCE_IDS ? 1 : 0;
  default: return 0;
  }
}
double profile_value(const struct aggregate *a, const struct ranking *r, size_t flow,
                     enum profile_feature feature, double interval) {
  const struct flow *f = aggregate_flow(a, flow);
  struct flow_rates rates;
  if (!f || !ranking_rates(r, flow, &rates)) return 0;
  return feature_value(f, &rates, feature, interval);
}
enum flow_presence profile_presence(const struct flow *f, const struct flow_rates *rates) {
  if (f->carp == FLOW_CARP_MIRROR) return PRESENCE_MIRROR;
  if (f->carp == FLOW_CARP_HIDDEN) return PRESENCE_NONE;
  uint64_t bytes = f->bytes_from_remote;
  bytes = UINT64_MAX - bytes < f->bytes_to_remote ? UINT64_MAX : bytes + f->bytes_to_remote;
  if (!bytes) return PRESENCE_NONE;
  /* handshake-sized only: at most PROBE_BYTES_PER_STATE per state (states
   * never come near the product's overflow) */
  if (bytes <= (uint64_t)PROBE_BYTES_PER_STATE * f->states)
    return rates->attempts >= PROBE_ATTEMPTS_MIN ? PRESENCE_PROBE : PRESENCE_NONE;
  return PRESENCE_TRAFFIC;
}

/* Quality with traffic features faded by activity, times the asset. */
static double quality(const struct profile *def, const double values[FEATURE_COUNT], double activity) {
  double score = 0;
  for (int k = 0; k < FEATURE_COUNT; k++)
    if (def->weight[k] > 0)
      score += def->weight[k] * log1p(values[k] / FEATURES[k].scale) * (FEATURES[k].traffic ? activity : 1);
  return score;
}
double profile_estimate(const struct profile *def, const double values[FEATURE_COUNT], double asset) {
  return quality(def, values, 1.0) * asset;
}

/* Better first: higher score, then earlier first-seen. */
static bool better(const struct candidate_row *x, const struct candidate_row *y) {
  return x->score > y->score || (x->score == y->score && x->order < y->order);
}
/* A bounded min-heap (worst at the root) keeping the `limit` best rows. */
static void heap_offer(struct candidate_row *heap, size_t *used, size_t limit,
                       const struct candidate_row *row) {
  if (!limit) return;
  size_t n;
  if (*used < limit) {
    n = (*used)++;
    while (n) {
      size_t parent = (n - 1) / 2;
      if (!better(&heap[parent], row)) break;
      heap[n] = heap[parent];
      n = parent;
    }
    heap[n] = *row;
    return;
  }
  if (!better(row, &heap[0])) return;
  n = 0;
  for (;;) {
    size_t child = 2 * n + 1;
    if (child >= *used) break;
    if (child + 1 < *used && better(&heap[child], &heap[child + 1])) child++;
    if (!better(row, &heap[child])) break;
    heap[n] = heap[child];
    n = child;
  }
  heap[n] = *row;
}
static int best_first(const void *left, const void *right) {
  const struct candidate_row *a = left, *b = right;
  return better(a, b) ? -1 : better(b, a) ? 1 : 0;
}
static bool reserve_rows(struct selected **rows, size_t *capacity, size_t needed,
                         struct fm_error *error) {
  if (needed <= *capacity) return true;
  void *grown = fm_realloc(*rows, needed * sizeof(**rows));
  if (!grown) return fm_error_set(error, errno, "profile selection");
  *rows = grown;
  *capacity = needed;
  return true;
}
/* A security class's reserved places: the floor percentage of the
 * selection, rounded up (a minimum guarantee). */
size_t profile_floor_places(const struct profile *def, enum security_class class, size_t limit) {
  double places = ceil(def->floor_percent[class] * (double)limit / 100.0 - 1e-9);
  return places < 0 ? 0 : places > (double)limit ? limit : (size_t)places;
}

static bool select_scored(struct ranker *p, const struct aggregate *a, const struct ranking *r,
                          double interval, size_t limit, struct fm_error *error) {
  const struct profile *def = p->active;
  size_t flows = aggregate_counts(a).flows, general = 0, reserved[4] = {0}, places[4] = {0};
  for (int c = SECURITY_S1; c <= SECURITY_S3; c++) places[c] = profile_floor_places(def, c, limit);
  for (size_t f = 0; f < flows; f++) {
    const struct flow *flow = aggregate_flow(a, f);
    struct flow_rates rates;
    if (!ranking_rates(r, f, &rates)) continue;
    double values[FEATURE_COUNT];
    for (int k = 0; k < FEATURE_COUNT; k++) values[k] = feature_value(flow, &rates, k, interval);
    /* a flow with no reason to be on the map scores 0 and is never selected */
    if (profile_presence(flow, &rates) == PRESENCE_NONE) continue;
    double score = quality(def, values, rates.activity) * flow->asset;
    p->scores[f] = score;
    if (!(score > 0)) continue;
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote, flow->owner);
    if (map_find(&p->previous, key, sizeof(key))) score *= PROFILE_INCUMBENCY;
    struct candidate_row row = {(uint32_t)f, score, rates.order};
    /* a flow counts for its own (highest) class only, and competes for the
     * general places as well */
    enum security_class class = security_class(&flow->evidence);
    if (class != SECURITY_S0)
      heap_offer(p->reserved[class], &reserved[class], places[class], &row);
    heap_offer(p->general, &general, limit, &row);
  }
  if (!reserve_rows(&p->selection, &p->capacity, limit, error)) return false;
  /* the floors' flows (S3, S2, S1: disjoint), then the best others until
   * the limit; places a floor did not use stay in the general pool */
  size_t count = 0;
  for (int c = SECURITY_S3; c >= SECURITY_S1; c--)
    for (size_t k = 0; k < reserved[c] && count < limit; k++)
      p->selection[count++] = (struct selected){p->reserved[c][k].flow, p->reserved[c][k].score};
  size_t floors = count;
  qsort(p->general, general, sizeof(*p->general), best_first);
  for (size_t k = 0; k < general && count < limit; k++) {
    bool taken = false;
    for (size_t j = 0; j < floors && !taken; j++) taken = p->selection[j].flow == p->general[k].flow;
    if (!taken) p->selection[count++] = (struct selected){p->general[k].flow, p->general[k].score};
  }
  /* final order: by score, then first-seen */
  struct candidate_row *order = p->general;
  for (size_t k = 0; k < count; k++) {
    struct flow_rates rates;
    ranking_rates(r, p->selection[k].flow, &rates);
    order[k] = (struct candidate_row){p->selection[k].flow, p->selection[k].score, rates.order};
  }
  qsort(order, count, sizeof(*order), best_first);
  for (size_t k = 0; k < count; k++) p->selection[k] = (struct selected){order[k].flow, order[k].score};
  p->selected = count;
  /* incumbency for the next sample */
  map_clear(&p->previous);
  for (size_t k = 0; k < count; k++) {
    const struct flow *flow = aggregate_flow(a, p->selection[k].flow);
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flow->local, flow->remote, flow->owner);
    if (!map_insert(&p->previous, key, sizeof(key), error)) return false;
  }
  return true;
}

bool ranker_select(struct ranker *p, const struct aggregate *a, const struct ranking *r,
                   double interval, size_t limit, struct fm_error *error) {
  /* the scratch holds the general heap and one floor heap per class */
  if (p->scratch < limit) {
    void *general = fm_realloc(p->general, limit * sizeof(*p->general));
    if (!general) return fm_error_set(error, errno ? errno : ENOMEM, "ranker scratch");
    p->general = general;
    for (int c = SECURITY_S1; c <= SECURITY_S3; c++) {
      void *reserved = fm_realloc(p->reserved[c], limit * sizeof(*p->reserved[c]));
      if (!reserved) return fm_error_set(error, errno ? errno : ENOMEM, "ranker scratch");
      p->reserved[c] = reserved;
    }
    p->scratch = limit;
  }
  size_t flows = aggregate_counts(a).flows;
  if (flows > p->scores_capacity) {
    void *grown = fm_realloc(p->scores, flows * sizeof(*p->scores));
    if (!grown) return fm_error_set(error, errno ? errno : ENOMEM, "ranker scores");
    p->scores = grown;
    p->scores_capacity = flows;
  }
  p->scores_count = flows;
  if (flows) /* no flows: scores may still be NULL */
    memset(p->scores, 0, flows * sizeof(*p->scores));
  if (!p->active)
    return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "no active ranking profile");
  return select_scored(p, a, r, interval, limit, error);
}

size_t ranker_bytes(const struct ranker *p) {
  return sizeof(*p) + p->scratch * 4 * sizeof(*p->general) + p->capacity * sizeof(*p->selection) +
         p->scores_capacity * sizeof(*p->scores) + map_bytes(&p->previous);
}
