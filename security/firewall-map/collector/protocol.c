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

#include "protocol.h"
#include "alloc.h"
#include "budget.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
void protocol_put(unsigned char **p, uint64_t value, unsigned width) {
  for (unsigned n = width; n; n--)
    *(*p)++ = value >> ((n - 1) * 8);
}
uint64_t protocol_get(const unsigned char **p, unsigned width) {
  uint64_t value = 0;
  while (width--)
    value = (value << 8) | *(*p)++;
  return value;
}
void protocol_address_put(unsigned char **p, struct addr a) {
  *(*p)++ = a.af;
  memcpy(*p, a.b, 16);
  *p += 16;
}
static void put_double(unsigned char **p, double value) {
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  protocol_put(p, bits, 8);
}
/* CRC-32 (IEEE 802.3, reflected 0xedb88320), as zlib.crc32 computes it. */
static const uint32_t crc_table[256] = {
    0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau, 0x076dc419u, 0x706af48fu,
    0xe963a535u, 0x9e6495a3u, 0x0edb8832u, 0x79dcb8a4u, 0xe0d5e91eu, 0x97d2d988u,
    0x09b64c2bu, 0x7eb17cbdu, 0xe7b82d07u, 0x90bf1d91u, 0x1db71064u, 0x6ab020f2u,
    0xf3b97148u, 0x84be41deu, 0x1adad47du, 0x6ddde4ebu, 0xf4d4b551u, 0x83d385c7u,
    0x136c9856u, 0x646ba8c0u, 0xfd62f97au, 0x8a65c9ecu, 0x14015c4fu, 0x63066cd9u,
    0xfa0f3d63u, 0x8d080df5u, 0x3b6e20c8u, 0x4c69105eu, 0xd56041e4u, 0xa2677172u,
    0x3c03e4d1u, 0x4b04d447u, 0xd20d85fdu, 0xa50ab56bu, 0x35b5a8fau, 0x42b2986cu,
    0xdbbbc9d6u, 0xacbcf940u, 0x32d86ce3u, 0x45df5c75u, 0xdcd60dcfu, 0xabd13d59u,
    0x26d930acu, 0x51de003au, 0xc8d75180u, 0xbfd06116u, 0x21b4f4b5u, 0x56b3c423u,
    0xcfba9599u, 0xb8bda50fu, 0x2802b89eu, 0x5f058808u, 0xc60cd9b2u, 0xb10be924u,
    0x2f6f7c87u, 0x58684c11u, 0xc1611dabu, 0xb6662d3du, 0x76dc4190u, 0x01db7106u,
    0x98d220bcu, 0xefd5102au, 0x71b18589u, 0x06b6b51fu, 0x9fbfe4a5u, 0xe8b8d433u,
    0x7807c9a2u, 0x0f00f934u, 0x9609a88eu, 0xe10e9818u, 0x7f6a0dbbu, 0x086d3d2du,
    0x91646c97u, 0xe6635c01u, 0x6b6b51f4u, 0x1c6c6162u, 0x856530d8u, 0xf262004eu,
    0x6c0695edu, 0x1b01a57bu, 0x8208f4c1u, 0xf50fc457u, 0x65b0d9c6u, 0x12b7e950u,
    0x8bbeb8eau, 0xfcb9887cu, 0x62dd1ddfu, 0x15da2d49u, 0x8cd37cf3u, 0xfbd44c65u,
    0x4db26158u, 0x3ab551ceu, 0xa3bc0074u, 0xd4bb30e2u, 0x4adfa541u, 0x3dd895d7u,
    0xa4d1c46du, 0xd3d6f4fbu, 0x4369e96au, 0x346ed9fcu, 0xad678846u, 0xda60b8d0u,
    0x44042d73u, 0x33031de5u, 0xaa0a4c5fu, 0xdd0d7cc9u, 0x5005713cu, 0x270241aau,
    0xbe0b1010u, 0xc90c2086u, 0x5768b525u, 0x206f85b3u, 0xb966d409u, 0xce61e49fu,
    0x5edef90eu, 0x29d9c998u, 0xb0d09822u, 0xc7d7a8b4u, 0x59b33d17u, 0x2eb40d81u,
    0xb7bd5c3bu, 0xc0ba6cadu, 0xedb88320u, 0x9abfb3b6u, 0x03b6e20cu, 0x74b1d29au,
    0xead54739u, 0x9dd277afu, 0x04db2615u, 0x73dc1683u, 0xe3630b12u, 0x94643b84u,
    0x0d6d6a3eu, 0x7a6a5aa8u, 0xe40ecf0bu, 0x9309ff9du, 0x0a00ae27u, 0x7d079eb1u,
    0xf00f9344u, 0x8708a3d2u, 0x1e01f268u, 0x6906c2feu, 0xf762575du, 0x806567cbu,
    0x196c3671u, 0x6e6b06e7u, 0xfed41b76u, 0x89d32be0u, 0x10da7a5au, 0x67dd4accu,
    0xf9b9df6fu, 0x8ebeeff9u, 0x17b7be43u, 0x60b08ed5u, 0xd6d6a3e8u, 0xa1d1937eu,
    0x38d8c2c4u, 0x4fdff252u, 0xd1bb67f1u, 0xa6bc5767u, 0x3fb506ddu, 0x48b2364bu,
    0xd80d2bdau, 0xaf0a1b4cu, 0x36034af6u, 0x41047a60u, 0xdf60efc3u, 0xa867df55u,
    0x316e8eefu, 0x4669be79u, 0xcb61b38cu, 0xbc66831au, 0x256fd2a0u, 0x5268e236u,
    0xcc0c7795u, 0xbb0b4703u, 0x220216b9u, 0x5505262fu, 0xc5ba3bbeu, 0xb2bd0b28u,
    0x2bb45a92u, 0x5cb36a04u, 0xc2d7ffa7u, 0xb5d0cf31u, 0x2cd99e8bu, 0x5bdeae1du,
    0x9b64c2b0u, 0xec63f226u, 0x756aa39cu, 0x026d930au, 0x9c0906a9u, 0xeb0e363fu,
    0x72076785u, 0x05005713u, 0x95bf4a82u, 0xe2b87a14u, 0x7bb12baeu, 0x0cb61b38u,
    0x92d28e9bu, 0xe5d5be0du, 0x7cdcefb7u, 0x0bdbdf21u, 0x86d3d2d4u, 0xf1d4e242u,
    0x68ddb3f8u, 0x1fda836eu, 0x81be16cdu, 0xf6b9265bu, 0x6fb077e1u, 0x18b74777u,
    0x88085ae6u, 0xff0f6a70u, 0x66063bcau, 0x11010b5cu, 0x8f659effu, 0xf862ae69u,
    0x616bffd3u, 0x166ccf45u, 0xa00ae278u, 0xd70dd2eeu, 0x4e048354u, 0x3903b3c2u,
    0xa7672661u, 0xd06016f7u, 0x4969474du, 0x3e6e77dbu, 0xaed16a4au, 0xd9d65adcu,
    0x40df0b66u, 0x37d83bf0u, 0xa9bcae53u, 0xdebb9ec5u, 0x47b2cf7fu, 0x30b5ffe9u,
    0xbdbdf21cu, 0xcabac28au, 0x53b39330u, 0x24b4a3a6u, 0xbad03605u, 0xcdd70693u,
    0x54de5729u, 0x23d967bfu, 0xb3667a2eu, 0xc4614ab8u, 0x5d681b02u, 0x2a6f2b94u,
    0xb40bbe37u, 0xc30c8ea1u, 0x5a05df1bu, 0x2d02ef8du,
};
static uint32_t crc(uint32_t value, const void *data, size_t size) {
  value = ~value;
  const unsigned char *p = data;
  while (size--)
    value = crc_table[(value ^ *p++) & 255] ^ (value >> 8);
  return ~value;
}
bool protocol_frame(FILE *f, const void *data, size_t len, uint32_t *checksum,
                    struct fm_error *error) {
  if (!len || len > FM_FRAME_MAX)
    return fm_error_set(error, EOVERFLOW, "frame size");
  unsigned char size[4], *p = size;
  protocol_put(&p, len, 4);
  if (fwrite(size, 1, 4, f) != 4 || fwrite(data, 1, len, f) != len)
    return fm_error_set(error, errno ? errno : EIO, "frame write");
  if (checksum) {
    *checksum = crc(*checksum, size, 4);
    *checksum = crc(*checksum, data, len);
  }
  return true;
}

/* Sizes of the fixed FMAGG4 records (PROTOCOL.md). */
#define FLOW_RECORD_SIZE 178
#define EVENT_RECORD_SIZE 194
#define TELEMETRY_RECORD_SIZE 365
#define FOOTER_RECORD_SIZE 117
#define CLASSIFIED_RECORD_SIZE 36
#define CLASS_SET_RECORD_SIZE 12

struct sent {
  uint64_t flows, candidates, matches, remotes, remote_candidates, classified, class_sets;
};

static bool write_header(FILE *f, bool threats, uint32_t *checksum,
                         struct fm_error *error) {
  if (fwrite("FMAGG4\0\0", 1, 8, f) != 8)
    return fm_error_set(error, errno ? errno : EIO, "FMAGG4 header");
  unsigned char b[16], *p = b;
  *p++ = RECORD_HEADER;
  protocol_put(&p, FM_PROTOCOL_VERSION, 4);
  protocol_put(&p, threats ? 1 : 0, 4);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_flow(FILE *f, size_t rank, const struct flow *flow,
                       const struct ranked_flow *rates, uint32_t *checksum,
                       struct fm_error *error) {
  unsigned char b[FLOW_RECORD_SIZE], *p = b;
  *p++ = RECORD_FLOW;
  protocol_put(&p, rank, 4);
  protocol_address_put(&p, flow->local);
  protocol_address_put(&p, flow->remote);
  protocol_put(&p, flow->states, 8);
  protocol_put(&p, flow->bytes_from_remote, 8);
  protocol_put(&p, flow->bytes_to_remote, 8);
  protocol_put(&p, flow->oldest, 4);
  protocol_put(&p, flow->youngest, 4);
  protocol_put(&p, flow->remote_initiated_weight, 8);
  protocol_put(&p, flow->local_initiated_weight, 8);
  protocol_put(&p, flow->first, 8);
  protocol_put(&p, flow->delta.bytes_from_remote, 8);
  protocol_put(&p, flow->delta.bytes_to_remote, 8);
  protocol_put(&p, flow->delta.packets, 8);
  protocol_put(&p, flow->classes, 8);
  *p++ = flow->evidence.mask;
  *p++ = (unsigned char)security_class(&flow->evidence);
  protocol_put(&p, flow->evidence.blocked_hits, 4);
  protocol_put(&p, flow->evidence.ids_alerts, 4);
  *p++ = flow->evidence.ids_severity;
  put_double(&p, rates->rate_from_remote);
  put_double(&p, rates->rate_to_remote);
  put_double(&p, rates->packet_rate);
  put_double(&p, rates->activity);
  put_double(&p, rates->score);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_candidate(FILE *f, unsigned char kind, uint32_t owner,
                            const struct candidate_view *value, bool weight,
                            uint32_t *checksum, struct fm_error *error) {
  unsigned char b[32 + CANDIDATE_VALUE_MAX], *p = b;
  if (value->len > CANDIDATE_VALUE_MAX)
    return fm_error_set(error, EOVERFLOW, "candidate size");
  *p++ = kind;
  protocol_put(&p, owner, 4);
  *p++ = value->kind;
  protocol_put(&p, value->seq, 8);
  if (weight)
    protocol_put(&p, value->weight, 8);
  protocol_put(&p, value->association, 8);
  protocol_put(&p, value->len, 2);
  memcpy(p, value->data, value->len);
  p += value->len;
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_match(FILE *f, const struct event_match *match,
                        uint32_t *checksum, struct fm_error *error) {
  const struct correlation_value *v = &match->value;
  unsigned char b[EVENT_RECORD_SIZE], *p = b;
  *p++ = RECORD_EVENT_MATCH;
  protocol_put(&p, match->id, 2);
  *p++ = match->kind;
  *p++ = match->key.protocol;
  protocol_address_put(&p, match->key.public.a);
  protocol_put(&p, match->key.public.port, 2);
  protocol_address_put(&p, match->key.remote.a);
  protocol_put(&p, match->key.remote.port, 2);
  *p++ = v->has_inside;
  protocol_address_put(&p, v->inside.a);
  protocol_put(&p, v->inside.port, 2);
  protocol_put(&p, v->state_id, 8);
  protocol_put(&p, v->creator_id, 4);
  *p++ = v->ambiguous;
  protocol_put(&p, v->age, 4);
  protocol_put(&p, v->bytes_from_remote, 8);
  protocol_put(&p, v->bytes_to_remote, 8);
  protocol_put(&p, v->packets_from_remote, 8);
  protocol_put(&p, v->packets_to_remote, 8);
  *p++ = v->remote_initiated;
  *p++ = v->apparent_remote_initiated;
  memcpy(p, v->interface, FM_INTERFACE_SIZE);
  p += FM_INTERFACE_SIZE;
  memcpy(p, v->rule, FM_LABEL_SIZE);
  p += FM_LABEL_SIZE;
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_telemetry(FILE *f, const struct telemetry *t,
                            uint32_t *checksum, struct fm_error *error) {
  unsigned char b[TELEMETRY_RECORD_SIZE], *p = b;
  *p++ = RECORD_TELEMETRY;
  protocol_put(&p, t->pid, 4);
  protocol_put(&p, t->sequence, 8);
  put_double(&p, t->interval);
  put_double(&p, t->dump_seconds);
  put_double(&p, t->processing_seconds);
  put_double(&p, t->user_cpu);
  put_double(&p, t->system_cpu);
  const uint64_t values[] = {t->max_rss,
                             t->heap_bytes,
                             t->heap_peak,
                             t->heap_blocks,
                             t->heap_budget,
                             t->state_limit,
                             t->preflight_states,
                             t->skipped_af_translation,
                             t->candidates_omitted,
                             t->threat_remotes_omitted,
                             t->threat_candidates_omitted,
                             t->event_history_evicted,
                             t->classifier_bytes,
                             t->regime,
                             t->next_regime,
                             t->quality_discovery,
                             t->quality_ranking,
                             t->quality_attribution,
                             t->discovery_error,
                             t->flows_total,
                             t->flows_estimated,
                             t->tracked_flows,
                             t->tracked_limit,
                             t->exit_threshold,
                             t->forced_limit,
                             t->forced_flows,
                             t->forced_refused,
                             t->candidate_limit,
                             t->candidate_evictions,
                             t->join_limit,
                             t->join_refused,
                             t->untracked_states,
                             t->promoted,
                             t->baseline_bytes,
                             t->tracked_bytes,
                             t->candidate_bytes,
                             t->join_bytes,
                             t->ranking_bytes,
                             t->discovery_bytes};
  for (size_t n = 0; n < sizeof(values) / sizeof(*values); n++)
    protocol_put(&p, values[n], 8);
  return protocol_frame(f, b, p - b, checksum, error);
}
static bool write_footer(FILE *f, struct sample_outcome outcome,
                         struct aggregate_counts counts, const struct sent *sent,
                         uint32_t checksum, struct fm_error *error) {
  unsigned char b[FOOTER_RECORD_SIZE], *p = b;
  *p++ = RECORD_FOOTER;
  protocol_put(&p, outcome.code, 4);
  protocol_put(&p, outcome.context_kind, 4);
  protocol_put(&p, outcome.actual, 8);
  protocol_put(&p, outcome.limit, 8);
  protocol_put(&p, counts.seen, 8);
  protocol_put(&p, counts.retained, 8);
  protocol_put(&p, counts.mapped, 8);
  protocol_put(&p, counts.flows, 8);
  protocol_put(&p, sent->flows, 8);
  protocol_put(&p, sent->candidates, 8);
  protocol_put(&p, sent->matches, 8);
  protocol_put(&p, sent->remotes, 8);
  protocol_put(&p, sent->remote_candidates, 8);
  protocol_put(&p, sent->classified, 8);
  protocol_put(&p, sent->class_sets, 8);
  protocol_put(&p, checksum, 4);
  return protocol_frame(f, b, p - b, NULL, error) &&
         (fflush(f) == 0 || fm_error_set(error, errno, "FMAGG4 flush"));
}

/* A candidate of a sent flow, while choosing which ones fit the budget. */
struct chosen {
  uint32_t rank;
  unsigned char kind;
  uint64_t weight, seq;
  size_t index;
};
static int compare_chosen(const void *left, const void *right) {
  const struct chosen *a = left, *b = right;
  if (a->rank != b->rank) return a->rank < b->rank ? -1 : 1;
  if (a->kind != b->kind) return a->kind < b->kind ? -1 : 1;
  if (a->weight != b->weight) return a->weight > b->weight ? -1 : 1;
  return a->seq < b->seq ? -1 : a->seq > b->seq;
}

/* Ranked (or explicitly selected) flows with, per (flow, kind), the
 * `candidates_per_kind` heaviest candidates (earliest first on ties). */
static bool write_flows(FILE *f, const struct aggregate *a,
                        const struct ranking *ranking,
                        const struct ranked_flow *selection, size_t selected,
                        size_t candidates_per_kind, uint32_t *checksum,
                        struct sent *sent, uint64_t *omitted,
                        struct fm_error *error) {
  size_t total = aggregate_counts(a).flows;
  if (total > UINT32_MAX || total > SIZE_MAX / sizeof(uint32_t))
    return fm_error_set(error, EOVERFLOW, "ranked flow count");
  /* rank_of[flow] = rank + 1 for sent flows, 0 otherwise. */
  uint32_t *rank_of = total ? fm_calloc(total, sizeof(*rank_of)) : NULL;
  if (total && !rank_of)
    return fm_error_set(error, errno, "ranked flow index");
  struct chosen *chosen = NULL;
  size_t chosen_count = 0, chosen_capacity = 0;
  bool ok = true;
  for (size_t n = 0; ok && n < selected; n++) {
    struct ranked_flow rank;
    bool valid = ranking ? ranking_at(ranking, n, &rank) : true;
    if (!ranking)
      rank = selection[n];
    if (!valid || rank.flow >= total || n >= UINT32_MAX || rank_of[rank.flow]) {
      ok = fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "ranked flow identity");
      break;
    }
    rank_of[rank.flow] = (uint32_t)n + 1;
    ok = write_flow(f, n, aggregate_flow(a, rank.flow), &rank, checksum, error);
    sent->flows += ok;
  }
  size_t candidates = aggregate_counts(a).candidates;
  for (size_t n = 0; ok && n < candidates; n++) {
    struct candidate_view value;
    if (!aggregate_candidate(a, n, &value) || value.flow >= total) {
      ok = fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "ranked candidate identity");
      break;
    }
    if (!rank_of[value.flow])
      continue;
    if (chosen_count == chosen_capacity) {
      size_t capacity = chosen_capacity ? chosen_capacity * 2 : 256;
      void *grown = capacity <= SIZE_MAX / sizeof(*chosen)
                        ? fm_realloc(chosen, capacity * sizeof(*chosen)) : NULL;
      if (!grown) {
        ok = fm_error_set(error, errno ? errno : ENOMEM, "candidate selection");
        break;
      }
      chosen = grown;
      chosen_capacity = capacity;
    }
    chosen[chosen_count++] = (struct chosen){rank_of[value.flow] - 1, value.kind,
                                             value.weight, value.seq, n};
  }
  if (ok && chosen_count)
    qsort(chosen, chosen_count, sizeof(*chosen), compare_chosen);
  size_t run = 0;
  for (size_t n = 0; ok && n < chosen_count; n++) {
    run = n && chosen[n].rank == chosen[n - 1].rank && chosen[n].kind == chosen[n - 1].kind
              ? run + 1 : 0;
    if (run >= candidates_per_kind) {
      (*omitted)++;
      continue;
    }
    struct candidate_view value;
    aggregate_candidate(a, chosen[n].index, &value);
    ok = write_candidate(f, RECORD_CANDIDATE, chosen[n].rank, &value, true, checksum, error);
    sent->candidates += ok;
  }
  fm_free(chosen);
  fm_free(rank_of);
  return ok;
}
static bool write_threats(FILE *f, const struct threat_summary *threats,
                          uint32_t *checksum, struct sent *sent,
                          struct fm_error *error) {
  size_t remotes = threat_summary_remote_count(threats);
  for (size_t n = 0; n < remotes; n++) {
    struct threat_remote remote;
    if (!threat_summary_remote_at(threats, n, &remote))
      return fm_error_set(error, EINVAL, "threat summary remote");
    unsigned char b[64], *p = b;
    *p++ = RECORD_THREAT_REMOTE;
    protocol_put(&p, n, 4);
    protocol_address_put(&p, remote.address);
    protocol_put(&p, remote.remote_initiated_states, 8);
    protocol_put(&p, remote.local_initiated_states, 8);
    protocol_put(&p, remote.bytes, 8);
    protocol_put(&p, remote.classes, 8);
    protocol_put(&p, remote.youngest, 4);
    if (!protocol_frame(f, b, p - b, checksum, error))
      return false;
    sent->remotes++;
  }
  size_t candidates = threat_summary_candidate_count(threats);
  for (size_t n = 0; n < candidates; n++) {
    struct threat_candidate_view view;
    if (!threat_summary_candidate_at(threats, n, &view))
      return fm_error_set(error, EINVAL, "threat summary candidate");
    if (!write_candidate(f, RECORD_THREAT_CANDIDATE, view.remote,
                         &view.candidate, false, checksum, error))
      return false;
    sent->remote_candidates++;
  }
  return true;
}

/* The footer's flow total is every flow of the sample, tracked or not (an
 * estimate when the telemetry says so); the tracked count is in the telemetry. */
static struct aggregate_counts footer_counts(const struct aggregate *a, const struct telemetry *t) {
  struct aggregate_counts counts = aggregate_counts(a);
  if (t->flows_total > counts.flows)
    counts.flows = t->flows_total;
  return counts;
}

/* Masks of the requested addresses (nonzero only), then every set's status. */
static size_t address_key(unsigned char key[17], struct addr a) {
  key[0] = a.af;
  memcpy(key + 1, a.b, 16);
  return 17;
}
/* Per requested address: its set mask, its evidence (facts and the derived
 * security class: the one policy, evidence.h) and its PF states in tracked
 * flows, when any of them is set. */
static bool write_classification(FILE *f, const struct class_report *report,
                                 uint32_t *checksum, struct sent *sent,
                                 struct fm_error *error) {
  struct map asked = {0};
  uint64_t *states = report->address_count && report->aggregate
                         ? fm_calloc(report->address_count, sizeof(*states)) : NULL;
  bool ok = !(report->address_count && report->aggregate && !states) ||
            fm_error_set(error, errno, "classified states");
  /* states per asked address: one pass over the tracked flows */
  for (size_t n = 0; ok && states && n < report->address_count; n++) {
    unsigned char key[17];
    struct item *item = lookup(&asked, key, address_key(key, report->addresses[n]), true, error);
    if (!(ok = item != NULL)) break;
    item->value = n;
  }
  size_t flows = ok && states ? aggregate_counts(report->aggregate).flows : 0;
  for (size_t n = 0; n < flows; n++) {
    const struct flow *flow = aggregate_flow(report->aggregate, n);
    unsigned char key[17];
    const struct item *item = map_find(&asked, key, address_key(key, flow->remote));
    if (item) states[item->value] += flow->states;
  }
  for (size_t n = 0; ok && n < report->address_count; n++) {
    uint64_t mask = classifier_lookup(report->classifier, report->addresses[n]);
    struct evidence facts = {0};
    if (report->evidence) {
      unsigned char key[17];
      const struct item *item = map_find(report->evidence, key, address_key(key, report->addresses[n]));
      if (item) facts = report->facts[item->value];
    }
    if (mask & report->threat_mask) facts.mask |= EVIDENCE_THREAT_LIST;
    uint64_t count = states ? states[n] : 0;
    if (!mask && !facts.mask && !count) continue;
    unsigned char b[CLASSIFIED_RECORD_SIZE], *p = b;
    *p++ = RECORD_CLASSIFIED;
    protocol_address_put(&p, report->addresses[n]);
    protocol_put(&p, mask, 8);
    *p++ = facts.mask;
    *p++ = (unsigned char)security_class(&facts);
    protocol_put(&p, count, 8);
    if (!(ok = protocol_frame(f, b, p - b, checksum, error))) break;
    sent->classified++;
  }
  map_clear(&asked);
  fm_free(states);
  if (!ok) return false;
  size_t sets = report->classifier ? classifier_set_count(report->classifier) : 0;
  for (size_t n = 0; n < sets; n++) {
    const struct class_set *set = classifier_set(report->classifier, n);
    unsigned char b[CLASS_SET_RECORD_SIZE], *p = b;
    *p++ = RECORD_CLASS_SET;
    *p++ = (unsigned char)set->id;
    *p++ = (unsigned char)set->category;
    *p++ = (unsigned char)set->status;
    protocol_put(&p, set->entries, 8);
    if (!protocol_frame(f, b, p - b, checksum, error)) return false;
    sent->class_sets++;
  }
  return true;
}

/* One record per profile: its selection as union positions with scores. */
static bool write_selections(FILE *f, const struct ranked_output *out, uint32_t *checksum,
                             struct fm_error *error) {
  for (size_t n = 0; n < profiles_count(out->profiles); n++) {
    const struct selected *rows;
    size_t count = profiles_selection(out->profiles, n, &rows);
    unsigned char b[4 + BUDGET_RANKED_FLOWS * 12], *p = b;
    if (count > BUDGET_RANKED_FLOWS)
      return fm_error_fail(error, FM_FAILURE_INTERNAL, EOVERFLOW, "profile selection size");
    *p++ = RECORD_SELECTION;
    *p++ = (unsigned char)n;
    protocol_put(&p, count, 2);
    for (size_t k = 0; k < count; k++) {
      uint32_t position = out->position[rows[k].flow];
      if (!position)
        return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "profile selection identity");
      protocol_put(&p, position - 1, 4);
      put_double(&p, rows[k].score);
    }
    if (!protocol_frame(f, b, p - b, checksum, error)) return false;
  }
  return true;
}

bool protocol_write_ranked(FILE *f, const struct aggregate *a,
                           const struct ranked_output *ranked,
                           const struct threat_summary *threats,
                           const struct event_match *matches, size_t count,
                           const struct class_report *classes,
                           size_t candidates_per_kind, struct telemetry *telemetry,
                           struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  if (!write_header(f, threats != NULL, &checksum, error) ||
      !write_flows(f, a, NULL, ranked->flows, ranked->count, candidates_per_kind,
                   &checksum, &sent, &telemetry->candidates_omitted, error) ||
      !write_selections(f, ranked, &checksum, error) ||
      (threats && !write_threats(f, threats, &checksum, &sent, error)))
    return false;
  if (threats) {
    telemetry->threat_remotes_omitted = threat_summary_remotes_omitted(threats);
    telemetry->threat_candidates_omitted = threat_summary_candidates_omitted(threats);
  }
  for (size_t n = 0; n < count; n++) {
    if (!write_match(f, &matches[n], &checksum, error))
      return false;
    sent.matches++;
  }
  if (classes && !write_classification(f, classes, &checksum, &sent, error))
    return false;
  return write_telemetry(f, telemetry, &checksum, error) &&
         write_footer(f, (struct sample_outcome){OUTCOME_SAMPLE, 0, 0, 0},
                      footer_counts(a, telemetry), &sent, checksum, error);
}

bool protocol_write_selected(FILE *f, const struct aggregate *a,
                             const struct ranked_flow *rows, size_t count,
                             const struct telemetry *sample_telemetry,
                             struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  struct telemetry telemetry = *sample_telemetry;
  telemetry.candidates_omitted = 0;
  return write_header(f, false, &checksum, error) &&
         write_flows(f, a, NULL, rows, count, BUDGET_CANDIDATES_DEFAULT, &checksum, &sent,
                     &telemetry.candidates_omitted, error) &&
         write_telemetry(f, &telemetry, &checksum, error) &&
         write_footer(f, (struct sample_outcome){OUTCOME_SAMPLE, 0, 0, 0},
                      footer_counts(a, &telemetry), &sent, checksum, error);
}

bool protocol_write_refusal(FILE *f, struct sample_outcome outcome,
                            uint64_t states_seen,
                            const struct telemetry *telemetry,
                            struct fm_error *error) {
  uint32_t checksum = 0;
  struct sent sent = {0};
  struct aggregate_counts counts = {.seen = states_seen};
  return write_header(f, false, &checksum, error) &&
         write_telemetry(f, telemetry, &checksum, error) &&
         write_footer(f, outcome, counts, &sent, checksum, error);
}

void protocol_write_failure(FILE *f, const struct fm_error *failure) {
  unsigned char b[16 + sizeof(failure->message)], *p = b;
  size_t length = strnlen(failure->message, sizeof(failure->message));
  *p++ = RECORD_FAILURE;
  protocol_put(&p, (uint32_t)failure->failure_class, 4);
  protocol_put(&p, (uint32_t)failure->code, 4);
  memcpy(p, failure->message, length);
  p += length;
  struct fm_error ignored = {0};
  if (fwrite("FMFAIL1\0", 1, 8, f) == 8)
    protocol_frame(f, b, p - b, NULL, &ignored);
  fflush(f);
}
