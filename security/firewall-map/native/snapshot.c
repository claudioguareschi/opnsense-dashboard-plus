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

#include "snapshot.h"
#include "alloc.h"
#include "response.h"
#include "index.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

struct detail_row {
  struct detail_row *previous, *next;
  size_t cost, length;
  uint32_t flow;
  char json[];
};
struct row_list { struct detail_row *first, *last; };
/* Exact per-flow accounting over every matching state, independent of how
 * many exemplar rows fit the budgets. */
struct flow_totals {
  uint64_t matched, captured, bytes_from_remote, bytes_to_remote,
      packets_from_remote, packets_to_remote;
  unsigned reasons;
};
struct snapshot {
  const struct context *ctx;
  struct map selected;
  struct snapshot_flow *flows;
  struct flow_totals *totals;
  size_t count, byte_limit, state_limit, bytes, included;
  uint64_t observed, traversed, generation;
  unsigned reasons;
  double sample_time, started;
  struct row_list incident, ordinary;
};

static double wall_time(void) {
  struct timespec t;
  return clock_gettime(CLOCK_REALTIME, &t) ? 0.0 : t.tv_sec + t.tv_nsec / 1e9;
}
static void append(struct row_list *list, struct detail_row *row) {
  row->previous = list->last;
  row->next = NULL;
  if (list->last) list->last->next = row;
  else list->first = row;
  list->last = row;
}
static void drop_last(struct snapshot *s, unsigned reason) {
  struct detail_row *row = s->ordinary.last;
  s->ordinary.last = row->previous;
  if (row->previous) row->previous->next = NULL;
  else s->ordinary.first = NULL;
  s->bytes -= row->cost;
  s->included--;
  s->totals[row->flow].captured--;
  s->totals[row->flow].reasons |= reason;
  fm_free(row);
}
void snapshot_destroy(struct snapshot *s) {
  if (!s) return;
  struct row_list *lists[] = {&s->incident, &s->ordinary};
  for (unsigned i = 0; i < 2; i++) {
    struct detail_row *row = lists[i]->first;
    while (row) {
      struct detail_row *next = row->next;
      fm_free(row);
      row = next;
    }
  }
  map_clear(&s->selected);
  fm_free(s->flows);
  fm_free(s->totals);
  fm_free(s);
}

struct snapshot *snapshot_create(const struct context *ctx,
                                 const struct snapshot_flow *flows, size_t count,
                                 size_t byte_limit, size_t state_limit,
                                 uint64_t generation, double sample_time,
                                 struct fm_error *error) {
  if (count > FM_SNAPSHOT_FLOWS || byte_limit > FM_SNAPSHOT_BYTES ||
      !state_limit || state_limit > FM_SNAPSHOT_STATES) {
    fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "snapshot limits");
    return NULL;
  }
  struct snapshot *s = fm_calloc(1, sizeof(*s));
  if (!s) { fm_error_set(error, errno, "snapshot allocation"); return NULL; }
  s->ctx = ctx;
  s->count = count;
  s->byte_limit = byte_limit;
  s->state_limit = state_limit;
  s->generation = generation;
  s->sample_time = sample_time;
  s->started = wall_time();
  s->flows = count ? fm_malloc(count * sizeof(*flows)) : NULL;
  s->totals = count ? fm_calloc(count, sizeof(*s->totals)) : NULL;
  if (count && (!s->flows || !s->totals)) {
    fm_error_set(error, errno, "snapshot identities allocation");
    snapshot_destroy(s);
    return NULL;
  }
  if (count) memcpy(s->flows, flows, count * sizeof(*flows));
  for (size_t n = 0; n < count; n++) {
    unsigned char key[FM_FLOW_KEY_SIZE];
    state_flow_key(key, flows[n].local, flows[n].remote);
    struct item *i = lookup(&s->selected, key, sizeof(key), true, error);
    if (!i || i->count) {
      if (i) fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "duplicate snapshot flow");
      snapshot_destroy(s);
      return NULL;
    }
    i->count = 1;
    i->value = n;
  }
  return s;
}

static void address_text(struct addr a, char out[INET6_ADDRSTRLEN]) {
  inet_ntop(a.af == 4 ? AF_INET : AF_INET6, a.b, out, INET6_ADDRSTRLEN);
}
static void endpoint_json(struct endpoint e, char out[128]) {
  char address[INET6_ADDRSTRLEN];
  address_text(e.a, address);
  snprintf(out, 128, "{\"address\":\"%s\",\"port\":%u}", address, e.port);
}
/* Length of a well-formed UTF-8 sequence starting at in[0] (RFC 3629, no
 * overlong forms or surrogates), or 0. */
static size_t utf8_sequence(const unsigned char *in, size_t available) {
  unsigned char c = in[0];
  size_t length = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3
                  : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
  if (!length || length > available)
    return 0;
  for (size_t n = 1; n < length; n++)
    if ((in[n] & 0xc0) != 0x80)
      return 0;
  unsigned char second = in[1];
  if ((c == 0xe0 && second < 0xa0) || (c == 0xed && second > 0x9f) ||
      (c == 0xf0 && second < 0x90) || (c == 0xf4 && second > 0x8f))
    return 0;
  return length;
}
/* Fixed-size kernel strings, bounded before JSON escaping. Control
 * characters, quotes and backslashes are escaped; byte sequences that are not
 * valid UTF-8 (a label PF truncated mid-character) become U+FFFD, so the
 * document is always valid JSON. Output needs at most 6 bytes per input byte. */
static void escape(const char *text, size_t max, char *out) {
  const unsigned char *in = (const unsigned char *)text;
  size_t available = strnlen(text, max);
  char *p = out;
  for (size_t n = 0; n < available;) {
    unsigned char c = in[n];
    if (c < 0x80) {
      if (c < 32 || c == '"' || c == '\\') {
        snprintf(p, 7, "\\u%04x", c);
        p += 6;
      } else
        *p++ = (char)c;
      n++;
      continue;
    }
    size_t length = utf8_sequence(in + n, available - n);
    if (length) {
      memcpy(p, in + n, length);
      p += length;
      n += length;
    } else {
      memcpy(p, "\\ufffd", 6);
      p += 6;
      n++;
    }
  }
  *p = 0;
}
static size_t row_json(const struct state *state, const struct state_view *v,
                       char out[FM_FRAME_MAX], size_t *cost) {
  char local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];
  char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN], nat[INET6_ADDRSTRLEN];
  char wire[2][128], stack[2][128], inside[128], outside[128];
  char iface[FM_INTERFACE_SIZE * 6 + 1], orig[FM_INTERFACE_SIZE * 6 + 1];
  char label[FM_LABEL_SIZE * 6 + 1], protocol[16], translation[128];
  const struct orientation *pf = &v->pf;
  address_text(v->local, local); address_text(v->remote, remote);
  address_text(pf->initiator.a, src); address_text(pf->responder.a, dst);
  address_text(pf->untranslated.a, nat);
  for (unsigned n = 0; n < 2; n++) {
    endpoint_json(state->key[FM_WIRE_KEY].e[n], wire[n]);
    endpoint_json(state->key[FM_STACK_KEY].e[n], stack[n]);
  }
  endpoint_json(v->inside, inside); endpoint_json(v->remote_endpoint, outside);
  escape(state->interface, FM_INTERFACE_SIZE, iface);
  escape(state->original_interface, FM_INTERFACE_SIZE, orig);
  escape(state->label, FM_LABEL_SIZE, label);
  const char *name = pf->proto == 6 ? "tcp" :
                     pf->proto == 17 ? "udp" :
                     pf->proto == 1 ? "icmp" :
                     pf->proto == 58 ? "ipv6-icmp" :
                     pf->proto == 132 ? "sctp" : NULL;
  if (name) snprintf(protocol, sizeof(protocol), "%s", name);
  else snprintf(protocol, sizeof(protocol), "%u", pf->proto);
  if (!pf->translated) strcpy(translation, "null");
  else snprintf(translation, sizeof(translation), "\"%s%s%s:%u\"",
                pf->untranslated.a.af == 6 ? "[" : "", nat,
                pf->untranslated.a.af == 6 ? "]" : "", pf->untranslated.port);
  bool remote_initiated = v->remote_initiated;
  /* "byte_counters"/"packets" are PF's raw [forward, reverse] counters;
   * the from_remote/to_remote fields are the same traffic oriented by
   * the PF initiator. "remote_started" keeps its historical meaning (the
   * apparent-initiator heuristic). */
  int length = snprintf(out, FM_FRAME_MAX,
      "{\"flow\":{\"origin\":\"%s\",\"dest\":\"%s\"},"
      "\"id\":\"%016" PRIx64 "\",\"creatorid\":\"%08" PRIx32 "\","
      "\"protocol\":%u,\"proto\":\"%s\",\"direction\":%u,"
      "\"interface\":\"%s\",\"original_interface\":\"%s\","
      "\"wire\":[%s,%s],\"stack\":[%s,%s],"
      "\"src_addr\":\"%s\",\"src_port\":%u,\"dst_addr\":\"%s\",\"dst_port\":%u,"
      "\"nat\":%s,\"inside\":%s,\"outside\":%s,\"remote_started\":%s,"
      "\"remote_initiated\":%s,"
      "\"packets\":[%" PRIu64 ",%" PRIu64 "],\"byte_counters\":[%" PRIu64 ",%" PRIu64 "],"
      "\"bytes\":%" PRIu64 ",\"bytes_from_remote\":%" PRIu64 ",\"bytes_to_remote\":%" PRIu64 ","
      "\"packets_from_remote\":%" PRIu64 ",\"packets_to_remote\":%" PRIu64 ","
      "\"peer_states\":[%u,%u],"
      "\"age\":%u,\"expire\":%u,\"rule_number\":%u,\"rule_label\":\"%s\"}",
      local, remote, state->id, state->creator, pf->proto, protocol, state->pf_direction,
      iface, orig, wire[0], wire[1], stack[0], stack[1], src, pf->initiator.port, dst,
      pf->responder.port, translation, v->has_inside ? inside : "null", outside,
      v->apparent_remote_initiated ? "true" : "false", remote_initiated ? "true" : "false",
      state->pf_packets[FM_PF_FORWARD], state->pf_packets[FM_PF_REVERSE],
      state->pf_bytes[FM_PF_FORWARD], state->pf_bytes[FM_PF_REVERSE],
      state->pf_bytes[FM_PF_FORWARD] + state->pf_bytes[FM_PF_REVERSE],
      state_bytes_from_remote(state, remote_initiated),
      state_bytes_to_remote(state, remote_initiated),
      state_packets_from_remote(state, remote_initiated),
      state_packets_to_remote(state, remote_initiated),
      state->peer[0], state->peer[1], state->age, state->expire, state->rule, label);
  if (length < 0 || length >= FM_FRAME_MAX - 5) return 0;
  /* Includes conservative states[remote] wrapper/comma overhead. */
  *cost = (size_t)length + strlen(remote) + 8;
  /* ensure_ascii Python document encoding can expand non-ASCII UTF-8 labels.
   * Six bytes per input byte is a conservative upper bound. */
  for (int n = 0; n < length; n++)
    if ((unsigned char)out[n] >= 128) *cost += 5;
  return (size_t)length;
}

static bool add_total(uint64_t *total, uint64_t value) {
  if (UINT64_MAX - *total < value) return false;
  *total += value;
  return true;
}
bool snapshot_add(const struct state *state, void *arg, struct fm_error *error) {
  struct snapshot *s = arg;
  s->traversed++;
  struct state_view v;
  if (!state_normalize(state, s->ctx, &v, error)) return false;
  if (!v.mapped) return true;
  unsigned char key[FM_FLOW_KEY_SIZE];
  state_flow_key(key, v.local, v.remote);
  const struct item *i = map_find(&s->selected, key, sizeof(key));
  if (!i) return true;
  s->observed++;
  struct flow_totals *totals = &s->totals[i->value];
  bool remote = v.remote_initiated;
  if (!add_total(&totals->matched, 1) ||
      !add_total(&totals->bytes_from_remote, state_bytes_from_remote(state, remote)) ||
      !add_total(&totals->bytes_to_remote, state_bytes_to_remote(state, remote)) ||
      !add_total(&totals->packets_from_remote, state_packets_from_remote(state, remote)) ||
      !add_total(&totals->packets_to_remote, state_packets_to_remote(state, remote)))
    return fm_error_set(error, EOVERFLOW, "snapshot flow totals");
  char json[FM_FRAME_MAX];
  size_t cost = 0, length = row_json(state, &v, json, &cost);
  if (!length) return fm_error_fail(error, FM_FAILURE_INTERNAL, EOVERFLOW, "snapshot record size");
  bool incident = s->flows[i->value].incident;
  while (incident && s->ordinary.last &&
         (cost > s->byte_limit - s->bytes || s->included >= s->state_limit)) {
    unsigned reason = cost > s->byte_limit - s->bytes ? SNAPSHOT_OMITTED_BYTES
                                                      : SNAPSHOT_OMITTED_STATES;
    s->reasons |= reason;
    drop_last(s, reason);
  }
  if (cost > s->byte_limit - s->bytes || s->included >= s->state_limit) {
    if (incident)
      return fm_error_set(error, EOVERFLOW, "required incident PF evidence exceeds snapshot safety ceiling");
    unsigned reason = cost > s->byte_limit - s->bytes ? SNAPSHOT_OMITTED_BYTES
                                                      : SNAPSHOT_OMITTED_STATES;
    s->reasons |= reason;
    totals->reasons |= reason;
    return true;
  }
  struct detail_row *row = fm_malloc(sizeof(*row) + length);
  if (!row) return fm_error_set(error, errno, "snapshot row allocation");
  row->cost = cost; row->length = length; row->flow = (uint32_t)i->value;
  memcpy(row->json, json, length);
  append(incident ? &s->incident : &s->ordinary, row);
  s->bytes += cost;
  s->included++;
  totals->captured++;
  return true;
}

bool snapshot_write(struct snapshot *s, FILE *out, struct fm_error *error) {
  if (fwrite("FMSTATE2", 1, 8, out) != 8)
    return fm_error_set(error, EIO, "snapshot header");
  uint32_t crc = 0;
  unsigned char frame[FM_FRAME_MAX], *p = frame;
  *p++ = 0; protocol_put(&p, 2, 4); protocol_put(&p, s->generation, 8);
  if (!protocol_frame(out, frame, p - frame, &crc, error)) return false;
  struct row_list *lists[] = {&s->incident, &s->ordinary};
  for (unsigned n = 0; n < 2; n++)
    for (struct detail_row *row = lists[n]->first; row; row = row->next) {
      p = frame; *p++ = 1; protocol_put(&p, row->flow, 4);
      memcpy(p, row->json, row->length); p += row->length;
      if (!protocol_frame(out, frame, p - frame, &crc, error)) return false;
    }
  for (size_t n = 0; n < s->count; n++) {
    const struct flow_totals *t = &s->totals[n];
    p = frame; *p++ = 2; protocol_put(&p, n, 4);
    protocol_put(&p, t->matched, 8); protocol_put(&p, t->captured, 8);
    protocol_put(&p, t->bytes_from_remote, 8); protocol_put(&p, t->bytes_to_remote, 8);
    protocol_put(&p, t->packets_from_remote, 8); protocol_put(&p, t->packets_to_remote, 8);
    *p++ = (unsigned char)t->reasons;
    if (!protocol_frame(out, frame, p - frame, &crc, error)) return false;
  }
  p = frame; *p++ = 255;
  protocol_put(&p, s->traversed, 8); protocol_put(&p, s->observed, 8);
  protocol_put(&p, s->included, 8); protocol_put(&p, s->bytes, 8);
  protocol_put(&p, s->reasons, 4); protocol_put(&p, SNAPSHOT_POLICY_ARRIVAL, 4);
  protocol_put(&p, 0, 8); /* skipped states: none are skipped yet */
  protocol_put(&p, crc, 4);
  double times[] = {s->sample_time, s->started, wall_time()};
  for (unsigned n = 0; n < 3; n++) {
    uint64_t bits; memcpy(&bits, &times[n], 8); protocol_put(&p, bits, 8);
  }
  return protocol_frame(out, frame, p - frame, NULL, error) &&
         (fflush(out) == 0 || fm_error_set(error, errno, "snapshot flush"));
}

/* Commands use bounded lines/row counts; no unbounded getline allocation. */
static bool line_read(FILE *in, char line[256], struct fm_error *error) {
  if (!fgets(line, 256, in) || !strchr(line, '\n'))
    return fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "incomplete snapshot request");
  return true;
}
static bool parse_addr(const char *text, struct addr *a) {
  memset(a, 0, sizeof(*a)); a->af = strchr(text, ':') ? 6 : 4;
  return inet_pton(a->af == 4 ? AF_INET : AF_INET6, text, a->b) == 1;
}
static bool identities(FILE *in, struct snapshot_flow *flows, size_t count,
                       struct fm_error *error) {
  char line[256], a[64], b[64], extra;
  unsigned incident;
  for (size_t n = 0; n < count; n++) {
    if (!line_read(in, line, error)) return false;
    if (sscanf(line, "F %63s %63s %u %c", a, b, &incident, &extra) != 3 ||
        incident > 1 || !parse_addr(a, &flows[n].local) || !parse_addr(b, &flows[n].remote))
      return fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "snapshot flow row");
    flows[n].incident = incident;
  }
  return line_read(in, line, error) && (!strcmp(line, "RUN\n") ||
         fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "snapshot request terminator"));
}
static bool page_write(FILE *out, const struct aggregate *a, const struct ranking *r,
                       size_t start, uint64_t generation, struct fm_error *error) {
  size_t active = aggregate_counts(a).flows;
  if (start > active) return fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "snapshot page offset");
  size_t count = active - start < 150 ? active - start : 150;
  if (fwrite("FMPAGE1\0", 1, 8, out) != 8) return fm_error_set(error, EIO, "snapshot page header");
  unsigned char b[128], *p = b; uint32_t crc = 0;
  *p++ = 0; protocol_put(&p, 1, 4); protocol_put(&p, generation, 8);
  protocol_put(&p, active, 8); protocol_put(&p, start, 8); protocol_put(&p, count, 4);
  if (!protocol_frame(out, b, p - b, &crc, error)) return false;
  for (size_t n = 0; n < count; n++) {
    struct ranked_flow row;
    uint64_t order;
    if (!ranking_snapshot_at(r, a, start + n, &row, &order))
      return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "snapshot rank");
    const struct flow *flow = aggregate_flow(a, row.flow);
    p = b; *p++ = 1; protocol_address_put(&p, flow->local); protocol_address_put(&p, flow->remote);
    uint64_t bits; memcpy(&bits, &row.score, 8); protocol_put(&p, bits, 8);
    protocol_put(&p, order, 8);
    if (!protocol_frame(out, b, p - b, &crc, error)) return false;
  }
  p = b; *p++ = 255; protocol_put(&p, crc, 4);
  return protocol_frame(out, b, p - b, NULL, error) &&
         (fflush(out) == 0 || fm_error_set(error, errno, "snapshot page flush"));
}
static bool select_rows(const struct aggregate *a, const struct ranking *r,
                        const struct snapshot_flow *flows, size_t count,
                        struct ranked_flow *rows, struct fm_error *error) {
  struct map selected = {0}; bool ok = false;
  for (size_t n = 0; n < count; n++) {
    unsigned char key[FM_FLOW_KEY_SIZE]; state_flow_key(key, flows[n].local, flows[n].remote);
    struct item *i = lookup(&selected, key, sizeof(key), true, error);
    if (!i || i->count) {
      if (i) fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "duplicate snapshot selection");
      goto done;
    }
    i->count = 1; i->value = n;
  }
  size_t found = 0;
  for (size_t n = 0; n < aggregate_counts(a).flows; n++) {
    struct ranked_flow row;
    uint64_t order;
    if (!ranking_snapshot_at(r, a, n, &row, &order)) {
      fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "snapshot rank lookup");
      goto done;
    }
    const struct flow *flow = aggregate_flow(a, row.flow);
    unsigned char key[FM_FLOW_KEY_SIZE]; state_flow_key(key, flow->local, flow->remote);
    const struct item *i = map_find(&selected, key, sizeof(key));
    if (i) { rows[i->value] = row; found++; }
  }
  ok = found == count ||
       fm_error_fail(error, FM_FAILURE_REQUEST, EINVAL, "snapshot selection not in sample");
done:
  map_clear(&selected); return ok;
}

/* Each command's answer is rendered completely before any byte reaches the
 * collector: a failed command leaves the stream clean for FMFAIL1. */
enum command { COMMAND_PAGE, COMMAND_SELECT, COMMAND_DETAIL };
struct command_args {
  const struct context *ctx;
  const struct aggregate *a;
  const struct ranking *r;
  uint64_t generation;
  double sample_time;
  const struct telemetry *telemetry;
  struct snapshot_flow *flows;
  struct ranked_flow *rows;
  size_t count, bytes, states, offset;
};
static bool render(enum command command, const struct command_args *c, FILE *out,
                   struct fm_error *error) {
  switch (command) {
  case COMMAND_PAGE:
    return page_write(out, c->a, c->r, c->offset, c->generation, error);
  case COMMAND_SELECT:
    return protocol_write_selected(out, c->a, c->rows, c->count, c->telemetry, error);
  case COMMAND_DETAIL: {
    struct snapshot *s = snapshot_create(c->ctx, c->flows, c->count, c->bytes, c->states,
                                         c->generation, c->sample_time, error);
    if (!s) return false;
    bool ok = pf_reader_live(snapshot_add, s, NULL, NULL, error) && snapshot_write(s, out, error);
    snapshot_destroy(s);
    return ok;
  }
  }
  return fm_error_fail(error, FM_FAILURE_INTERNAL, EINVAL, "snapshot command");
}
static bool respond(enum command command, const struct command_args *c, FILE *out,
                    struct fm_error *error) {
  struct response response;
  if (!response_begin(&response, error)) return false;
  if (!render(command, c, response.stream, error)) {
    response_discard(&response);
    return false;
  }
  return response_commit(&response, out, error);
}

bool snapshot_session(FILE *in, FILE *out, const struct context *ctx,
                      const struct aggregate *a, const struct ranking *r,
                      uint64_t generation, double sample_time,
                      const struct telemetry *telemetry, struct fm_error *error) {
  char line[256], extra;
  bool ok = false;
  /* Heap, not stack: two 5000-row arrays. */
  struct command_args c = {.ctx = ctx, .a = a, .r = r, .generation = generation,
                           .sample_time = sample_time, .telemetry = telemetry,
                           .flows = fm_calloc(FM_SNAPSHOT_FLOWS, sizeof(*c.flows)),
                           .rows = fm_calloc(FM_SNAPSHOT_FLOWS, sizeof(*c.rows))};
  uint64_t requested;
  if (!c.flows || !c.rows) {
    fm_error_set(error, errno, "snapshot session allocation");
    goto done;
  }
  for (;;) {
    if (!line_read(in, line, error)) goto done;
    if (!strcmp(line, "FMSNAP1 CANCEL\n")) { ok = true; goto done; }
    if (sscanf(line, "FMSNAP1 PAGE %zu %c", &c.offset, &extra) == 1) {
      if (!respond(COMMAND_PAGE, &c, out, error)) goto done;
    } else if (sscanf(line, "FMSNAP1 SELECT %" SCNu64 " %zu %c", &requested, &c.count, &extra) == 2) {
      if (requested != generation || c.count > FM_SNAPSHOT_FLOWS) {
        fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "snapshot selection generation or count");
        goto done;
      }
      if (!identities(in, c.flows, c.count, error) ||
          !select_rows(a, r, c.flows, c.count, c.rows, error) ||
          !respond(COMMAND_SELECT, &c, out, error)) goto done;
    } else if (sscanf(line, "FMSNAP1 DETAIL %" SCNu64 " %zu %zu %zu %c",
                      &requested, &c.bytes, &c.states, &c.count, &extra) == 4) {
      if (requested != generation || c.count > FM_SNAPSHOT_FLOWS) {
        fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "snapshot detail generation or count");
        goto done;
      }
      ok = identities(in, c.flows, c.count, error) &&
           select_rows(a, r, c.flows, c.count, c.rows, error) &&
           respond(COMMAND_DETAIL, &c, out, error);
      goto done;
    } else {
      fm_error_fail(error, FM_FAILURE_REQUEST, EPROTO, "snapshot command/version");
      goto done;
    }
  }
done:
  fm_free(c.flows);
  fm_free(c.rows);
  return ok;
}
