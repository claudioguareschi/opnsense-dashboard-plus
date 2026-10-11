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

/* libFuzzer target: arbitrary PF states through the whole engine (state
 * normalization, history, aggregation, ranking, threat summary, correlation
 * and the FMAGG5 writer) with a fixed realistic context. Portable: needs no
 * FreeBSD headers. The netlink decoder itself is fuzz_netlink.c (FreeBSD).
 * Input: a sequence of sizeof(struct state) records, each copied into a state
 * (strings forced NUL-terminated, as the decoder guarantees); every 64
 * states one sample is committed. Build and run with devel/fuzz/run.sh. */
#include "../../collector/aggregate.h"
#include "../../collector/alloc.h"
#include "../../collector/budget.h"
#include "../../collector/event_correlation.h"
#include "../../collector/history.h"
#include "../../collector/protocol.h"
#include "../../collector/ranking.h"
#include "../../collector/threat_summary.h"
#include "../balanced_profile.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define RECORD sizeof(struct state)

static struct addr parse(const char *text) {
  struct addr a = {.af = strchr(text, ':') ? 6 : 4};
  inet_pton(a.af == 4 ? AF_INET : AF_INET6, text, a.b);
  return a;
}
static struct context *context(void) {
  struct fm_error error = {0};
  struct context *ctx = context_create(&error);
  const struct range ranges[] = {
      {parse("0.0.0.0"), parse("9.255.255.255"), FM_PUBLIC},
      {parse("10.0.0.0"), parse("10.255.255.255"), FM_PRIVATE},
      {parse("11.0.0.0"), parse("255.255.255.255"), FM_PUBLIC},
      {parse("::"), parse("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), FM_PUBLIC},
      {parse("fc00::"), parse("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), FM_PRIVATE}};
  for (size_t n = 0; n < sizeof(ranges) / sizeof(*ranges); n++)
    context_add_range(ctx, ranges[n], &error);
  context_add_local(ctx, parse("45.33.32.10"), &error);
  context_add_local(ctx, parse("2001:470::2"), &error);
  struct net lan = {parse("10.0.0.0"), 24, "lan0"}, wan = {parse("45.33.32.0"), 24, "wan0"};
  context_add_net(ctx, lan, &error);
  context_add_net(ctx, wan, &error);
  struct assigned assigned = {parse("45.33.32.10"), "wan0"};
  context_add_assigned(ctx, assigned, &error);
  strcpy(ctx->wan, "wan0");
  context_add_service(ctx, (struct service){6, 443, 2}, &error);
  if (!context_prepare(ctx, &error)) abort();
  return ctx;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static struct context *ctx;
  static struct classifier *classes;
  static uint64_t context_blocks;
  static struct profile profile; /* kept, like the context */
  if (!ctx) {
    struct fm_error error = {0};
    ctx = context();
    /* half of each address family is threat-listed, the other half a country: both summary
     * classes and every mask path are reached */
    struct class_set sets[2] = {{0, 'T', "threat", CLASS_OK, 0}, {1, 'C', "country", CLASS_OK, 0}};
    struct class_entry threat[2] = {{{4, {0}}, 1, false}, {{6, {0}}, 1, false}};
    struct class_entry country[2] = {{{4, {128}}, 1, false}, {{6, {128}}, 1, false}};
    const struct class_entry *entries[2] = {threat, country};
    size_t counts[2] = {2, 2};
    classes = classifier_build(sets, 2, entries, counts, &error);
    if (!fm_balanced_profile(&profile)) abort();
    context_blocks = fm_heap_usage().blocks;
  }
  struct fm_error error = {0};
  struct history *history = history_create(&error);
  struct ranking *ranking = ranking_create(20.0, 0.5, &error);
  struct ranker *ranker = ranker_create(&error);
  if (ranker) ranker_configure(ranker, &profile);
  struct event_history *events = event_history_create(&error);
  double anchor = 1;
  for (size_t offset = 0; offset < size && !error.code;) {
    if (!history_begin(history, anchor, &error)) break;
    struct event_sample *stream = event_sample_begin(events, NULL, 0, &error);
    struct aggregate *aggregate =
        stream ? aggregate_create(ctx, history, event_sample_observe, stream, &error) : NULL;
    bool ok = aggregate != NULL;
    if (ok) aggregate_set_classifier(aggregate, classes);
    for (unsigned n = 0; ok && n < 64 && offset + RECORD <= size; n++, offset += RECORD) {
      struct state s;
      memcpy(&s, data + offset, RECORD);
      s.interface[FM_INTERFACE_SIZE - 1] = s.original_interface[FM_INTERFACE_SIZE - 1] = 0;
      s.label[FM_LABEL_SIZE - 1] = 0;
      for (unsigned k = 0; k < 2; k++)
        for (unsigned e = 0; e < 2; e++)
          s.key[k].e[e].a.af = s.key[k].e[e].a.af & 1 ? 6 : 4; /* the decoder emits only 4 or 6 */
      ok = aggregate_add(aggregate, &s, &error);
      if (!ok) { memset(&error, 0, sizeof(error)); ok = true; } /* a rejected state ends nothing here */
    }
    if (offset + RECORD > size) offset = size;
    ok = ok && aggregate_finish(aggregate, &error) &&
         ranking_update(ranking, aggregate, anchor, history_interval(history), &error) &&
         ranker_select(ranker, aggregate, ranking, history_interval(history), BUDGET_RANKED_FLOWS_DEFAULT, &error);
    struct threat_limits limits = {NULL, 0, 100, 4, classifier_category(classes, 'T')};
    struct threat_summary *threats = ok ? threat_summary_create(aggregate, limits, &error) : NULL;
    ok = ok && threats;
    if (ok) {
      event_sample_finish(events, stream, anchor, NULL, 0, &error);
      ok = !error.code;
    }
    event_sample_destroy(stream);
    if (ok) {
      char *buffer = NULL;
      size_t length = 0;
      FILE *out = open_memstream(&buffer, &length);
      struct telemetry telemetry = {0};
      if (out) {
        struct class_report report = {classes, NULL, 0, aggregate, NULL, NULL, classifier_category(classes, 'T')};
        struct ranked_flow rows[BUDGET_RANKED_FLOWS_DEFAULT];
        size_t count = fm_selection_rows(ranker, ranking, aggregate, rows);
        struct ranked_output ranked = {rows, count, NULL, 0, ranking, ranker};
        protocol_write_ranked(out, aggregate, &ranked, threats, NULL, 0, &report, 4, &telemetry, &error);
        fclose(out);
      }
      free(buffer);
    }
    threat_summary_destroy(threats);
    aggregate_destroy(aggregate);
    if (ok) history_commit(history); else history_abort(history);
    memset(&error, 0, sizeof(error));
    anchor += 2;
  }
  history_destroy(history);
  ranking_destroy(ranking);
  ranker_destroy(ranker);
  event_history_destroy(events);
  if (fm_heap_usage().blocks != context_blocks) abort(); /* every engine allocation was released */
  return 0;
}
