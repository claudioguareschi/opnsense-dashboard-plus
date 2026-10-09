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

/* Screening of PF states at the normalization boundary, before any Firewall
 * Map processing: a state whose reported lifetime is impossible is skipped
 * and counted; an age the kernel cannot have measured is marked unknown.
 *
 * PF netlink (pf_nl.c dump_state) reports, as u32 seconds:
 *   CREATION = time_uptime - creation/1000, the state's age;
 *   EXPIRE   = pf_state_expires() - time_uptime while the state is live, or
 *              the absolute pf_state_expires() (<= time_uptime) once it has
 *              expired and awaits the purge (PFTM_PURGE reports time_uptime).
 * A live state's remaining time is at most the timeout that applies to it:
 * its rule's value for its timeout index, else the default; adaptive scaling
 * only shortens it. So a legitimate EXPIRE never exceeds
 * max(largest applicable timeout, uptime); a larger one is impossible. */
#ifndef FM_LIFETIME_H
#define FM_LIFETIME_H
#include "state.h"
#include <stdbool.h>
#include <stdint.h>

/* A state's age the kernel could not have measured (wire and API: unknown,
 * never 0, which means a new state). */
#define FM_AGE_UNKNOWN UINT32_MAX
/* PF's timeout table size (pf.h PFTM_MAX). */
#define LIFETIME_TIMEOUTS 25

/* Whether timeout index i can time a state: the protocol timeouts (TCP, UDP,
 * ICMP, other: 0-13; SCTP: 20-24). Fragment, purge interval, adaptive start
 * and end (state counts), source node and timestamp difference never do. */
bool lifetime_index_applies(unsigned index);
/* The largest applying value of one timeout table, in seconds. */
uint64_t lifetime_table_max(const uint32_t timeouts[LIFETIME_TIMEOUTS]);

/* The largest timeout any state can have: the default table and every loaded
 * filter rule's table (a rule's 0 means the default). Unavailable when it
 * could not be established: then nothing is rejected (fail open). */
struct lifetime_bound {
  bool available;
  uint64_t timeout_max; /* seconds */
  int error;            /* why it is unavailable (errno) */
};

/* The rule itself: an EXPIRE (u32 seconds, as reported) is possible when it
 * is at most max(timeout_max, uptime) (seconds since boot, as time_uptime). */
bool lifetime_expire_valid(uint64_t timeout_max, uint32_t expire, uint64_t uptime);
/* An age (CREATION) the kernel can have measured: at most the uptime. */
bool lifetime_age_known(uint32_t age, uint64_t uptime);

/* System uptime in whole seconds, the base of PF's time_uptime (FreeBSD:
 * CLOCK_UPTIME, from the same nanouptime as time_uptime = th_offset.sec, so a
 * reading taken after a state was reported is >= the uptime it was reported
 * at). Test builds may fix it with FM_TEST_UPTIME=<seconds>. */
uint64_t lifetime_uptime(void);

/* One dump's screen. The uptime is read at the start and again, lazily, only
 * for a state above the current limit, so the check stays one comparison. */
struct lifetime_screen {
  struct lifetime_bound bound;
  uint64_t uptime, limit;
  uint64_t observed, invalid, age_unknown;
};
void lifetime_screen_begin(struct lifetime_screen *, struct lifetime_bound);
/* The state to process: s itself, scratch (a copy whose age is
 * FM_AGE_UNKNOWN) when its age is impossible, or NULL when its lifetime is
 * impossible (skipped). Every call counts as one observed PF record. */
const struct state *lifetime_screen_state(struct lifetime_screen *, const struct state *s,
                                          struct state *scratch);
#endif
