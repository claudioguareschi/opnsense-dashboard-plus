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


#ifndef FM_EVIDENCE_H
#define FM_EVIDENCE_H
#include <stdbool.h>
#include <stdint.h>

/* Security evidence of a flow's remote (CONTRACTS.md, "Evidence"). Each
 * source is its own fact; a flow may have several, and none is ever folded
 * into another. Python collects the bounded evidence (filterlog, Suricata,
 * AbuseIPDB verdicts) and sends it with EVIDENCE rows; THREAT_LIST is
 * derived here from the PF-table set mask, which is kept separately. */
enum evidence_bit {
  EVIDENCE_THREAT_LIST = 1, /* the remote is in a threat-category PF table */
  EVIDENCE_PF_BLOCKED = 2,  /* PF logged blocked attempts from it (filterlog window) */
  EVIDENCE_IDS = 4,         /* Suricata alerts involve it (alert window) */
  EVIDENCE_IDS_HIGH = 8,    /* one of them has severity 1 or 2 */
  EVIDENCE_REPUTATION = 16, /* an AbuseIPDB lookup scored it abusive */
};
/* The bits a request may set (THREAT_LIST is the collector's own). */
#define EVIDENCE_REQUEST_BITS \
  (EVIDENCE_PF_BLOCKED | EVIDENCE_IDS | EVIDENCE_IDS_HIGH | EVIDENCE_REPUTATION)
/* Counts are Python's bounded window counts, capped here. */
#define EVIDENCE_COUNT_MAX 1000000u
/* Suricata severities 1 (highest) to 3; IDS_HIGH is a worst severity at or
 * below this (the map's long-standing "severity 1-2 flags" rule). */
#define EVIDENCE_IDS_HIGH_SEVERITY 2
struct evidence {
  uint8_t mask;          /* enum evidence_bit */
  uint8_t ids_severity;  /* worst (lowest) Suricata severity, 1-3; 0 without IDS */
  uint32_t blocked_hits; /* logged blocked attempts in the filterlog window */
  uint32_t ids_alerts;   /* Suricata alerts in the alert window */
};
/* A request's facts are consistent: IDS exactly when there are alerts and a
 * severity, IDS_HIGH exactly when that severity is high, PF_BLOCKED exactly
 * when there are hits, counts within the cap. */
static inline bool evidence_valid(const struct evidence *e) {
  bool ids = e->mask & EVIDENCE_IDS, high = e->mask & EVIDENCE_IDS_HIGH;
  return !(e->mask & ~EVIDENCE_REQUEST_BITS) && e->blocked_hits <= EVIDENCE_COUNT_MAX &&
         e->ids_alerts <= EVIDENCE_COUNT_MAX &&
         ids == (e->ids_alerts > 0 && e->ids_severity >= 1 && e->ids_severity <= 3) &&
         (ids || !e->ids_severity) && high == (ids && e->ids_severity <= EVIDENCE_IDS_HIGH_SEVERITY) &&
         ((e->mask & EVIDENCE_PF_BLOCKED) != 0) == (e->blocked_hits > 0);
}

/* The security class, derived (never stored as evidence) for reservations:
 *   S3  high-severity IDS evidence
 *   S2  other IDS evidence, or strong blocked activity (at least
 *       SECURITY_BLOCKED_STRONG_HITS logged blocks in the window)
 *   S1  any other evidence: threat list, reputation, weaker blocked activity
 *   S0  no evidence
 * so a flow has a class above S0 exactly when it has any evidence. The one
 * place this policy lives (tests/collector_evidence: Phase G may tune it). */
#define SECURITY_BLOCKED_STRONG_HITS 30u
enum security_class { SECURITY_S0 = 0, SECURITY_S1 = 1, SECURITY_S2 = 2, SECURITY_S3 = 3 };
static inline enum security_class security_class(const struct evidence *e) {
  if (e->mask & EVIDENCE_IDS_HIGH) return SECURITY_S3;
  if ((e->mask & EVIDENCE_IDS) ||
      ((e->mask & EVIDENCE_PF_BLOCKED) && e->blocked_hits >= SECURITY_BLOCKED_STRONG_HITS))
    return SECURITY_S2;
  return e->mask ? SECURITY_S1 : SECURITY_S0;
}
#endif
