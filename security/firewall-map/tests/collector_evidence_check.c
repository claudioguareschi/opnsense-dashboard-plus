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


/* Exhaustive check of collector/evidence.h: which facts a request may send,
 * and the security class every combination derives (the one place the
 * S0-S3 policy lives). Built and run by tests/test_collector_evidence.py;
 * prints "ok" or the first violation. */
#include "../collector/evidence.h"
#include <stdio.h>

static int expect(const char *what, bool ok) {
  if (!ok) printf("%s\n", what);
  return !ok;
}

int main(void) {
  static const uint32_t counts[] = {0, 1, 29, 30, 31, EVIDENCE_COUNT_MAX, EVIDENCE_COUNT_MAX + 1};
  int failed = 0;
  for (unsigned mask = 0; mask < 32; mask++)
    for (unsigned severity = 0; severity <= 4; severity++)
      for (unsigned b = 0; b < sizeof(counts) / sizeof(*counts); b++)
        for (unsigned i = 0; i < sizeof(counts) / sizeof(*counts); i++) {
          struct evidence e = {(uint8_t)mask, (uint8_t)severity, counts[b], counts[i]};
          bool ids = mask & EVIDENCE_IDS, high = mask & EVIDENCE_IDS_HIGH,
               blocked = mask & EVIDENCE_PF_BLOCKED;
          bool consistent = !(mask & EVIDENCE_THREAT_LIST) && counts[b] <= EVIDENCE_COUNT_MAX &&
                            counts[i] <= EVIDENCE_COUNT_MAX && ids == (counts[i] > 0 && severity >= 1 && severity <= 3) &&
                            (ids || !severity) && high == (ids && severity <= 2) && blocked == (counts[b] > 0);
          char what[128];
          snprintf(what, sizeof(what), "valid mask %u severity %u blocked %u alerts %u", mask, severity,
                   counts[b], counts[i]);
          failed |= expect(what, evidence_valid(&e) == consistent);
          /* the class of every combination, valid or not (the derivation never
           * depends on validity), with THREAT_LIST included */
          for (unsigned list = 0; list < 2; list++) {
            e.mask = (uint8_t)(mask | (list ? EVIDENCE_THREAT_LIST : 0));
            enum security_class want =
                (e.mask & EVIDENCE_IDS_HIGH) ? SECURITY_S3
                : (e.mask & EVIDENCE_IDS) || ((e.mask & EVIDENCE_PF_BLOCKED) && counts[b] >= 30) ? SECURITY_S2
                : e.mask ? SECURITY_S1 : SECURITY_S0;
            snprintf(what, sizeof(what), "class mask %u blocked %u", e.mask, counts[b]);
            failed |= expect(what, security_class(&e) == want);
            /* any evidence exactly when the class is above S0 */
            failed |= expect("class above S0 exactly with evidence", (security_class(&e) != SECURITY_S0) == (e.mask != 0));
            /* the class leaves the facts alone */
            failed |= expect("class changed facts", e.mask == (uint8_t)(mask | (list ? EVIDENCE_THREAT_LIST : 0)));
          }
        }
  if (!failed) printf("ok\n");
  return failed;
}
