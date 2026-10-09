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


/* Checks of collector/profile.c: schema-v1 validation (every rejection the
 * contract names), longest-prefix asset lookup over IPv4 and IPv6, discovery
 * units, ceiling-rounded floor places and effective estimates. Built and run
 * by tests/test_collector_profile.py with the example file as argv[1] and
 * the built-in profiles Python writes after it; prints "ok" or every
 * violation. */
#include "../collector/profile.h"
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int failed;
static void expect(const char *what, bool ok) {
  if (!ok) {
    printf("%s\n", what);
    failed = 1;
  }
}
static struct addr address(const char *text) {
  struct addr a = {0};
  a.af = strchr(text, ':') ? 6 : 4;
  inet_pton(a.af == 4 ? AF_INET : AF_INET6, text, a.b);
  return a;
}
#define WEIGHTS                                                                                     \
  "\"weights\":{\"byte_rate\":30,\"packet_rate\":10,\"active_states\":15,\"new_state_rate\":20,"     \
  "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5}"
#define ASSETS "\"asset_importance\":{\"default_multiplier\":1,\"rules\":[]}"
#define FLOORS "\"security_visibility\":{\"s3_min_percent\":10,\"s2_min_percent\":5,\"s1_min_percent\":2}"
#define UUID "\"uuid\":\"6f36c7b2-70ad-4c41-a32d-4cb1e3fb1a01\",\"name\":\"T\""
#define DOC(weights, assets, floors, direction)                                                      \
  "{\"schema_version\":1,\"profile\":{" UUID "," weights "," assets "," floors ",\"direction\":" direction "}}"

static void rejects(const char *what, const char *text) {
  struct profile p;
  char why[256] = "";
  bool ok = profile_compile(text, strlen(text), &p, why, sizeof(why));
  char line[512];
  snprintf(line, sizeof(line), "accepted: %s", what);
  expect(line, !ok && why[0]);
  if (ok) profile_release(&p);
}
static bool accepts(const char *text, struct profile *p) {
  char why[256] = "";
  bool ok = profile_compile(text, strlen(text), p, why, sizeof(why));
  if (!ok) printf("rejected: %s\n", why);
  return ok;
}

int main(int argc, char **argv) {
  struct profile p;
  char why[256];
  /* the contract's example file */
  expect("example file", argc > 1 && profile_load(argv[1], &p, why, sizeof(why)));
  if (failed) return printf("%s\n", why), 1;
  expect("uuid", !strcmp(p.uuid, "6f36c7b2-70ad-4c41-a32d-4cb1e3fb1a01"));
  expect("weights", p.weight[FEATURE_BYTE_RATE] == 30 && p.weight[FEATURE_IDS_EVIDENCE] == 5);
  expect("floors", p.floor_percent[SECURITY_S3] == 10 && p.floor_percent[SECURITY_S2] == 5 &&
                       p.floor_percent[SECURITY_S1] == 2);
  /* longest prefix wins, matches never multiply */
  expect("/32 inside /24", profile_asset(&p, address("192.168.70.5")) == 10.0);
  expect("/24", profile_asset(&p, address("192.168.70.4")) == 2.0);
  expect("/24 edge", profile_asset(&p, address("192.168.70.255")) == 2.0);
  expect("other /32", profile_asset(&p, address("192.168.1.2")) == 5.0);
  expect("default", profile_asset(&p, address("192.168.71.0")) == 1.0);
  expect("v6 default", profile_asset(&p, address("2001:db8::1")) == 1.0);
  /* ceiling-rounded percentage floors */
  expect("S3 150", profile_floor_places(&p, SECURITY_S3, 150) == 15);
  expect("S2 150", profile_floor_places(&p, SECURITY_S2, 150) == 8);
  expect("S1 150", profile_floor_places(&p, SECURITY_S1, 150) == 3);
  expect("S1 1", profile_floor_places(&p, SECURITY_S1, 1) == 1);
  expect("S0", profile_floor_places(&p, SECURITY_S0, 150) == 0);
  /* asset importance multiplies quality: quality 5 at 10x beats 20 at 1x */
  double values[FEATURE_COUNT] = {0};
  values[FEATURE_ACTIVE_STATES] = 10;
  double unit = profile_estimate(&p, values, 1.0);
  expect("estimate", fabs(unit - 15 * log1p(1.0)) < 1e-9);
  expect("multiplier", fabs(profile_estimate(&p, values, 10.0) - 10 * unit) < 1e-9);
  /* discovery units: relative to the smallest multiplier */
  expect("unit 1x", profile_unit(&p, 1.0) == PROFILE_DISCOVERY_UNIT);
  expect("unit 10x", profile_unit(&p, 10.0) == 10 * PROFILE_DISCOVERY_UNIT);
  expect("unit inverse", profile_unit_multiplier(&p, profile_unit(&p, 2.0)) == 2.0);
  profile_release(&p);

  /* IPv6 and nested rules */
  if (accepts(DOC(WEIGHTS,
                  "\"asset_importance\":{\"default_multiplier\":1.5,\"rules\":["
                  "{\"cidr\":\"2001:db8::/32\",\"multiplier\":3},{\"cidr\":\"2001:db8:1::/48\",\"multiplier\":7},"
                  "{\"cidr\":\"2001:db8:1::1/128\",\"multiplier\":9},{\"cidr\":\"0.0.0.0/0\",\"multiplier\":2},"
                  "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":4},{\"cidr\":\"10.0.0.0/8\",\"multiplier\":4}]}",
                  FLOORS, "\"equal\""),
              &p)) {
    expect("v6 /128", profile_asset(&p, address("2001:db8:1::1")) == 9);
    expect("v6 /48", profile_asset(&p, address("2001:db8:1::2")) == 7);
    expect("v6 /32", profile_asset(&p, address("2001:db8:2::")) == 3);
    expect("v6 none", profile_asset(&p, address("2001:db9::")) == 1.5);
    expect("v4 /0", profile_asset(&p, address("11.0.0.0")) == 2);
    expect("v4 /8", profile_asset(&p, address("10.255.255.255")) == 4);
    expect("duplicate kept once", p.asset_rules == 5);
    expect("min multiplier", p.min_multiplier == 1.5);
    profile_release(&p);
  } else failed = 1;
  /* precise floors and fractional weights */
  if (accepts(DOC("\"weights\":{\"byte_rate\":33.3,\"packet_rate\":33.3,\"active_states\":33.4,"
                  "\"new_state_rate\":0,\"flow_volume\":0,\"pf_blocked\":0,\"threat_intelligence\":0,\"ids_evidence\":0}",
                  ASSETS, "\"security_visibility\":{\"s3_min_percent\":0,\"s2_min_percent\":0,\"s1_min_percent\":0}",
                  "\"equal\""),
              &p)) {
    expect("zero floor", profile_floor_places(&p, SECURITY_S3, 150) == 0);
    profile_release(&p);
  } else failed = 1;

  /* rejections */
  rejects("not JSON", "{");
  rejects("trailing", DOC(WEIGHTS, ASSETS, FLOORS, "\"equal\"") " x");
  rejects("schema 2", "{\"schema_version\":2,\"profile\":{}}");
  rejects("no schema", "{\"profile\":{}}");
  rejects("unknown root key", "{\"schema_version\":1,\"profile\":{},\"x\":1}");
  rejects("unknown profile key", "{\"schema_version\":1,\"profile\":{" UUID "," WEIGHTS "," ASSETS "," FLOORS
                                 ",\"direction\":\"equal\",\"x\":1}}");
  rejects("bad uuid", "{\"schema_version\":1,\"profile\":{\"uuid\":\"Balanced\",\"name\":\"T\"," WEIGHTS "," ASSETS
                      "," FLOORS ",\"direction\":\"equal\"}}");
  rejects("uppercase uuid", "{\"schema_version\":1,\"profile\":{\"uuid\":\"6F36C7B2-70AD-4C41-A32D-4CB1E3FB1A01\","
                            "\"name\":\"T\"," WEIGHTS "," ASSETS "," FLOORS ",\"direction\":\"equal\"}}");
  rejects("empty name", "{\"schema_version\":1,\"profile\":{\"uuid\":\"6f36c7b2-70ad-4c41-a32d-4cb1e3fb1a01\","
                        "\"name\":\"\"," WEIGHTS "," ASSETS "," FLOORS ",\"direction\":\"equal\"}}");
  rejects("unknown feature",
          DOC("\"weights\":{\"byte_rate\":30,\"packet_rate\":10,\"active_states\":15,\"new_state_rate\":20,"
              "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5,\"reputation\":0}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("missing feature",
          DOC("\"weights\":{\"byte_rate\":35,\"packet_rate\":10,\"active_states\":15,\"new_state_rate\":20,"
              "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("duplicate feature",
          DOC("\"weights\":{\"byte_rate\":30,\"byte_rate\":30,\"packet_rate\":10,\"active_states\":15,"
              "\"new_state_rate\":20,\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("total 99",
          DOC("\"weights\":{\"byte_rate\":29,\"packet_rate\":10,\"active_states\":15,\"new_state_rate\":20,"
              "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("negative weight",
          DOC("\"weights\":{\"byte_rate\":40,\"packet_rate\":-10,\"active_states\":25,\"new_state_rate\":20,"
              "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("string weight",
          DOC("\"weights\":{\"byte_rate\":\"30\",\"packet_rate\":10,\"active_states\":15,\"new_state_rate\":20,"
              "\"flow_volume\":10,\"pf_blocked\":5,\"threat_intelligence\":5,\"ids_evidence\":5}",
              ASSETS, FLOORS, "\"equal\""));
  rejects("direction", DOC(WEIGHTS, ASSETS, FLOORS, "\"inbound\""));
  rejects("direction type", DOC(WEIGHTS, ASSETS, FLOORS, "1"));
  rejects("floor over 100", DOC(WEIGHTS, ASSETS,
                                "\"security_visibility\":{\"s3_min_percent\":101,\"s2_min_percent\":0,\"s1_min_percent\":0}",
                                "\"equal\""));
  rejects("floors total", DOC(WEIGHTS, ASSETS,
                              "\"security_visibility\":{\"s3_min_percent\":50,\"s2_min_percent\":40,\"s1_min_percent\":20}",
                              "\"equal\""));
  rejects("negative floor", DOC(WEIGHTS, ASSETS,
                                "\"security_visibility\":{\"s3_min_percent\":-1,\"s2_min_percent\":0,\"s1_min_percent\":0}",
                                "\"equal\""));
  rejects("missing floor", DOC(WEIGHTS, ASSETS,
                               "\"security_visibility\":{\"s3_min_percent\":1,\"s2_min_percent\":0}", "\"equal\""));
  static const char *const bad_rules[] = {
      "{\"cidr\":\"192.168.70.5/24\",\"multiplier\":2}",   /* host bits set */
      "{\"cidr\":\"192.168.70.0/33\",\"multiplier\":2}",   /* length */
      "{\"cidr\":\"192.168.70.0\",\"multiplier\":2}",      /* no length */
      "{\"cidr\":\"192.168.70.0/024\",\"multiplier\":2}",  /* leading zero */
      "{\"cidr\":\"192.168.700.0/24\",\"multiplier\":2}",  /* address */
      "{\"cidr\":\"host.example/32\",\"multiplier\":2}",   /* a name */
      "{\"cidr\":\"2001:db8::1/64\",\"multiplier\":2}",    /* v6 host bits */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":0}",        /* zero */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":-2}",       /* negative */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":1e7}",      /* over the limit */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":0.999999}", /* below 1: boost only */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":0.5}",      /* a suppression */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":100.000001}", /* over 100 */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":101}",
      "{\"cidr\":\"10.0.0.0/8\"}",                         /* missing */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":2,\"x\":1}", /* unknown key */
      "{\"cidr\":\"10.0.0.0/8\",\"multiplier\":2},{\"cidr\":\"10.0.0.0/8\",\"multiplier\":3}", /* conflict */
      "1"};
  for (size_t n = 0; n < sizeof(bad_rules) / sizeof(*bad_rules); n++) {
    char text[2048];
    snprintf(text, sizeof(text),
             "{\"schema_version\":1,\"profile\":{" UUID "," WEIGHTS
             ",\"asset_importance\":{\"default_multiplier\":1,\"rules\":[%s]}," FLOORS ",\"direction\":\"equal\"}}",
             bad_rules[n]);
    rejects(bad_rules[n], text);
  }
  rejects("default multiplier 0", DOC(WEIGHTS, "\"asset_importance\":{\"default_multiplier\":0,\"rules\":[]}", FLOORS,
                                      "\"equal\""));
  /* asset multipliers boost only: 1 to 100 inclusive, default and rules alike */
  static const char *const multipliers[] = {"1", "2", "5", "10", "100", "1.0", "1e2", "0.999999", "0", "-1",
                                            "100.000001", "101", "1e3"};
  for (size_t n = 0; n < sizeof(multipliers) / sizeof(*multipliers); n++) {
    bool valid = n < 7;
    char text[2048];
    snprintf(text, sizeof(text),
             "{\"schema_version\":1,\"profile\":{" UUID "," WEIGHTS
             ",\"asset_importance\":{\"default_multiplier\":%s,\"rules\":[{\"cidr\":\"10.0.0.0/8\",\"multiplier\":%s}]},"
             FLOORS ",\"direction\":\"equal\"}}", multipliers[n], multipliers[n]);
    struct profile q;
    char reason[256];
    bool ok = profile_compile(text, strlen(text), &q, reason, sizeof(reason));
    if (ok) profile_release(&q);
    if (ok != valid) {
      printf("multiplier %s: %s\n", multipliers[n], ok ? "accepted" : reason);
      failed = 1;
    }
    /* the discovery units of every valid multiplier stay far from saturation */
    if (ok) expect("units", profile_unit(&q, 100.0) <= 100 * PROFILE_DISCOVERY_UNIT);
  }
  /* the rule cap */
  {
    size_t size = 64 + (PROFILE_ASSET_RULES_MAX + 1) * 48 + 1024;
    char *text = malloc(size), *at = text;
    at += sprintf(at, "{\"schema_version\":1,\"profile\":{" UUID "," WEIGHTS
                      ",\"asset_importance\":{\"default_multiplier\":1,\"rules\":[");
    for (int n = 0; n <= PROFILE_ASSET_RULES_MAX; n++)
      at += sprintf(at, "%s{\"cidr\":\"10.%d.%d.0/24\",\"multiplier\":2}", n ? "," : "", n >> 8, n & 255);
    sprintf(at, "]}," FLOORS ",\"direction\":\"equal\"}}");
    rejects("rule cap", text);
    free(text);
  }
  expect("missing file", !profile_load("/nonexistent/profile.json", &p, why, sizeof(why)));
  for (int n = 2; n < argc; n++) {
    bool loaded = profile_load(argv[n], &p, why, sizeof(why));
    if (!loaded) printf("%s: %s\n", argv[n], why);
    else profile_release(&p);
    failed |= !loaded;
  }
  if (!failed) printf("ok\n");
  return failed;
}
