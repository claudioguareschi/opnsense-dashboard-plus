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

#ifndef FM_STATE_H
#define FM_STATE_H
#include "error.h"
#include <stdint.h>
#include "context.h"
#define FM_LABEL_SIZE 64
/* PF state direction (PF_IN/PF_OUT); pf_reader.c asserts the values match. */
#define FM_IN 1
#define FM_OUT 2
/* PF keeps two keys per state. The wire key holds the addresses as they
 * appear on the interface the state was created on; the stack key holds the
 * addresses as the host stack sees them. They differ only under translation. */
#define FM_WIRE_KEY 0
#define FM_STACK_KEY 1
/* PF counters are indexed by packet direction relative to the state's
 * creation: forward is initiator -> responder, reverse the replies. */
#define FM_PF_FORWARD 0
#define FM_PF_REVERSE 1
struct endpoint {
  struct addr a;
  uint16_t port;
};
struct key {
  struct endpoint e[2];
  unsigned char proto;
};
/* One PF state as decoded from netlink (borrowed by callbacks). */
struct state {
  uint64_t id, pf_bytes[2], pf_packets[2];
  uint32_t creator, age, expire, rule;
  unsigned char pf_direction, peer[2];
  char interface[FM_INTERFACE_SIZE], original_interface[FM_INTERFACE_SIZE],
      label[FM_LABEL_SIZE];
  struct key key[2];
};
/* PF orientation of one state, before any map semantics.
 * initiator/responder: the endpoints of the packet that created the state, as
 *   PF shows them (wire key outbound, stack key inbound, as pfctl prints).
 * untranslated: the endpoint PF rewrote, before translation: the inside
 *   source of an outbound NAT, or the public destination of an inbound
 *   redirect. Equal to the corresponding side when nothing was translated. */
/* A state PF can produce but the map does not model yet. It is recognized
 * positively, skipped before any aggregation side effect and counted by
 * reason; anything not recognized this way is a structural failure. */
enum state_skip {
  SKIP_NONE = 0,
  SKIP_AF_TRANSLATION = 1, /* af-to (NAT64/NAT46): wire and stack keys of different families */
};
struct orientation {
  struct endpoint initiator, responder, untranslated;
  unsigned proto;
  bool translated;
  enum state_skip skip;
};
/* Map semantics of one state.
 * local/remote: the logical flow pair (our-side anchor address, external peer).
 * inside: the site-internal host endpoint, when one can be identified.
 * outside_view: our side of the connection as the remote sees it.
 * remote_endpoint: the remote side's address and port.
 * remote_initiated: exact; the remote is PF's initiator. It orients counters.
 * apparent_remote_initiated: presentation heuristic (also treats a low
 *   source port talking to a high port as remote initiated); never orients
 *   counters. */
struct state_view {
  struct orientation pf;
  struct endpoint inside, outside_view, remote_endpoint;
  struct addr local, remote;
  unsigned service_port;
  bool has_inside, retained, mapped, remote_initiated, apparent_remote_initiated;
};
/* Failure classes: an impossible PF direction or key protocol pair is
 * structural (FM_FAILURE_STRUCTURAL); keys the decoder should never produce
 * break an internal invariant (FM_FAILURE_INTERNAL); a recognized but
 * unsupported state sets orientation.skip and returns true. */
bool state_orient(const struct state *, struct orientation *, struct fm_error *);
bool state_normalize(const struct state *, const struct context *,
                     struct state_view *, struct fm_error *);
bool endpoint_equal(struct endpoint, struct endpoint);
bool state_is_icmp(unsigned);
#define FM_TUPLE_SIZE 39
size_t state_tuple(unsigned char *, unsigned, struct endpoint, struct endpoint);
/* Shared logical aggregate identity: local, remote and the flow's owner (the
 * inside host behind it, or the zero address for the firewall's own traffic),
 * so a LAN host's NAT state and the firewall's own state to the same remote
 * stay separate flows. Never includes a discovered map anchor. */
#define FM_FLOW_KEY_SIZE 51
void state_flow_key(unsigned char[FM_FLOW_KEY_SIZE], struct addr local, struct addr remote,
                    struct addr owner);
/* The owner of a state's flow: its inside host, or the zero address. */
struct addr state_owner(const struct state_view *);
/* Oriented counters of one state: remote_initiated selects which PF counter
 * index carries the remote's traffic. */
uint64_t state_bytes_from_remote(const struct state *, bool remote_initiated);
uint64_t state_bytes_to_remote(const struct state *, bool remote_initiated);
uint64_t state_packets_from_remote(const struct state *, bool remote_initiated);
uint64_t state_packets_to_remote(const struct state *, bool remote_initiated);
#endif
