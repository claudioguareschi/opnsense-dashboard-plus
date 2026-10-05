/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
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

/** Index current flows by their destination address for endpoint details. */
export function indexFlowsByDestination(data) {
  const locations = new Set((data.locations || []).map((location) => location.id));
  const flows = new Map();
  for (const flow of data.flows || []) {
    if (!locations.has(flow.dest)) {
      continue;
    }
    const members = flows.get(flow.dest);
    if (members) {
      members.push(flow);
    } else {
      flows.set(flow.dest, [flow]);
    }
  }
  return flows;
}

/** Keep the last details for endpoint objects that are still visible during fade-out. */
export function retainVisibleEndpointFlows(current, previous, visibleEndpoints) {
  const flows = new Map(current);
  for (const endpoint of visibleEndpoints || []) {
    if (!endpoint.fading || flows.has(endpoint.id)) {
      continue;
    }
    const previousFlows = previous.get(endpoint.id);
    if (previousFlows) {
      flows.set(endpoint.id, previousFlows);
    }
  }
  return flows;
}

/** Return only the flows belonging to the endpoint currently under the pointer. */
export function endpointMembers(index, endpoint) {
  return index.get(endpoint?.id) || [];
}
