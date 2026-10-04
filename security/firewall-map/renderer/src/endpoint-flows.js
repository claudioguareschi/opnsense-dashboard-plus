/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
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
