/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschi@gmail.com>
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

/*
 * Everything the renderer writes on the map (legend, hover cards, flow sentences), in English.
 * The map page and the dashboard widget pass their translated table to create() as `text`; a
 * key they leave out falls back to the English here. {name} marks a value filled in at run time;
 * keys ending in _one / _many are the singular and plural of one phrase.
 */
export const DEFAULT_TEXT = {
  map_started_inside: 'Started inside',
  map_started_outside: 'Started outside',
  map_started_both: 'Started from both sides',
  map_toward: 'Toward the firewall',
  map_away: 'Away from the firewall',
  map_blocked: 'Blocked',
  map_flagged_blocked: 'Flagged · blocked',
  map_flagged_allowed: 'Flagged · allowed',
  map_allowed: 'Allowed',
  map_ids_alert: 'IDS alert',
  map_minutes: '{count} min',
  map_hours: '{count} h',
  map_days: '{count} days',
  map_moments: 'moments',
  map_port: 'port {port}',
  map_traffic: 'traffic',
  map_this_firewall: 'this firewall',
  map_this_firewall_title: 'This firewall',
  map_other_targets_one: ' (and {count} other target)',
  map_other_targets_many: ' (and {count} other targets)',
  map_through_forward: ' through a port forward',
  map_open_for: ', open for {duration}',
  map_reached: '{other} reached {where} on {service}{more}{forwarded}{open}.',
  map_other_hosts_one: '{host} and {count} other host',
  map_other_hosts_many: '{host} and {count} other hosts',
  map_other_services_one: ' and {count} other service',
  map_other_services_many: ' and {count} other services',
  map_queried: '{who} queried {service}{more} at {other}',
  map_synced: '{who} synced time with {other} over {service}{more}',
  map_mailed: '{who} delivered mail to {other} over {service}{more}',
  map_pinged: '{who} pinged {other}',
  map_opened: '{who} opened {service}{more} to {other}',
  map_a_connection: 'a connection',
  map_other_ports_one: ' and {count} other port',
  map_other_ports_many: ' and {count} other ports',
  map_and: ' and ',
  map_by_rule: ' by "{rule}"',
  map_on_interface: ' on {interface}',
  map_first_seen_ago: ', first seen {duration} ago',
  map_block_sentence: '{source}{place} tried {tried} on this firewall: blocked {hits}× in the last {minutes} min{rule}{where}{since}.',
  map_ids_line: 'Suricata: {signature} (severity {severity}{category})',
  map_ids_first: ', {count}× in the last {window}, latest {latest} ago',
  map_ids_count: ', {count}×',
  map_more_alerts_one: 'and {count} more alert',
  map_more_alerts_many: 'and {count} more alerts',
  map_more_addresses_one: '+{count} more address here',
  map_more_addresses_many: '+{count} more addresses here',
  map_addresses_many: '{count} addresses',
  map_via: 'via {egress}',
  map_open_state: 'open for {duration}',
  map_closed: 'closed',
  map_ips_dropped: 'Dropped by IPS',
  map_ips_dropped_flagged: 'Dropped by IPS · flagged',
  map_ids_connection: 'Suricata alerted on this connection',
  map_ids_connection_dropped: 'Suricata alerted on this connection · dropped by IPS',
  map_rule: 'rule: {rule}',
  map_seen_by_suricata: 'Seen by Suricata',
  map_seen_by_suricata_flagged: 'Seen by Suricata · flagged',
  map_no_connection: 'No connection is open right now',
  map_last_minute: '{count} in the last minute',
  map_hammering: ' · hammering',
  map_active_links_one: '{count} active link',
  map_active_links_many: '{count} active links',
};

/** The text table in use: the caller's translations over the English defaults. */
export function textTable(text) {
  return {...DEFAULT_TEXT, ...(text || {})};
}
