{#
 # Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<link rel="stylesheet" href="/ui/css/firewall-map.css?v={{ styleVersion }}">
<link rel="stylesheet" href="/ui/css/flags/flag-icon.css">
<script>
    // The strings the page shares with the dashboard widget (and the renderer) come from the widget's
    // translations (sharedText, see IndexController, already plain text); the ones below are the
    // page's own, and win where both exist. lang._() returns HTML-escaped text and the page escapes
    // again where it builds HTML, so they are decoded once here; json_encode makes each a valid
    // JavaScript string.
    function firewallMapPlain(strings) {
        const box = document.createElement('textarea');
        Object.keys(strings).forEach(function (key) {
            box.innerHTML = strings[key];
            strings[key] = box.value;
        });
        return strings;
    }
    // what this user may do (see IndexController::permissions()): only flags, true or false
    window.FirewallMapPermissions = {{ permissions }};
    window.FirewallMapPageText = Object.assign({{ sharedText }}, firewallMapPlain({
        firewall_map: {{ lang._('Firewall Map')|json_encode }},
        starting: {{ lang._('Warming up…')|json_encode }},
        reading: {{ lang._('Reading data…')|json_encode }},
        unavailable: {{ lang._('Live flow data is unavailable')|json_encode }},
        webgl: {{ lang._('WebGL is required for Firewall Map+')|json_encode }},
        downloading: {{ lang._('Downloading the geolocation database…')|json_encode }},
        all_services: {{ lang._('All services')|json_encode }},
        all_interfaces: {{ lang._('All interfaces')|json_encode }},
        all_hosts: {{ lang._('All inside hosts')|json_encode }},
        all_countries: {{ lang._('All countries')|json_encode }},
        no_talkers: {{ lang._('No traffic yet')|json_encode }},
        filter_hint: {{ lang._('Show only this on the map')|json_encode }},
        click_hint: {{ lang._('Click an endpoint or arc on the map for details and actions.')|json_encode }},
        ids_flow: {{ lang._('IDS flow')|json_encode }},
        ids_flows: {{ lang._('IDS flows')|json_encode }},
        ids_address: {{ lang._('IDS address')|json_encode }},
        ids_addresses: {{ lang._('IDS addresses')|json_encode }},
        sec_connection: {{ lang._('Connection')|json_encode }},
        sec_firewall: {{ lang._('Firewall')|json_encode }},
        sec_reputation: {{ lang._('Reputation')|json_encode }},
        via: {{ lang._('Public side')|json_encode }},
        closed: {{ lang._('closed')|json_encode }},
        transferred: {{ lang._('Transferred')|json_encode }},
        decision: {{ lang._('Decision')|json_encode }},
        allowed: {{ lang._('Allowed')|json_encode }},
        rule: {{ lang._('Rule')|json_encode }},
        severity: {{ lang._('Severity')|json_encode }},
        ips_dropped: {{ lang._('dropped by IPS')|json_encode }},
        copy: {{ lang._('Copy')|json_encode }},
        whois: {{ lang._('Whois')|json_encode }},
        show_states: {{ lang._('States')|json_encode }},
        kill_states: {{ lang._('Kill states')|json_encode }},
        add_to_alias: {{ lang._('Add to alias')|json_encode }},
        add_country: {{ lang._('Add country to GeoIP alias')|json_encode }},
        close: {{ lang._('Close')|json_encode }},
        confirm: {{ lang._('Confirm')|json_encode }},
        cancel: {{ lang._('Cancel')|json_encode }},
        kill_confirm: {{ lang._('Kill all firewall states involving')|json_encode }},
        kill_scope: {{ lang._('This ends the connections of every inside host to this address, and any traffic routed through it.')|json_encode }},
        killed: {{ lang._('States killed:')|json_encode }},
        add_confirm: {{ lang._('Add')|json_encode }},
        no_aliases: {{ lang._('No suitable alias exists yet. Create one under Firewall ▸ Aliases first.')|json_encode }},
        action_failed: {{ lang._('The action failed')|json_encode }},
        states_for: {{ lang._('States for')|json_encode }},
        no_states: {{ lang._('No states found.')|json_encode }},
        more_states: {{ lang._('Only the first 100 states are shown.')|json_encode }},
        interface: {{ lang._('Interface')|json_encode }},
        protocol: {{ lang._('Protocol')|json_encode }},
        source: {{ lang._('Source')|json_encode }},
        destination: {{ lang._('Destination')|json_encode }},
        state: {{ lang._('State')|json_encode }},
        bytes: {{ lang._('Bytes')|json_encode }},
        investigate: {{ lang._('Investigate')|json_encode }},
        looking_up: {{ lang._('Looking up registry, routing and reputation…')|json_encode }},
        lookup_failed: {{ lang._('Lookup failed')|json_encode }},
        retry: {{ lang._('Retry')|json_encode }},
        registry: {{ lang._('Registry (RDAP)')|json_encode }},
        routing: {{ lang._('Routing (RIPEstat)')|json_encode }},
        owner: {{ lang._('Owner')|json_encode }},
        network: {{ lang._('Network')|json_encode }},
        range: {{ lang._('Range')|json_encode }},
        country: {{ lang._('Country')|json_encode }},
        abuse_contact: {{ lang._('Abuse contact')|json_encode }},
        registered: {{ lang._('Registered')|json_encode }},
        updated: {{ lang._('updated')|json_encode }},
        prefix: {{ lang._('Prefix')|json_encode }},
        origin_as: {{ lang._('Origin AS')|json_encode }},
        announced: {{ lang._('Announced')|json_encode }},
        yes: {{ lang._('yes')|json_encode }},
        no: {{ lang._('no')|json_encode }},
        confidence: {{ lang._('Abuse confidence')|json_encode }},
        reports: {{ lang._('Reports (90 days)')|json_encode }},
        reporters: {{ lang._('reporters')|json_encode }},
        last_reported: {{ lang._('Last reported')|json_encode }},
        usage: {{ lang._('Usage')|json_encode }},
        abuseipdb_hint: {{ lang._('Add an AbuseIPDB API key in the Firewall Map settings to see abuse reports here.')|json_encode }},
        mark_threat: {{ lang._('Mark as threat')|json_encode }},
        mark_confirm: {{ lang._('Add')|json_encode }},
        mark_scope: {{ lang._('to the FWMAP_Watchlist alias? The map will flag its traffic as a threat. No firewall rule is added.')|json_encode }},
        marked: {{ lang._('Its traffic is flagged on the map within five minutes.')|json_encode }},
        inbound: {{ lang._('Inbound')|json_encode }},
        outbound: {{ lang._('Outbound')|json_encode }},
        this_firewall: {{ lang._('this firewall')|json_encode }},
        blacklist: {{ lang._('AbuseIPDB blacklist (downloaded daily)')|json_encode }},
        blacklist_addresses: {{ lang._('addresses')|json_encode }},
        blacklist_pending: {{ lang._('Not downloaded yet')|json_encode }},
        blacklist_error: {{ lang._('last attempt failed')|json_encode }},
        blacklist_no_key: {{ lang._('Add an AbuseIPDB API key in the Firewall Map settings to download it.')|json_encode }},
        active: {{ lang._('Active')|json_encode }},
        allowed_flagged: {{ lang._('Allowed · flagged')|json_encode }},
        block_attempts: {{ lang._('Attempts')|json_encode }},
        blocked: {{ lang._('Blocked')|json_encode }},
        blocked_attempts: {{ lang._('Blocked attempts')|json_encode }},
        blocked_flagged: {{ lang._('Blocked · flagged')|json_encode }},
        flagged: {{ lang._('flagged')|json_encode }},
        ips_dropped_flagged: {{ lang._('Dropped by IPS · flagged')|json_encode }},
        ips_dropped_title: {{ lang._('Dropped by IPS')|json_encode }},
        clean: {{ lang._('Clean')|json_encode }},
        connections: {{ lang._('Connections')|json_encode }},
        current_rate: {{ lang._('Current rate')|json_encode }},
        egress: {{ lang._('Egress')|json_encode }},
        idle: {{ lang._('Idle')|json_encode }},
        ids_on_address: {{ lang._('Alerts on this address in the last hour (not necessarily this traffic)')|json_encode }},
        ids_on_connection: {{ lang._('Alerts raised by this exact connection')|json_encode }},
        ids_only: {{ lang._('Seen by Suricata')|json_encode }},
        ids_only_sub: {{ lang._('No open connection')|json_encode }},
        in_minutes: {{ lang._('in {minutes} min')|json_encode }},
        inside_side: {{ lang._('Inside side')|json_encode }},
        listed: {{ lang._('Listed')|json_encode }},
        more: {{ lang._('More')|json_encode }},
        no_connection: {{ lang._('No connection is open right now.')|json_encode }},
        no_ids: {{ lang._('No IDS alerts for this address')|json_encode }},
        no_ids_sub: {{ lang._('Suricata has not alerted on this address in the last hour.')|json_encode }},
        no_ids_talkers: {{ lang._('No Suricata alerts in the last hour')|json_encode }},
        select_hint: {{ lang._('Show the details')|json_encode }},
        last_updated_ago: {{ lang._('Last updated {time} ago')|json_encode }},
        ids_alert: {{ lang._('IDS alert')|json_encode }},
        open_ids: {{ lang._('Open Suricata alerts')|json_encode }},
        open_log: {{ lang._('Open the firewall log')|json_encode }},
        port_word: {{ lang._('Port')|json_encode }},
        checking: {{ lang._('checking…')|json_encode }},
        check_now: {{ lang._('Check now')|json_encode }},
        no_key: {{ lang._('no API key')|json_encode }},
        not_listed_short: {{ lang._('Not listed')|json_encode }},
        fw_passed: {{ lang._('Passed')|json_encode }},
        fw_blocked: {{ lang._('Blocked')|json_encode }},
        fw_not_seen: {{ lang._('not seen by the firewall')|json_encode }},
        ips_dropped_short: {{ lang._('IPS drop')|json_encode }},
        query: {{ lang._('query')|json_encode }},
        more_connection: {{ lang._('more connection')|json_encode }},
        more_connections: {{ lang._('more connections')|json_encode }},
        connection_col: {{ lang._('Connection')|json_encode }},
        no_snapshot: {{ lang._('No connection snapshot yet: it is taken the next time this address has an open connection.')|json_encode }},
        show_more: {{ lang._('Show {count} more')|json_encode }},
        showing: {{ lang._('{shown} of {total} shown')|json_encode }},
        dismiss_all: {{ lang._('Dismiss all ({count})')|json_encode }},
        dismiss_all_confirm: {{ lang._('Dismiss all {count} new entries? You can reopen them from the Dismissed tab.')|json_encode }},
        delete_all: {{ lang._('Delete all ({count})')|json_encode }},
        delete_all_confirm: {{ lang._('Delete all {count} {status} entries for good? This cannot be undone. New traffic from these addresses would create new entries.')|json_encode }},
        sample: {{ lang._('sample')|json_encode }},
        other_target: {{ lang._('other target')|json_encode }},
        other_targets: {{ lang._('other targets')|json_encode }},
        targets_seen: {{ lang._('Targets')|json_encode }},
        other_hosts: {{ lang._('more inside')|json_encode }},
        more_details: {{ lang._('More details')|json_encode }},
        services_seen: {{ lang._('Services seen')|json_encode }},
        remote_port: {{ lang._('Remote port')|json_encode }},
        duration: {{ lang._('Duration')|json_encode }},
        alerts_short: {{ lang._('alerts')|json_encode }},
        flow_one: {{ lang._('flow')|json_encode }},
        flow_many: {{ lang._('flows')|json_encode }},
        organization: {{ lang._('Organization')|json_encode }},
        pf_sets: {{ lang._('PF sets')|json_encode }},
        set_country: {{ lang._('country blocklist: membership decided by the firewall, which may differ from the geolocation')|json_encode }},
        set_operational: {{ lang._('operational set')|json_encode }},
        other_ports: {{ lang._('Other ports')|json_encode }},
        other_services: {{ lang._('Other services')|json_encode }},
        port_forward: {{ lang._('Port forward')|json_encode }},
        remote_addresses_here: {{ lang._('addresses here:')|json_encode }},
        connections_here: {{ lang._('connections to this address:')|json_encode }},
        remote_side: {{ lang._('Remote side')|json_encode }},
        sec_ids_long: {{ lang._('IDS (Suricata)')|json_encode }},
        started: {{ lang._('Started')|json_encode }},
        started_inside_long: {{ lang._('Outbound · started inside')|json_encode }},
        started_outside_long: {{ lang._('Inbound · started outside')|json_encode }},
        target: {{ lang._('Target')|json_encode }},
        this_firewall_title: {{ lang._('This firewall')|json_encode }},
        tried: {{ lang._('Tried')|json_encode }},
        review_queue: {{ lang._('Threats')|json_encode }},
        review_intro: {{ lang._('Flagged traffic organized by observed firewall and IPS disposition')|json_encode }},
        record_threats: {{ lang._('Record in the background')|json_encode }},
        record_threats_hint: {{ lang._('Keep recording while the map is closed, as long as the widget is on a dashboard. Setting a status never changes firewall rules.')|json_encode }},
        queue_search: {{ lang._('Filter by address, network, list, host…')|json_encode }},
        time_ago: {{ lang._('{time} ago')|json_encode }},
        first_seen_ago: {{ lang._('First seen {time} ago')|json_encode }},
        blacklist_short: {{ lang._('AbuseIPDB blacklist')|json_encode }},
        status_new: {{ lang._('New')|json_encode }},
        status_reviewed: {{ lang._('Reviewed')|json_encode }},
        status_dismissed: {{ lang._('Dismissed')|json_encode }},
        status_blocked: {{ lang._('Blocked')|json_encode }},
        status_all: {{ lang._('All')|json_encode }},
        status_passed: {{ lang._('Passed / reached host')|json_encode }},
        status_firewall_blocked: {{ lang._('Blocked by firewall')|json_encode }},
        status_ips_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        disposition_passed: {{ lang._('Passed · reached host')|json_encode }},
        disposition_firewall_blocked: {{ lang._('Blocked at firewall')|json_encode }},
        disposition_ips_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        passed_attention: {{ lang._('need attention')|json_encode }},
        mark_reviewed: {{ lang._('Mark reviewed')|json_encode }},
        dismiss: {{ lang._('Dismiss')|json_encode }},
        reopen: {{ lang._('Reopen')|json_encode }},
        block: {{ lang._('Block…')|json_encode }},
        block_title: {{ lang._('Add to a blocking alias')|json_encode }},
        block_hint: {{ lang._('The address is added to the alias you choose. It is blocked only if a firewall rule uses that alias.')|json_encode }},
        edit_note: {{ lang._('Note')|json_encode }},
        note_title: {{ lang._('Note for')|json_encode }},
        save: {{ lang._('Save')|json_encode }},
        first_seen: {{ lang._('First seen')|json_encode }},
        samples: {{ lang._('samples')|json_encode }},
        peak: {{ lang._('peak')|json_encode }},
        seen_after_block: {{ lang._('Traffic was seen after it was marked blocked: check that a rule uses the alias.')|json_encode }},
        snapshot_population: {{ lang._('from {count} flows')|json_encode }},
        snapshot_ranking_bounded: {{ lang._('ranking was bounded')|json_encode }},
        map_profile: {{ lang._('{profile} ranking')|json_encode }},
        map_interval: {{ lang._('refreshed every {seconds} s')|json_encode }},
        map_carp_backup: {{ lang._('CARP backup: traffic is passing through the master')|json_encode }},
        map_carp_mirror: {{ lang._("CARP backup: mirroring the master's connections (no traffic data)")|json_encode }},
        map_waiting_restart: {{ lang._('The collector is restarting: the map resumes with its first ranked sample')|json_encode }},
        map_waiting_profile: {{ lang._('Applying the {profile} ranking profile: the map resumes with its first ranked sample')|json_encode }},
        mirror_sub: {{ lang._('Mirrored from the CARP master (no traffic data)')|json_encode }},
        probe_sub: {{ lang._('{count} connection attempts, no data')|json_encode }},
        snapshot_loading: {{ lang._('Loading the snapshot…')|json_encode }},
        snapshot_waiting: {{ lang._('The map is waiting for the collector: take the snapshot when it resumes')|json_encode }},
        map_ranking_bounded: {{ lang._('the top-ranked of {count} flows')|json_encode }},
        map_ranking_warming: {{ lang._('ranking settling after a busy period')|json_encode }},
        listed_flows_one: {{ lang._('{count} to a listed address')|json_encode }},
        listed_flows_many: {{ lang._('{count} to listed addresses')|json_encode }},
        dismiss_shown: {{ lang._('Dismiss {count} shown')|json_encode }},
        dismiss_shown_confirm: {{ lang._('Dismiss the {count} new entries this search shows? You can reopen them from the Dismissed tab.')|json_encode }},
        delete_shown: {{ lang._('Delete {count} shown')|json_encode }},
        queue_no_match: {{ lang._('No entries match this search.')|json_encode }},
        queue_empty: {{ lang._('Nothing here.')|json_encode }},
        queue_empty_passed: {{ lang._('No unreviewed flagged traffic reached a host.')|json_encode }},
        queue_empty_firewall_blocked: {{ lang._('No unreviewed flagged traffic was blocked by PF.')|json_encode }},
        queue_empty_ips_dropped: {{ lang._('No unreviewed flagged traffic was dropped by IPS.')|json_encode }},
        queue_empty_reviewed: {{ lang._('No entries marked reviewed yet.')|json_encode }},
        queue_empty_dismissed: {{ lang._('No dismissed entries.')|json_encode }},
        queue_empty_all: {{ lang._('Threat history is empty.')|json_encode }},
        resize_hint: {{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset')|json_encode }},
        today: {{ lang._('Today')|json_encode }},
        snapshot: {{ lang._('Snapshot')|json_encode }},
        snapshots: {{ lang._('Snapshots')|json_encode }},
        snapshot_flows_one: {{ lang._('{count} flow')|json_encode }},
        snapshot_flows_many: {{ lang._('{count} flows')|json_encode }},
        snapshot_flagged_one: {{ lang._('{count} flagged')|json_encode }},
        snapshot_flagged_many: {{ lang._('{count} flagged')|json_encode }},
        snapshot_view: {{ lang._('Open')|json_encode }},
        snapshot_note: {{ lang._('Snapshot note')|json_encode }},
        snapshot_add_note: {{ lang._('Add a note')|json_encode }},
        snapshot_edit_note: {{ lang._('Edit note')|json_encode }},
        snapshot_download: {{ lang._('Download as JSON')|json_encode }},
        snapshot_delete: {{ lang._('Delete snapshot')|json_encode }},
        snapshot_delete_confirm: {{ lang._('Delete the snapshot taken')|json_encode }},
        snapshot_by: {{ lang._('by')|json_encode }},
        snapshot_partial: {{ lang._('summary only')|json_encode }},
        snapshot_unknown: {{ lang._('Detail completeness unknown')|json_encode }},
        snapshot_truncated: {{ lang._('Truncated detail')|json_encode }},
        snapshot_complete: {{ lang._('Complete detail within capture scope')|json_encode }},
        snapshot_captured_flows: {{ lang._('{captured} flows captured of {available} available')|json_encode }},
        snapshot_omitted_geo: {{ lang._('{count} additional flows without geographic data')|json_encode }},
        snapshot_captured_states: {{ lang._('{captured} of {available} matching PF rows saved across captured remotes')|json_encode }},
        snapshot_partial_hint: {{ lang._('The collector did not answer in time: the map as shown was saved, without the connection states.')|json_encode }},
        snapshot_no_states: {{ lang._('This snapshot was saved without connection states.')|json_encode }},
        snapshot_show: {{ lang._('Show this snapshot')|json_encode }},
        snapshot_older: {{ lang._('Older snapshot')|json_encode }},
        snapshot_newer: {{ lang._('Newer snapshot')|json_encode }},
        no_snapshots: {{ lang._('No snapshots yet: take one with the camera button on the map.')|json_encode }},
        snapshots_kept: {{ lang._('The newest {count} are kept, for up to {days} days.')|json_encode }},
        timeline: {{ lang._('Timeline')|json_encode }},
        timeline_expand: {{ lang._('Show the timeline')|json_encode }},
        timeline_collapse: {{ lang._('Collapse the timeline')|json_encode }},
        timeline_previous_day: {{ lang._('Previous day with snapshots')|json_encode }},
        timeline_next_day: {{ lang._('Next day with snapshots')|json_encode }},
        snapshots_here_one: {{ lang._('{count} snapshot')|json_encode }},
        snapshots_here_many: {{ lang._('{count} snapshots taken close together')|json_encode }},
        captured_at: {{ lang._('Captured {time}')|json_encode }},
        as_captured_at: {{ lang._('As captured at {time}')|json_encode }},
        may_have_closed: {{ lang._('this connection may have closed since')|json_encode }},
        states_at: {{ lang._('States at')|json_encode }},
        current_states: {{ lang._('Current states')|json_encode }},
    }));
</script>
<script src="/ui/js/firewall-map-renderer.js?v={{ rendererVersion }}"></script>
<script src="/ui/js/firewall-map-page.js?v={{ pageVersion }}"></script>
{% if diagnosticsVersion %}
<script src="/ui/js/firewall-map-diagnostics.js?v={{ diagnosticsVersion }}"></script>
{% endif %}

<div class="content-box" style="padding: 12px;">
    <div id="fwmap-layout">
        <div id="fwmap-main">
    <div id="fwmap-toolbar">
            <div id="fwmap-mode" class="btn-group btn-group-sm" role="group" aria-label="{{ lang._('Map mode') }}">
                <button type="button" id="fwmap-mode-live" class="btn btn-default active" data-mode="live" aria-pressed="true"><i class="fwmap-live"></i> {{ lang._('Live') }}</button>
                <button type="button" id="fwmap-mode-snapshots" class="btn btn-default" data-mode="snapshots" aria-pressed="false" disabled><i class="fa fa-fw fa-camera" aria-hidden="true"></i> {{ lang._('Snapshots') }} <span class="badge" id="fwmap-snapshot-count"></span></button>
            </div>
            <span class="fwmap-tool-sep" aria-hidden="true"></span>
            <div id="fwmap-chips" role="group" aria-label="{{ lang._('Filters') }}">
                <div class="btn-group btn-group-sm fwmap-filter" data-filter="traffic" data-icon="fa-fw fa-arrows-up-down">
                    <select id="fwmap-filter-traffic" class="selectpicker" data-width="fit" data-style="btn-default btn-sm" data-icon-base="fa" data-size="12" aria-label="{{ lang._('Traffic') }}">
                        <option value="all">{{ lang._('All traffic') }}</option>
                        <option value="permitted">{{ lang._('Allowed') }}</option>
                        <option value="blocked">{{ lang._('Blocked') }}</option>
                        <option value="threats">{{ lang._('Threats that got through') }}</option>
                        <option value="ids">{{ lang._('IDS alerts') }}</option>
                        <option value="ids_flows">{{ lang._('IDS flows') }}</option>
                        <option value="ids_addresses">{{ lang._('IDS addresses') }}</option>
                    </select>
                    <button type="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><i class="fa fa-xmark" aria-hidden="true"></i></button>
                </div>
                <div class="btn-group btn-group-sm fwmap-filter" data-filter="iface" data-icon="fa-fw fa-sitemap">
                    <select id="fwmap-filter-iface" class="selectpicker" data-width="fit" data-style="btn-default btn-sm" data-icon-base="fa" data-size="12" data-live-search="true" aria-label="{{ lang._('Interface') }}"><option value="">{{ lang._('All interfaces') }}</option></select>
                    <button type="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><i class="fa fa-xmark" aria-hidden="true"></i></button>
                </div>
                <div class="btn-group btn-group-sm fwmap-filter" data-filter="host" data-icon="fa-fw fa-desktop">
                    <select id="fwmap-filter-host" class="selectpicker" data-width="fit" data-style="btn-default btn-sm" data-icon-base="fa" data-size="12" data-live-search="true" aria-label="{{ lang._('Inside host') }}"><option value="">{{ lang._('All inside hosts') }}</option></select>
                    <button type="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><i class="fa fa-xmark" aria-hidden="true"></i></button>
                </div>
                <div class="btn-group btn-group-sm fwmap-filter" data-filter="service" data-icon="fa-fw fa-table-cells-large">
                    <select id="fwmap-filter-service" class="selectpicker" data-width="fit" data-style="btn-default btn-sm" data-icon-base="fa" data-size="12" data-live-search="true" aria-label="{{ lang._('Service') }}"><option value="">{{ lang._('All services') }}</option></select>
                    <button type="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><i class="fa fa-xmark" aria-hidden="true"></i></button>
                </div>
                <div class="btn-group btn-group-sm fwmap-filter" data-filter="country" data-icon="fa-fw fa-globe">
                    <select id="fwmap-filter-country" class="selectpicker" data-width="fit" data-style="btn-default btn-sm" data-icon-base="fa" data-size="12" data-live-search="true" aria-label="{{ lang._('Country') }}"><option value="">{{ lang._('All countries') }}</option></select>
                    <button type="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><i class="fa fa-xmark" aria-hidden="true"></i></button>
                </div>
                <div class="btn-group btn-group-sm" id="fwmap-filter-asn">
                    <span class="btn btn-primary fwmap-asn-label"><i class="fa fa-fw fa-building" aria-hidden="true"></i> <span></span></span>
                    <a href="#" role="button" class="btn btn-primary fwmap-filter-clear" title="{{ lang._('Remove') }}" aria-label="{{ lang._('Remove') }}"><i class="fa fa-xmark" aria-hidden="true"></i></a>
                </div>
                <div class="btn-group btn-group-sm" id="fwmap-more-wrap" style="display:none">
                    <button type="button" class="btn btn-default dropdown-toggle" id="fwmap-more" aria-haspopup="true" aria-expanded="false"><i class="fa fa-fw fa-filter" aria-hidden="true"></i> {{ lang._('Filters') }} <span class="badge" id="fwmap-more-count"></span> <span class="caret"></span></button>
                    <div class="dropdown-menu" id="fwmap-more-menu" role="group" aria-label="{{ lang._('More filters') }}"></div>
                </div>
                <button id="fwmap-reset" class="btn btn-default btn-sm" type="button" title="{{ lang._('Reset filters') }}" aria-label="{{ lang._('Reset filters') }}" style="display:none"><i class="fa fa-fw fa-rotate-left" aria-hidden="true"></i></button>
            </div>
            <button id="fwmap-review" class="btn btn-default btn-sm" type="button" style="display:none" title="{{ lang._('Threats') }}">
                <i class="fa fa-fw fa-list" aria-hidden="true"></i><span class="fwmap-tool-text">{{ lang._('Threats') }}</span> <span class="fwmap-pill fwmap-pill-danger" id="fwmap-review-count"></span>
            </button>
        </div>
        <div id="fwmap-map">
            <div id="fwmap-grid" aria-hidden="true"></div>
            <div id="fwmap-canvas"></div>
            <div id="fwmap-legend">
                <span class="fwmap-legend-mode"><span class="fwmap-legend-label">{{ lang._('Color') }}</span>
                    <select id="fwmap-color" class="selectpicker" data-width="fit" data-style="btn-default btn-xs" aria-label="{{ lang._('Color') }}">
                        <option value="initiator">{{ lang._('Inbound / outbound') }}</option>
                        <option value="direction">{{ lang._('Download / upload') }}</option>
                        <option value="egress">{{ lang._('By egress') }}</option>
                        <option value="service">{{ lang._('By service') }}</option>
                    </select></span>
                <span id="fwmap-legend-items"></span>
            </div>
            <div id="fwmap-controls">
                <div id="fwmap-zoom" class="btn-group-vertical btn-group-sm" role="group" aria-label="{{ lang._('Zoom') }}">
                    <button type="button" class="btn btn-default" data-zoom="1" title="{{ lang._('Zoom in') }}" aria-label="{{ lang._('Zoom in') }}"><i class="fa fa-fw fa-plus" aria-hidden="true"></i></button>
                    <button type="button" class="btn btn-default" data-zoom="-1" title="{{ lang._('Zoom out') }}" aria-label="{{ lang._('Zoom out') }}"><i class="fa fa-fw fa-minus" aria-hidden="true"></i></button>
                    <button type="button" class="btn btn-default" data-zoom="fit" title="{{ lang._('Whole world') }}" aria-label="{{ lang._('Whole world') }}"><i class="fa fa-fw fa-expand" aria-hidden="true"></i></button>
                    <button type="button" class="btn btn-default" id="fwmap-follow" data-zoom="follow" aria-pressed="false" title="{{ lang._('Follow traffic: keep the map zoomed to the current arcs') }}" aria-label="{{ lang._('Follow traffic') }}"><i class="fa fa-fw fa-crosshairs" aria-hidden="true"></i></button>
                </div>
                <button type="button" class="btn btn-default btn-sm" id="fwmap-camera" title="{{ lang._('Take a snapshot: save the map as it is now, to review later') }}" aria-label="{{ lang._('Take a snapshot') }}"><i class="fa fa-fw fa-camera" aria-hidden="true"></i></button>
            </div>
            <div id="fwmap-banner" style="display:none" aria-live="polite"></div>
            <div id="fwmap-geo"></div>
            <div id="fwmap-timeline" style="display:none"></div>
            <div id="fwmap-credit"></div>
        </div>
        <div id="fwmap-statusbar"><div id="fwmap-status" aria-live="polite"></div><div id="fwmap-updated"></div></div>
        </div>
        <div class="fwmap-splitter fwmap-splitter-v" id="fwmap-split-side" title="{{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset') }}"></div>
        <div id="fwmap-side">
            <div id="fwmap-talkers">
                <!-- each tab shows its icon; only the open one also shows its name (the others on hover) -->
                <ul class="nav nav-tabs" role="tablist" aria-label="{{ lang._('Top talkers') }}">
                    <li class="active" role="presentation"><a href="#" role="tab" aria-selected="true" data-tab="hosts" title="{{ lang._('Hosts') }}"><i class="fa fa-fw fa-desktop" aria-hidden="true"></i><span class="fwmap-tab-text">{{ lang._('Hosts') }}</span></a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="countries" title="{{ lang._('Countries') }}"><i class="fa fa-fw fa-globe" aria-hidden="true"></i><span class="fwmap-tab-text">{{ lang._('Countries') }}</span></a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="networks" title="{{ lang._('Networks') }}"><i class="fa fa-fw fa-sitemap" aria-hidden="true"></i><span class="fwmap-tab-text">{{ lang._('Networks') }}</span></a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="ids" title="{{ lang._('IDS') }}"><i class="fa fa-fw fa-shield-halved" aria-hidden="true"></i><span class="fwmap-tab-text">{{ lang._('IDS') }}</span></a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="snapshots" title="{{ lang._('Snapshots') }}"><i class="fa fa-fw fa-camera" aria-hidden="true"></i><span class="fwmap-tab-text">{{ lang._('Snapshots') }}</span></a></li>
                </ul>
                <div class="fwmap-talker-tools">
                    <div class="input-group input-group-sm">
                        <span class="input-group-addon"><i class="fa fa-fw fa-magnifying-glass" aria-hidden="true"></i></span>
                        <input type="search" class="form-control" id="fwmap-talker-search" placeholder="{{ lang._('Search…') }}" aria-label="{{ lang._('Search…') }}">
                    </div>
                    <select class="selectpicker" id="fwmap-talker-sort" data-width="fit" data-style="btn-default btn-sm" aria-label="{{ lang._('Sort') }}">
                        <option value="rate">{{ lang._('Top talkers') }}</option>
                        <option value="flows">{{ lang._('Most flows') }}</option>
                        <option value="name">{{ lang._('Name') }}</option>
                    </select>
                </div>
                <div id="fwmap-talkers-list"></div>
            </div>
            <div class="fwmap-splitter fwmap-splitter-h" id="fwmap-split-details" title="{{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset') }}"></div>
            <div id="fwmap-details-box">
                <div id="fwmap-details"></div>
            </div>
        </div>
    </div>
</div>
