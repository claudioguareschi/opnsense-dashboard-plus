{#
 # Copyright (C) 2026 Claudio Guareschi
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

<style>
    #fwmap-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
    #fwmap-toolbar select { width: auto; min-width: 130px; max-width: 220px; display: inline-block; height: 30px; padding: 2px 6px; }
    #fwmap-toolbar label { margin: 0 2px 0 6px; font-weight: normal; opacity: .8; }
    #fwmap-filter-asn { display: none; }
    #fwmap-layout { display: flex; }
    #fwmap-map {
        position: relative; flex: 1; min-width: 0; overflow: hidden; border-radius: 6px;
        /* header, page title, toolbar, content padding and the fixed footer */
        height: calc(100vh - 280px); min-height: 420px;
    }
    #fwmap-grid { pointer-events: none; position: absolute; inset: 0; z-index: 0; background-size: 48px 48px; }
    #fwmap-canvas { position: absolute; inset: 0; z-index: 1; text-align: left; }
    #fwmap-status { position: absolute; left: 14px; bottom: 10px; z-index: 2; font-size: .85em; pointer-events: none; }
    #fwmap-credit { position: absolute; right: 12px; bottom: 10px; z-index: 2; font-size: .8em; opacity: .7; }
    #fwmap-legend {
        position: absolute; left: 12px; top: 10px; z-index: 2; font-size: .8em; pointer-events: none;
        display: flex; flex-wrap: wrap; gap: 4px 12px; max-width: 70%;
    }
    .fwmap-legend-item i { display: inline-block; width: 18px; height: 3px; margin-right: 5px; vertical-align: middle; border-radius: 2px; }
    #fwmap-side { width: clamp(380px, 36vw, 640px); flex: 0 0 clamp(380px, 36vw, 640px); display: flex; flex-direction: column;
        height: calc(100vh - 280px); min-height: 420px; }
    #fwmap-talkers, #fwmap-details-box { border: 1px solid rgba(128, 128, 128, .25); border-radius: 6px; padding: 8px; }
    #fwmap-talkers { flex: 1 1 60%; overflow-y: auto; min-height: 0; }
    #fwmap-details-box { flex: 1 1 40%; overflow-y: auto; overflow-x: hidden; min-height: 0; }
    /* drag handles: between map and side panel, and between the two side boxes; double-click resets */
    .fwmap-splitter { flex: 0 0 12px; position: relative; touch-action: none; user-select: none; }
    .fwmap-splitter::after { content: ""; position: absolute; border-radius: 2px; background: rgba(128, 128, 128, .35);
        transition: background .15s; }
    .fwmap-splitter:hover::after, .fwmap-splitter.fwmap-dragging::after { background: rgba(128, 128, 128, .75); }
    .fwmap-splitter-v { cursor: col-resize; }
    .fwmap-splitter-v::after { left: 5px; top: 50%; width: 3px; height: 40px; margin-top: -20px; }
    .fwmap-splitter-h { cursor: row-resize; }
    .fwmap-splitter-h::after { top: 5px; left: 50%; height: 3px; width: 40px; margin-left: -20px; }
    body.fwmap-resizing, body.fwmap-resizing * { user-select: none !important; }
    #fwmap-talkers .nav { margin-bottom: 6px; }
    #fwmap-talkers .nav > li > a { padding: 4px 10px; }
    .fwmap-talker { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; column-gap: 8px; row-gap: 0;
        align-items: center; padding: 4px 6px; cursor: pointer; border-radius: 4px; }
    .fwmap-talker:hover { background: rgba(128, 128, 128, .12); }
    .fwmap-talker.active { background: rgba(200, 90, 40, .14); box-shadow: inset 3px 0 0 rgb(200, 90, 40); }
    .fwmap-talker-icon { grid-row: 1 / span 2; text-align: center; opacity: .7; font-size: 1.05em; }
    .fwmap-talker-label, .fwmap-talker-sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .fwmap-talker-label { font-weight: 600; }
    .fwmap-talker-rate, .fwmap-talker-count { text-align: right; font-variant-numeric: tabular-nums; font-size: .9em; white-space: nowrap; }
    .fwmap-talker-count { font-weight: 600; }
    .fwmap-talker-sub { font-size: .8em; opacity: .7; }
    .fwmap-talker canvas, .fwmap-talker > .fwmap-talker-flows { justify-self: end; }
    .fwmap-talker-flows { font-size: .8em; opacity: .7; white-space: nowrap; }
    .fwmap-details-head { display: flex; justify-content: space-between; }
    .fwmap-details-head a { font-size: 1.3em; line-height: 1; text-decoration: none; }
    .fwmap-address { margin-top: 6px; }
    .fwmap-summary { font-weight: 600; }
    .fwmap-ids { margin-top: 2px; color: rgb(200, 110, 0); }
    .fwmap-sec { margin-top: 8px; }
    .fwmap-sec-title { font-size: .75em; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; opacity: .7;
        border-bottom: 1px solid rgba(128, 128, 128, .25); margin-bottom: 3px; padding-bottom: 1px; }
    .fwmap-sig { margin-bottom: 4px; }
    .fwmap-ids-high { color: rgb(196, 18, 48); font-weight: 600; }
    .fwmap-verdict { margin: 4px 0; padding: 3px 8px; border-radius: 3px; font-weight: 600; }
    .fwmap-verdict-allowed { background: rgba(46, 139, 87, .14); color: rgb(30, 110, 65); }
    .fwmap-verdict-danger { background: rgb(196, 18, 48); color: #fff; }
    .fwmap-verdict-blocked { background: rgba(128, 128, 128, .16); }
    .fwmap-links { font-size: .85em; }
    .fwmap-empty { padding: 6px 2px; }
    .fwmap-investigation { margin: 4px 0 8px; padding: 6px 8px; border-left: 3px solid rgba(128, 128, 128, .35); }
    .fwmap-inv-section { margin-bottom: 6px; }
    .fwmap-inv-title { font-weight: 600; font-size: .9em; text-transform: uppercase; letter-spacing: .03em; opacity: .75; }
    .fwmap-inv-table { width: 100%; font-size: .9em; }
    .fwmap-inv-table th { font-weight: normal; opacity: .7; padding-right: 8px; vertical-align: top; white-space: nowrap; width: 1%; }
    .fwmap-inv-table td { word-break: break-word; }
    .fwmap-score { color: #fff; border-radius: 3px; padding: 0 6px; font-weight: 600; }
    .fwmap-feed { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 6px 0;
        border-bottom: 1px solid rgba(128, 128, 128, .2); }
    #fwmap-review-count:empty { display: none; }
    #fwmap-review-count { background: rgb(196, 18, 48); }
    .fwmap-q-dialog .modal-title .fwmap-q-subtitle { font-size: .8em; font-weight: normal; opacity: .85; margin-left: 4px; }
    .fwmap-q-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }
    .fwmap-q-tabs { flex: 1 1 auto; margin: 0; }
    .fwmap-q-tabs > li > a { padding: 5px 12px; }
    .fwmap-q-tabs .badge { margin-left: 4px; }
    .fwmap-q-search { width: 260px; max-width: 100%; }
    .fwmap-q-list { max-height: 62vh; overflow-y: auto; margin: 0 -4px; padding: 0 4px; }
    .fwmap-q-item { padding: 10px 12px; margin: 8px 0; border: 1px solid rgba(128, 128, 128, .22);
        border-left: 4px solid rgb(196, 18, 48); border-radius: 4px; }
    .fwmap-q-item.fwmap-q-reviewed { border-left-color: rgb(46, 139, 87); }
    .fwmap-q-item.fwmap-q-dismissed { border-left-color: rgba(128, 128, 128, .6); opacity: .85; }
    .fwmap-q-item.fwmap-q-blocked { border-left-color: rgb(70, 70, 70); }
    .fwmap-q-head { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; }
    .fwmap-q-ip { font-family: SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; font-size: 1.05em; }
    .fwmap-q-status-pill { font-size: .7em; font-weight: 600; letter-spacing: .05em; text-transform: uppercase;
        padding: 1px 7px; border-radius: 9px; background: rgba(128, 128, 128, .18); }
    .fwmap-q-new .fwmap-q-status-pill { background: rgb(196, 18, 48); color: #fff; }
    .fwmap-q-dir { font-size: .85em; font-weight: 600; }
    .fwmap-q-in { color: rgb(200, 110, 0); }
    .fwmap-q-out { color: rgb(46, 139, 87); }
    .fwmap-q-seen { margin-left: auto; font-size: .85em; opacity: .7; white-space: nowrap; }
    .fwmap-q-summary { margin-top: 4px; line-height: 1.4; }
    .fwmap-q-chips { margin-top: 5px; }
    .fwmap-q-chip { display: inline-block; font-size: .75em; font-weight: 600; margin: 0 4px 3px 0; padding: 1px 7px;
        border-radius: 3px; color: rgb(196, 18, 48); border: 1px solid rgba(196, 18, 48, .45); }
    .fwmap-q-meta { display: flex; flex-wrap: wrap; gap: 2px 14px; font-size: .85em; opacity: .7; margin-top: 2px; }
    .fwmap-q-meta .fa, .fwmap-q-tools .fa { width: 1.1em; text-align: center; }
    .fwmap-q-warning { margin-top: 5px; color: rgb(196, 18, 48); font-weight: 600; }
    .fwmap-q-note { white-space: pre-wrap; margin-top: 6px; padding: 4px 8px; border-left: 3px solid rgba(128, 128, 128, .35);
        background: rgba(128, 128, 128, .07); }
    .fwmap-q-actions { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 6px; margin-top: 8px; }
    .fwmap-q-tools { display: flex; flex-wrap: wrap; gap: 2px 12px; font-size: .9em; }
    .fwmap-q-decisions { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
    .fwmap-q-decisions .btn { margin: 0; line-height: 1.5; }
    .fwmap-q-footer { float: left; display: flex; flex-wrap: wrap; align-items: center; gap: 4px 18px; text-align: left;
        font-size: .9em; padding-top: 6px; }
    .fwmap-q-record { font-weight: normal; margin: 0; }
    .fwmap-q-source { opacity: .75; }

    /* details panel: header, connection diagram, four cards, action bar */
    .fwmap-d-head { display: flex; align-items: flex-start; gap: 10px; }
    .fwmap-d-icon { font-size: 1.9em; opacity: .75; margin-top: 2px; }
    .fwmap-d-title { flex: 1; min-width: 0; }
    .fwmap-d-name { font-size: 1.25em; font-weight: 600; line-height: 1.2; overflow-wrap: anywhere; }
    .fwmap-d-sub { font-size: .85em; opacity: .75; }
    .fwmap-d-verdict { text-align: right; max-width: 45%; }
    .fwmap-d-verdict .fwmap-d-sub { white-space: normal; }
    #fwmap-details-close { font-size: 1.4em; line-height: 1; text-decoration: none; margin-left: 4px; }
    .fwmap-pill { display: inline-block; font-size: .8em; font-weight: 600; padding: 2px 9px; border-radius: 10px; white-space: nowrap; }
    .fwmap-pill-ok { background: rgba(46, 139, 87, .15); color: rgb(30, 110, 65); }
    .fwmap-pill-danger { background: rgb(196, 18, 48); color: #fff; }
    .fwmap-pill-warning { background: rgba(230, 140, 0, .18); color: rgb(170, 95, 0); }
    .fwmap-pill-blocked { background: rgba(90, 90, 90, .85); color: #fff; }
    .fwmap-pill-muted { background: rgba(128, 128, 128, .18); }
    .fwmap-picker { margin: 6px 0 0; font-size: .85em; display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: center; }
    .fwmap-pick { padding: 0 6px; border-radius: 8px; }
    .fwmap-pick.active { background: rgba(128, 128, 128, .2); font-weight: 600; }
    .fwmap-diagram { display: flex; align-items: stretch; gap: 8px; margin: 10px 0 4px; }
    .fwmap-end { flex: 1 1 0; min-width: 0; text-align: center; padding: 8px 6px; border-radius: 6px;
        background: rgba(128, 128, 128, .09); border: 1px solid rgba(128, 128, 128, .18); }
    .fwmap-end .fa { font-size: 1.5em; opacity: .7; }
    .fwmap-end-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fwmap-end-sub { font-size: .8em; opacity: .75; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fwmap-link { flex: 0 0 34%; display: flex; flex-direction: column; justify-content: center; text-align: center; font-size: .85em; }
    .fwmap-link-service { font-weight: 600; }
    .fwmap-link-port { opacity: .75; }
    .fwmap-link-arrow { position: relative; height: 12px; margin: 2px 6px; }
    .fwmap-link-arrow::before { content: ""; position: absolute; left: 0; right: 6px; top: 5px; border-top: 1.5px solid currentColor; opacity: .7; }
    .fwmap-link-arrow::after { content: ""; position: absolute; right: 0; top: 1px; border: 5px solid transparent; border-left: 7px solid currentColor; opacity: .7; }
    .fwmap-link-blocked .fwmap-link-arrow .fa { position: relative; z-index: 1; color: rgb(196, 18, 48); background: inherit; }
    .fwmap-link-rate { opacity: .75; }
    .fwmap-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin-top: 8px; }
    .fwmap-card { border: 1px solid rgba(128, 128, 128, .22); border-radius: 6px; padding: 6px 8px; min-width: 0; }
    .fwmap-card-title { font-weight: 600; margin-bottom: 4px; }
    .fwmap-card-title .fa { width: 1.2em; text-align: center; color: rgb(200, 90, 40); }
    .fwmap-card-note { font-size: .8em; margin-bottom: 3px; }
    .fwmap-kv { width: 100%; font-size: .88em; }
    .fwmap-kv th { font-weight: normal; opacity: .7; padding: 1px 8px 1px 0; vertical-align: top; white-space: nowrap; width: 1%; }
    .fwmap-kv td { padding: 1px 0; overflow-wrap: anywhere; }
    .fwmap-two { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 2px 10px; }
    .fwmap-empty-note { font-size: .88em; padding: 4px 6px; border-radius: 4px; background: rgba(128, 128, 128, .07); }
    .fwmap-empty-note .fa-check { color: rgb(46, 139, 87); }
    .fwmap-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
    .fwmap-actions .btn-group { margin-left: auto; }
    @media (max-width: 1100px) {
        #fwmap-layout { flex-direction: column; }
        #fwmap-split-side { display: none; }
        #fwmap-side { width: auto; flex: none; height: auto; }
    }
</style>

<script>
    window.FirewallMapPageText = {
        firewall_map: "{{ lang._('Firewall Map') }}",
        active_flows: "{{ lang._('active flows') }}",
        blocked_sources: "{{ lang._('blocked sources') }}",
        below_threshold: "{{ lang._('below threshold') }}",
        listed_flows: "{{ lang._('to listed addresses') }}",
        no_flows: "{{ lang._('No active public flows') }}",
        starting: "{{ lang._('Starting flow collector…') }}",
        unavailable: "{{ lang._('Live flow data is unavailable') }}",
        webgl: "{{ lang._('WebGL is required for Firewall Map+') }}",
        renderer_failed: "{{ lang._('Map renderer failed to initialise') }}",
        carp_backup: "{{ lang._('CARP backup: traffic is passing through the master') }}",
        key_missing: "{{ lang._('A MaxMind license key is needed: add it in the Firewall Map widget settings or in the GeoIP alias settings, or choose DB-IP Lite') }}",
        downloading: "{{ lang._('Downloading the geolocation database…') }}",
        database_failed: "{{ lang._('Geolocation database download failed') }}",
        all_services: "{{ lang._('All services') }}",
        all_interfaces: "{{ lang._('All interfaces') }}",
        all_hosts: "{{ lang._('All inside hosts') }}",
        all_countries: "{{ lang._('All countries') }}",
        no_talkers: "{{ lang._('No traffic yet') }}",
        filter_hint: "{{ lang._('Show only this on the map') }}",
        click_hint: "{{ lang._('Click an endpoint or arc on the map for details and actions.') }}",
        verdict_allowed: "{{ lang._('Allowed: the firewall let this traffic through') }}",
        verdict_allowed_flagged: "{{ lang._('Allowed: flagged traffic got through the firewall') }}",
        verdict_ids: "{{ lang._('Seen by Suricata: no connection is open right now') }}",
        ids_flow: "{{ lang._('IDS flow') }}",
        ids_flows: "{{ lang._('IDS flows') }}",
        ids_address: "{{ lang._('IDS address') }}",
        ids_addresses: "{{ lang._('IDS addresses') }}",
        sec_connection: "{{ lang._('Connection') }}",
        sec_firewall: "{{ lang._('Firewall') }}",
        sec_ids: "{{ lang._('IDS') }}",
        sec_reputation: "{{ lang._('Reputation') }}",
        path: "{{ lang._('Path') }}",
        started_by: "{{ lang._('Started') }}",
        started_inside: "{{ lang._('inside') }}",
        started_outside: "{{ lang._('outside') }}",
        via: "{{ lang._('Public side') }}",
        open_for: "{{ lang._('open, started') }}",
        closed: "{{ lang._('closed') }}",
        transferred: "{{ lang._('Transferred') }}",
        decision: "{{ lang._('Decision') }}",
        allowed: "{{ lang._('Allowed') }}",
        rule: "{{ lang._('Rule') }}",
        severity: "{{ lang._('Severity') }}",
        ips_dropped: "{{ lang._('dropped by IPS') }}",
        not_listed: "{{ lang._('Not on any configured list') }}",
        verdict_blocked: "{{ lang._('Blocked: the firewall dropped this traffic') }}",
        remote_addresses: "{{ lang._('remote addresses') }}",
        inside_hosts: "{{ lang._('Inside hosts') }}",
        copy: "{{ lang._('Copy') }}",
        whois: "{{ lang._('Whois') }}",
        show_states: "{{ lang._('States') }}",
        kill_states: "{{ lang._('Kill states') }}",
        add_to_alias: "{{ lang._('Add to alias') }}",
        add_country: "{{ lang._('Add country to GeoIP alias') }}",
        close: "{{ lang._('Close') }}",
        confirm: "{{ lang._('Confirm') }}",
        cancel: "{{ lang._('Cancel') }}",
        kill_confirm: "{{ lang._('Kill all firewall states involving') }}",
        kill_scope: "{{ lang._('This ends the connections of every inside host to this address, and any traffic routed through it.') }}",
        listed_in: "{{ lang._('Listed in') }}",
        killed: "{{ lang._('States killed:') }}",
        add_confirm: "{{ lang._('Add') }}",
        no_aliases: "{{ lang._('No suitable alias exists yet. Create one under Firewall ▸ Aliases first.') }}",
        action_failed: "{{ lang._('The action failed') }}",
        states_for: "{{ lang._('States for') }}",
        no_states: "{{ lang._('No states found.') }}",
        more_states: "{{ lang._('Only the first 100 states are shown.') }}",
        interface: "{{ lang._('Interface') }}",
        protocol: "{{ lang._('Protocol') }}",
        source: "{{ lang._('Source') }}",
        destination: "{{ lang._('Destination') }}",
        state: "{{ lang._('State') }}",
        bytes: "{{ lang._('Bytes') }}",
        investigate: "{{ lang._('Investigate') }}",
        looking_up: "{{ lang._('Looking up registry, routing and reputation…') }}",
        lookup_failed: "{{ lang._('Lookup failed') }}",
        registry: "{{ lang._('Registry (RDAP)') }}",
        routing: "{{ lang._('Routing (RIPEstat)') }}",
        owner: "{{ lang._('Owner') }}",
        network: "{{ lang._('Network') }}",
        range: "{{ lang._('Range') }}",
        country: "{{ lang._('Country') }}",
        abuse_contact: "{{ lang._('Abuse contact') }}",
        registered: "{{ lang._('Registered') }}",
        updated: "{{ lang._('updated') }}",
        prefix: "{{ lang._('Prefix') }}",
        origin_as: "{{ lang._('Origin AS') }}",
        announced: "{{ lang._('Announced') }}",
        yes: "{{ lang._('yes') }}",
        no: "{{ lang._('no') }}",
        confidence: "{{ lang._('Abuse confidence') }}",
        reports: "{{ lang._('Reports (90 days)') }}",
        reporters: "{{ lang._('reporters') }}",
        last_reported: "{{ lang._('Last reported') }}",
        usage: "{{ lang._('Usage') }}",
        abuseipdb_hint: "{{ lang._('Add an AbuseIPDB API key in the Firewall Map widget settings to see abuse reports here.') }}",
        mark_threat: "{{ lang._('Mark as threat') }}",
        mark_confirm: "{{ lang._('Add') }}",
        mark_scope: "{{ lang._('to the FWMAP_Watchlist alias? The map will flag its traffic as a threat. No firewall rule is added.') }}",
        marked: "{{ lang._('Its traffic is flagged on the map within five minutes.') }}",
        inbound: "{{ lang._('Inbound') }}",
        inbound_outbound: "{{ lang._('Inbound and outbound') }}",
        outbound: "{{ lang._('Outbound') }}",
        this_firewall: "{{ lang._('this firewall') }}",
        to: "{{ lang._('to') }}",
        blacklist: "{{ lang._('AbuseIPDB blacklist (downloaded daily)') }}",
        blacklist_addresses: "{{ lang._('addresses') }}",
        blacklist_pending: "{{ lang._('Not downloaded yet') }}",
        blacklist_error: "{{ lang._('last attempt failed') }}",
        blacklist_no_key: "{{ lang._('Add an AbuseIPDB API key in the Firewall Map widget settings to download it.') }}",
        active: "{{ lang._('Active') }}",
        allowed_flagged: "{{ lang._('Allowed · flagged') }}",
        attempts: "{{ lang._('Attempts') }}",
        blocked: "{{ lang._('Blocked') }}",
        blocked_attempts: "{{ lang._('Blocked attempts') }}",
        clean: "{{ lang._('Clean') }}",
        connections: "{{ lang._('Connections') }}",
        current_rate: "{{ lang._('Current rate') }}",
        egress: "{{ lang._('Egress') }}",
        idle: "{{ lang._('Idle') }}",
        ids_on_address: "{{ lang._('Alerts on this address in the last hour (not necessarily this traffic)') }}",
        ids_on_connection: "{{ lang._('Alerts raised by this exact connection') }}",
        ids_only: "{{ lang._('Seen by Suricata') }}",
        ids_only_sub: "{{ lang._('No open connection') }}",
        in_minutes: "{{ lang._('in %s min') }}",
        inside_side: "{{ lang._('Inside side') }}",
        listed: "{{ lang._('Listed') }}",
        more: "{{ lang._('More') }}",
        no_connection: "{{ lang._('No connection is open right now.') }}",
        no_ids: "{{ lang._('No IDS alerts for this address') }}",
        no_ids_sub: "{{ lang._('Suricata has not alerted on this address in the last hour.') }}",
        no_ids_talkers: "{{ lang._('No Suricata alerts in the last hour') }}",
        select_hint: "{{ lang._('Show the details') }}",
        flow_one: "{{ lang._('flow') }}",
        flow_many: "{{ lang._('flows') }}",
        not_checked: "{{ lang._('not checked') }}",
        organization: "{{ lang._('Organization') }}",
        other_ports: "{{ lang._('Other ports') }}",
        other_services: "{{ lang._('Other services') }}",
        port_forward: "{{ lang._('Port forward') }}",
        remote_addresses_here: "{{ lang._('addresses here:') }}",
        remote_side: "{{ lang._('Remote side') }}",
        sec_ids_long: "{{ lang._('IDS (Suricata)') }}",
        started: "{{ lang._('Started') }}",
        started_inside_long: "{{ lang._('Started inside') }}",
        started_outside_long: "{{ lang._('Started outside') }}",
        target: "{{ lang._('Target') }}",
        this_firewall_title: "{{ lang._('This firewall') }}",
        tried: "{{ lang._('Tried') }}",
        review_queue: "{{ lang._('Review queue') }}",
        review_intro: "{{ lang._('Allowed traffic to or from flagged addresses') }}",
        record_threats: "{{ lang._('Record in the background') }}",
        record_threats_hint: "{{ lang._('Keep recording while the map is closed, as long as the widget is on a dashboard. Setting a status never changes firewall rules.') }}",
        queue_search: "{{ lang._('Filter by address, network, list, host…') }}",
        ago: "{{ lang._('ago') }}",
        blacklist_short: "{{ lang._('AbuseIPDB blacklist') }}",
        status_new: "{{ lang._('New') }}",
        status_reviewed: "{{ lang._('Reviewed') }}",
        status_dismissed: "{{ lang._('Dismissed') }}",
        status_blocked: "{{ lang._('Blocked') }}",
        status_all: "{{ lang._('All') }}",
        mark_reviewed: "{{ lang._('Mark reviewed') }}",
        dismiss: "{{ lang._('Dismiss') }}",
        reopen: "{{ lang._('Reopen') }}",
        block: "{{ lang._('Block…') }}",
        block_title: "{{ lang._('Add to a blocking alias') }}",
        block_hint: "{{ lang._('The address is added to the alias you choose. It is blocked only if a firewall rule uses that alias.') }}",
        edit_note: "{{ lang._('Note') }}",
        note_title: "{{ lang._('Note for') }}",
        save: "{{ lang._('Save') }}",
        first_seen: "{{ lang._('First seen') }}",
        last_seen: "{{ lang._('Last seen') }}",
        samples: "{{ lang._('samples') }}",
        peak: "{{ lang._('peak') }}",
        inside_host: "{{ lang._('inside') }}",
        from: "{{ lang._('from') }}",
        seen_after_block: "{{ lang._('Traffic was seen after it was marked blocked: check that a rule uses the alias.') }}",
        queue_empty: "{{ lang._('Nothing here.') }}",
    };
</script>
<script src="/ui/js/firewall-map-renderer.js?v={{ rendererVersion }}"></script>
<script src="/ui/js/firewall-map-page.js?v={{ pageVersion }}"></script>

<div class="content-box" style="padding: 12px;">
    <div id="fwmap-toolbar">
        <label for="fwmap-color">{{ lang._('Colour') }}</label>
        <select id="fwmap-color" class="form-control">
            <option value="initiator">{{ lang._('By who connected') }}</option>
            <option value="direction">{{ lang._('By data direction') }}</option>
            <option value="egress">{{ lang._('By egress') }}</option>
            <option value="service">{{ lang._('By service') }}</option>
        </select>
        <label for="fwmap-filter-traffic">{{ lang._('Show') }}</label>
        <select id="fwmap-filter-traffic" class="form-control">
            <option value="all">{{ lang._('All traffic') }}</option>
            <option value="permitted">{{ lang._('Permitted') }}</option>
            <option value="blocked">{{ lang._('Blocked') }}</option>
            <option value="threats">{{ lang._('Threats that got through') }}</option>
            <option value="ids">{{ lang._('IDS alerts') }}</option>
        </select>
        <select id="fwmap-filter-service" class="form-control"></select>
        <select id="fwmap-filter-iface" class="form-control"></select>
        <select id="fwmap-filter-host" class="form-control"></select>
        <select id="fwmap-filter-country" class="form-control"></select>
        <span id="fwmap-filter-asn" class="label label-default">
            <span></span> <a href="#" style="color:inherit" title="{{ lang._('Remove') }}">&times;</a>
        </span>
        <button id="fwmap-reset" class="btn btn-default btn-sm" type="button">{{ lang._('Reset filters') }}</button>
        <button id="fwmap-review" class="btn btn-default btn-sm" type="button" style="display:none; margin-left:auto">
            <i class="fa fa-list-alt"></i> {{ lang._('Review queue') }} <span class="badge" id="fwmap-review-count"></span>
        </button>
    </div>
    <div id="fwmap-layout">
        <div id="fwmap-map">
            <div id="fwmap-grid" aria-hidden="true"></div>
            <div id="fwmap-canvas"></div>
            <div id="fwmap-legend"></div>
            <div id="fwmap-status"></div>
            <div id="fwmap-credit"></div>
        </div>
        <div class="fwmap-splitter fwmap-splitter-v" id="fwmap-split-side" title="{{ lang._('Drag to resize, double-click to reset') }}"></div>
        <div id="fwmap-side">
            <div id="fwmap-talkers">
                <ul class="nav nav-tabs">
                    <li class="active"><a href="#" data-tab="hosts">{{ lang._('Hosts') }}</a></li>
                    <li><a href="#" data-tab="countries">{{ lang._('Countries') }}</a></li>
                    <li><a href="#" data-tab="networks">{{ lang._('Networks') }}</a></li>
                    <li><a href="#" data-tab="ids">{{ lang._('IDS') }}</a></li>
                </ul>
                <div id="fwmap-talkers-list"></div>
            </div>
            <div class="fwmap-splitter fwmap-splitter-h" id="fwmap-split-details" title="{{ lang._('Drag to resize, double-click to reset') }}"></div>
            <div id="fwmap-details-box">
                <div id="fwmap-details"></div>
            </div>
        </div>
    </div>
</div>
