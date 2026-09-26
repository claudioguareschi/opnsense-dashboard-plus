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
    #fwmap-layout { display: flex; gap: 12px; }
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
    #fwmap-side { width: 320px; flex: 0 0 320px; display: flex; flex-direction: column; gap: 12px;
        height: calc(100vh - 280px); min-height: 420px; }
    #fwmap-talkers, #fwmap-details-box { border: 1px solid rgba(128, 128, 128, .25); border-radius: 6px; padding: 8px; }
    #fwmap-talkers { flex: 1 1 60%; overflow-y: auto; min-height: 0; }
    #fwmap-details-box { flex: 1 1 40%; overflow-y: auto; min-height: 0; }
    #fwmap-talkers .nav { margin-bottom: 6px; }
    #fwmap-talkers .nav > li > a { padding: 4px 10px; }
    .fwmap-talker { display: flex; align-items: center; gap: 8px; padding: 3px 2px; cursor: pointer; border-radius: 4px; }
    .fwmap-talker:hover { background: rgba(128, 128, 128, .12); }
    .fwmap-talker-text { flex: 1; min-width: 0; }
    .fwmap-talker-label, .fwmap-talker-sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .fwmap-talker-sub { font-size: .8em; opacity: .7; }
    .fwmap-talker-rate { width: 70px; text-align: right; font-size: .85em; }
    .fwmap-details-head { display: flex; justify-content: space-between; }
    .fwmap-details-head a { font-size: 1.3em; line-height: 1; text-decoration: none; }
    .fwmap-address { margin-top: 6px; }
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
    @media (max-width: 1100px) {
        #fwmap-layout { flex-direction: column; }
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
        remote_endpoints: "{{ lang._('Remote endpoints') }}",
        blocked_source: "{{ lang._('Blocked source') }}",
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
        threat_feeds: "{{ lang._('Threat feeds') }}",
        add_feed: "{{ lang._('Add') }}",
        feed_added: "{{ lang._('Added') }}",
        mark_threat: "{{ lang._('Mark as threat') }}",
        mark_confirm: "{{ lang._('Add') }}",
        mark_scope: "{{ lang._('to the FWMAP_Watchlist alias? The map will flag its traffic as a threat. No firewall rule is added.') }}",
        marked: "{{ lang._('Its traffic is flagged on the map within five minutes.') }}",
        inbound: "{{ lang._('Inbound') }}",
        inbound_outbound: "{{ lang._('Inbound and outbound') }}",
        outbound: "{{ lang._('Outbound') }}",
        to: "{{ lang._('to') }}",
        blacklist: "{{ lang._('AbuseIPDB blacklist (downloaded daily)') }}",
        blacklist_addresses: "{{ lang._('addresses') }}",
        blacklist_pending: "{{ lang._('Not downloaded yet') }}",
        blacklist_error: "{{ lang._('last attempt failed') }}",
        blacklist_no_key: "{{ lang._('Add an AbuseIPDB API key in the Firewall Map widget settings to download it.') }}",
        feeds_note: "{{ lang._('Each feed becomes a URL table alias refreshed daily. It marks matching traffic on the map only; no firewall rules are added.') }}",
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
            <option value="threats">{{ lang._('Threats') }}</option>
        </select>
        <select id="fwmap-filter-service" class="form-control"></select>
        <select id="fwmap-filter-iface" class="form-control"></select>
        <select id="fwmap-filter-host" class="form-control"></select>
        <select id="fwmap-filter-country" class="form-control"></select>
        <span id="fwmap-filter-asn" class="label label-default">
            <span></span> <a href="#" style="color:inherit" title="{{ lang._('Remove') }}">&times;</a>
        </span>
        <button id="fwmap-reset" class="btn btn-default btn-sm" type="button">{{ lang._('Reset filters') }}</button>
        <button id="fwmap-feeds" class="btn btn-default btn-sm" type="button" style="display:none; margin-left:auto">
            <i class="fa fa-shield"></i> {{ lang._('Threat feeds') }}
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
        <div id="fwmap-side">
            <div id="fwmap-talkers">
                <ul class="nav nav-tabs">
                    <li class="active"><a href="#" data-tab="hosts">{{ lang._('Hosts') }}</a></li>
                    <li><a href="#" data-tab="countries">{{ lang._('Countries') }}</a></li>
                    <li><a href="#" data-tab="networks">{{ lang._('Networks') }}</a></li>
                </ul>
                <div id="fwmap-talkers-list"></div>
            </div>
            <div id="fwmap-details-box">
                <div id="fwmap-details"></div>
            </div>
        </div>
    </div>
</div>
