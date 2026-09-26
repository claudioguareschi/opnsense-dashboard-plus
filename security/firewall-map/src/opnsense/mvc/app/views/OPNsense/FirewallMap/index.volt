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
    #firewallmap-page {
        position: relative;
        height: calc(100vh - 170px);
        min-height: 420px;
        overflow: hidden;
        border-radius: 6px;
    }
    #firewallmap-page-grid {
        pointer-events: none;
        position: absolute;
        inset: 0;
        z-index: 0;
        background-size: 48px 48px;
    }
    #firewallmap-page-canvas {
        position: absolute;
        inset: 0;
        z-index: 1;
        text-align: left;
    }
    #firewallmap-page-status, #firewallmap-page-credit {
        position: absolute;
        bottom: 10px;
        z-index: 2;
        font-size: .85em;
    }
    #firewallmap-page-status { left: 14px; pointer-events: none; }
    #firewallmap-page-credit { right: 12px; opacity: .7; }
</style>

<script src="{{ cache_safe('/ui/js/firewall-map-renderer.js') }}"></script>
<script>
    $(async function () {
        const text = {
            active_flows: "{{ lang._('active flows') }}",
            no_flows: "{{ lang._('No active public flows') }}",
            starting: "{{ lang._('Starting flow collector…') }}",
            unavailable: "{{ lang._('Live flow data is unavailable') }}",
            webgl: "{{ lang._('WebGL is required for Firewall Map+') }}",
            renderer_failed: "{{ lang._('Map renderer failed to initialise') }}",
            carp_backup: "{{ lang._('CARP backup: traffic is passing through the master') }}",
            key_missing: "{{ lang._('A MaxMind license key is needed: add it in the Firewall Map widget settings or in the GeoIP alias settings, or choose DB-IP Lite') }}",
            downloading: "{{ lang._('Downloading the geolocation database…') }}",
        };
        const $map = $('#firewallmap-page');
        const status = (message) => $('#firewallmap-page-status').text(message || '');

        const canvas = document.createElement('canvas');
        if (!(canvas.getContext('webgl2') || canvas.getContext('webgl'))) {
            status(text.webgl);
            return;
        }

        // same per-user settings as the dashboard widget
        let config = {};
        try {
            const dashboard = await $.getJSON('/api/core/dashboard/getDashboard');
            config = (dashboard.dashboard?.widgets || []).find((widget) => widget.id === 'firewallmap')?.widget || {};
        } catch (error) {
            console.error('Firewall Map+: dashboard settings unavailable', error);
        }
        const settings = {
            heavyTop: parseInt(config.heavy_top ?? '5', 10),
            heavyRate: parseInt(config.heavy_rate ?? '1000000', 10),
            maxArcs: parseInt(config.max_arcs ?? '150', 10),
            labels: config.labels !== '0',
            hostnames: config.hostnames === '1',
            asn: config.asn !== '0',
        };

        let renderer;
        try {
            const theme = FirewallMapRenderer.readTheme($map[0]);
            const rgba = (color, alpha) => `rgba(${color.join(', ')}, ${alpha})`;
            $map.css({
                background: `rgb(${theme.background.join(', ')})`,
                boxShadow: `inset 0 0 0 1px ${rgba(theme.accent, theme.dark ? 0.3 : 0.18)}`,
            });
            const line = rgba(theme.text, theme.dark ? 0.07 : 0.05);
            $('#firewallmap-page-grid').css('background-image',
                `linear-gradient(${line} 1px, transparent 1px), linear-gradient(90deg, ${line} 1px, transparent 1px)`);
            $('#firewallmap-page-status').css('color', rgba(theme.text, 0.75));
            const container = document.getElementById('firewallmap-page-canvas');
            renderer = FirewallMapRenderer.create(container, {theme, settings});
            $(container).children('canvas').css({left: 0, top: 0});
        } catch (error) {
            console.error('Firewall Map+: renderer initialisation failed', error);
            status(`${text.renderer_failed}: ${error?.message || error}`);
            return;
        }

        $(window).on('resize', () => renderer.resize());

        const query = settings.hostnames ? '?hostnames=1' : '';
        const tick = async () => {
            try {
                const snapshot = await $.getJSON(`/api/firewallmap/flow/snapshot${query}`);
                if (snapshot.status === 'starting') {
                    status(text.starting);
                } else if (snapshot.status === 'no_database') {
                    renderer.render({flows: [], locations: []});
                    status(snapshot.reason === 'maxmind_key_missing' ? text.key_missing : text.downloading);
                } else if (snapshot.status !== 'ok') {
                    status(text.unavailable);
                } else {
                    renderer.render(snapshot);
                    $('#firewallmap-page-credit').html(snapshot.provider === 'dbip'
                        ? '<a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>' : '');
                    const count = snapshot.flows?.length || 0;
                    let message = count ? `${count} ${text.active_flows}` : text.no_flows;
                    if (snapshot.carp === 'backup') {
                        message += ` · ${text.carp_backup}`;
                    }
                    status(message);
                }
            } catch (error) {
                console.error('Firewall Map+: flow update failed', error);
                status(text.unavailable);
            }
            setTimeout(tick, 2000);
        };
        tick();
    });
</script>

<div class="content-box" style="padding: 12px;">
    <div id="firewallmap-page">
        <div id="firewallmap-page-grid" aria-hidden="true"></div>
        <div id="firewallmap-page-canvas"></div>
        <div id="firewallmap-page-status"></div>
        <div id="firewallmap-page-credit"></div>
    </div>
</div>
