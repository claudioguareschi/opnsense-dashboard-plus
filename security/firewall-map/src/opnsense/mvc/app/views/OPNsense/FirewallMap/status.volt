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

<script>
    $(document).ready(function () {
        const T = {
            running_live: "{{ lang._('Running: a map is open') }}",
            running_background: "{{ lang._('Running: recording threats in the background') }}",
            stopped: "{{ lang._('Stopped: starts when a map is opened') }}",
            recording_on: "{{ lang._('On') }}",
            recording_no_widget: "{{ lang._('On, but no dashboard has the Firewall Map widget') }}",
            recording_off: "{{ lang._('Off') }}",
            never: "{{ lang._('never') }}",
            ago: "{{ lang._('%s ago') }}",
            in: "{{ lang._('in %s') }}",
            built: "{{ lang._('built %s') }}",
            missing: "{{ lang._('not downloaded') }}",
            downloading: "{{ lang._('Downloading…') }}",
            ok: "{{ lang._('OK') }}",
            not_in_use: "{{ lang._('not in use') }}",
            no_key: "{{ lang._('No AbuseIPDB API key') }}",
            key_plugin: "{{ lang._('Stored in the Firewall Map settings') }}",
            key_alias: "{{ lang._('Taken from the GeoIP alias') }}",
            key_none: "{{ lang._('None') }}",
            key_unused: "{{ lang._('Not needed') }}",
            entries: "{{ lang._('%s entries') }}",
            started: "{{ lang._('Download started') }}",
            standin: "{{ lang._('%s standing in while the download fails') }}",
        };
        const PROVIDERS = {
            auto: "{{ lang._('Automatic') }}", maxmind: 'MaxMind GeoLite2', maxmind_paid: 'MaxMind GeoIP2 City', dbip: 'DB-IP Lite',
        };
        const escape = (text) => $('<div/>').text(text === null || text === undefined ? '' : String(text)).html();
        const duration = (seconds) => {
            seconds = Math.abs(seconds);
            if (seconds < 90) return `${Math.round(seconds)} s`;
            if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
            if (seconds < 172800) return `${Math.round(seconds / 3600)} h`;
            return `${Math.round(seconds / 86400)} days`;
        };
        const toEpoch = (value) => (typeof value === 'number' ? value : value ? Date.parse(value) / 1000 : null);
        const when = (value, now) => {
            const epoch = toEpoch(value);
            if (!epoch) return escape(T.never);
            const text = epoch > now ? T.in.replace('%s', duration(epoch - now)) : T.ago.replace('%s', duration(now - epoch));
            return `<span title="${escape(new Date(epoch * 1000).toLocaleString())}">${escape(text)}</span>`;
        };
        const megabytes = (bytes) => `${(bytes / 1048576).toFixed(1)} MB`;
        const state = (error, text = T.ok) => error
            ? `<span class="text-danger"><i class="fa fa-triangle-exclamation fa-fw"></i> ${escape(error)}</span>`
            : `<span class="text-success"><i class="fa fa-circle-check fa-fw"></i> ${escape(text)}</span>`;

        const render = function (data) {
            const now = data.now || Date.now() / 1000;
            const c = data.collector || {};
            $('#collector-status').html(c.running
                ? state(null, c.mode === 'live' ? T.running_live : T.running_background)
                : `<span class="text-muted"><i class="fa fa-circle-stop fa-fw"></i> ${escape(T.stopped)}</span>`);
            $('#collector-update').html(when(c.last_map_update, now));
            $('#collector-recording').text(!c.recording ? T.recording_off : c.widget_in_use ? T.recording_on : T.recording_no_widget);

            const db = data.database || {};
            const provider = PROVIDERS[db.provider] || db.provider || '';
            const active = db.standin ? ` (${T.standin.replace('%s', PROVIDERS[db.active_provider] || db.active_provider)})`
                : db.active_provider && db.active_provider !== db.provider && db.provider !== 'auto'
                ? ` (${PROVIDERS[db.active_provider] || db.active_provider})` : '';
            $('#geo-provider').text(provider + active);
            $('#geo-key').text(!db.key_required ? T.key_unused
                : db.key_source === 'plugin' ? T.key_plugin : db.key_source === 'alias' ? T.key_alias : T.key_none);
            for (const kind of ['city', 'asn']) {
                const file = db[kind];
                $(`#geo-${kind}`).html(file
                    ? `${escape(file.edition || '')} · ${when(file.updated_at, now)} · ${escape(megabytes(file.size))}`
                      + (file.built ? ` <span class="text-muted">(${escape(T.built.replace('%s', new Date(file.built * 1000).toLocaleDateString()))})</span>` : '')
                    : `<span class="text-danger">${escape(T.missing)}</span>`);
            }
            const newest = Math.min(...['city', 'asn'].map((kind) => toEpoch(db[kind]?.updated_at) || 0));
            $('#geo-next').html(db.next_retry ? when(db.next_retry, now)
                : newest ? when(newest + (db.update_days || 3) * 86400, now) : escape(T.never));
            $('#geo-state').html(db.state === 'downloading' ? `<i class="fa fa-spinner fa-pulse fa-fw"></i> ${escape(T.downloading)}`
                : state((db.errors || []).map((error) => error.message).join('; ') || db.last_error));

            $('#feeds').html((data.feeds || []).map((feed) => `<tr${feed.in_use ? '' : ' class="text-muted"'}>
                <td>${escape(feed.label)}<br><small class="text-muted">${escape(feed.name)}</small></td>
                <td>${feed.count !== null && feed.count !== undefined ? escape(Number(feed.count).toLocaleString()) : '—'}</td>
                <td>${feed.updated ? when(feed.updated, now) : '—'}</td>
                <td>${feed.in_use ? state(feed.error) : escape(T.not_in_use)}</td></tr>`).join(''));

            const abuse = data.abuseipdb || {};
            $('#abuse-count').text(abuse.count ? `${Number(abuse.count).toLocaleString()} (IPv4 ${Number(abuse.count_v4 || 0).toLocaleString()}, IPv6 ${Number(abuse.count_v6 || 0).toLocaleString()})` : '—');
            $('#abuse-updated').html(abuse.updated ? when(abuse.updated, now) : escape(T.never));
            $('#abuse-state').html(abuse.configured ? state(abuse.error) : `<span class="text-muted">${escape(T.no_key)}</span>`);
            $('#update-abuseipdb').prop('disabled', !abuse.configured);
        };

        let timer = null;
        const refresh = function () {
            clearTimeout(timer);
            ajaxGet('/api/firewallmap/service/overview', {}, function (data) {
                render(data || {});
                // while a download runs, follow it closely
                timer = setTimeout(refresh, (data && data.database && data.database.state === 'downloading') ? 2000 : 15000);
            });
        };
        $('.update-now').click(function () {
            const $button = $(this).prop('disabled', true);
            ajaxCall(`/api/firewallmap/service/update/${$button.data('what')}`, {}, function () {
                $button.prop('disabled', false);
                setTimeout(refresh, 1500);
            });
        });

        updateServiceControlUI('firewallmap');
        refresh();
    });
</script>

<div class="content-box __mb">
    <table class="table table-condensed">
        <thead><tr><th colspan="2">{{ lang._('Collector') }}</th></tr></thead>
        <tbody>
            <tr><td style="width: 25%;">{{ lang._('Status') }}</td><td id="collector-status"></td></tr>
            <tr><td>{{ lang._('Last map update') }}</td><td id="collector-update"></td></tr>
            <tr><td>{{ lang._('Background recording') }}</td><td id="collector-recording"></td></tr>
        </tbody>
    </table>
</div>

<div class="content-box __mb">
    <table class="table table-condensed">
        <thead><tr><th>{{ lang._('Geolocation database') }}</th>
            <th class="text-right"><button type="button" class="btn btn-default btn-xs update-now" id="update-geodb" data-what="geodb"><i class="fa fa-download fa-fw"></i> {{ lang._('Update now') }}</button></th></tr></thead>
        <tbody>
            <tr><td style="width: 25%;">{{ lang._('Service') }}</td><td id="geo-provider"></td></tr>
            <tr><td>{{ lang._('License key') }}</td><td id="geo-key"></td></tr>
            <tr><td>{{ lang._('Locations') }}</td><td id="geo-city"></td></tr>
            <tr><td>{{ lang._('Networks') }}</td><td id="geo-asn"></td></tr>
            <tr><td>{{ lang._('Next update') }}</td><td id="geo-next"></td></tr>
            <tr><td>{{ lang._('Last download') }}</td><td id="geo-state"></td></tr>
        </tbody>
    </table>
</div>

<div class="content-box __mb">
    <table class="table table-condensed">
        <thead><tr><th style="width: 25%;">{{ lang._('Threat feeds') }}</th><th>{{ lang._('Entries') }}</th><th>{{ lang._('Updated') }}</th>
            <th class="text-right"><button type="button" class="btn btn-default btn-xs update-now" id="update-feeds" data-what="feeds"><i class="fa fa-download fa-fw"></i> {{ lang._('Update now') }}</button></th></tr></thead>
        <tbody id="feeds"></tbody>
    </table>
</div>

<div class="content-box">
    <table class="table table-condensed">
        <thead><tr><th>{{ lang._('AbuseIPDB blacklist') }}</th>
            <th class="text-right"><button type="button" class="btn btn-default btn-xs update-now" id="update-abuseipdb" data-what="abuseipdb"><i class="fa fa-download fa-fw"></i> {{ lang._('Download now') }}</button></th></tr></thead>
        <tbody>
            <tr><td style="width: 25%;">{{ lang._('Entries') }}</td><td id="abuse-count"></td></tr>
            <tr><td>{{ lang._('Updated') }}</td><td id="abuse-updated"></td></tr>
            <tr><td>{{ lang._('Last download') }}</td><td id="abuse-state"></td></tr>
            <tr><td colspan="2" class="text-muted">{{ lang._('Downloaded once a day. The free AbuseIPDB plan allows only a few downloads a day, so use Download now sparingly.') }}</td></tr>
        </tbody>
    </table>
</div>
