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
        // lang._() returns HTML-escaped text and the page escapes again where it builds HTML: decode
        // once here (json_encode makes each a valid JavaScript string)
        const plain = function (strings) {
            const box = document.createElement('textarea');
            Object.keys(strings).forEach(function (key) {
                box.innerHTML = strings[key];
                strings[key] = box.value;
            });
            return strings;
        };
        const T = plain({
            running_live: {{ lang._('Running: a map is open')|json_encode }},
            running_background: {{ lang._('Running: recording threats in the background')|json_encode }},
            stopped: {{ lang._('Stopped: starts when a map is opened')|json_encode }},
            recording_on: {{ lang._('On')|json_encode }},
            recording_no_widget: {{ lang._('On, but no dashboard has the Firewall Map widget')|json_encode }},
            recording_off: {{ lang._('Off')|json_encode }},
            never: {{ lang._('never')|json_encode }},
            ago: {{ lang._('%s ago')|json_encode }},
            in: {{ lang._('in %s')|json_encode }},
            built: {{ lang._('built %s')|json_encode }},
            missing: {{ lang._('not downloaded')|json_encode }},
            downloading: {{ lang._('Downloading…')|json_encode }},
            ok: {{ lang._('OK')|json_encode }},
            list_missing: {{ lang._('no PF table: the alias does not exist or is not loaded')|json_encode }},
            list_too_large: {{ lang._('too large: over 500,000 entries, or past 1,000,000 across all lists')|json_encode }},
            list_unreadable: {{ lang._('the PF table could not be read')|json_encode }},
            list_pending: {{ lang._('not read yet')|json_encode }},
            list_unavailable: {{ lang._('Not used: no PF table. Enable Maintain blocklist aliases in the settings, or create the alias.')|json_encode }},
            lists_none: {{ lang._('No threat lists: choose them in the settings.')|json_encode }},
            no_key: {{ lang._('No AbuseIPDB API key')|json_encode }},
            key_plugin: {{ lang._('Stored in the Firewall Map settings')|json_encode }},
            key_alias: {{ lang._('Taken from the GeoIP alias')|json_encode }},
            key_none: {{ lang._('None')|json_encode }},
            key_unused: {{ lang._('Not needed')|json_encode }},
            entries: {{ lang._('%s entries')|json_encode }},
            started: {{ lang._('Download started')|json_encode }},
            unavailable: {{ lang._('The status could not be read. Trying again shortly.')|json_encode }},
            update_failed: {{ lang._('The download could not be started.')|json_encode }},
            standin: {{ lang._('%s standing in while the download fails')|json_encode }},
            seconds: {{ lang._('%s s')|json_encode }},
            minutes: {{ lang._('%s min')|json_encode }},
            hours: {{ lang._('%s h')|json_encode }},
            days: {{ lang._('%s days')|json_encode }},
            sample: {{ lang._('%s ms (CPU %s ms)')|json_encode }},
            engine_helper: {{ lang._('Process %s, started %s times; built for PF state ABI %s')|json_encode }},
            engine_version_warning: {{ lang._('Built on FreeBSD %s, running %s: compatibility is decided by the PF state check')|json_encode }},
            engine_limit: {{ lang._('Up to %s states (memory budget %s)')|json_encode }},
            engine_tracking: {{ lang._('%s: %s of up to %s flows tracked, %s flows in all')|json_encode }},
            engine_quality: {{ lang._('discovery %s, ranking %s, attribution %s')|json_encode }},
            regime_exact: {{ lang._('Every flow tracked')|json_encode }},
            regime_bounded: {{ lang._('Bounded')|json_encode }},
            quality_exact: {{ lang._('exact')|json_encode }},
            quality_bounded: {{ lang._('bounded')|json_encode }},
            quality_warming: {{ lang._('warming')|json_encode }},
            quality_partial: {{ lang._('partial')|json_encode }},
            engine_sample: {{ lang._('%s states: PF read %s ms, processing %s ms, memory peak %s')|json_encode }},
            engine_baseline: {{ lang._('first sample of this process: no rates yet')|json_encode }},
            engine_omitted: {{ lang._('%s states skipped (unsupported address-family translation), %s candidates and %s threat remotes over their budgets, %s recent tuples evicted')|json_encode }},
            engine_rejected: {{ lang._('%s filter log and %s IDS lines rejected')|json_encode }},
            engine_refused: {{ lang._('Last sample refused: %s')|json_encode }},
            engine_incompatible: {{ lang._('Incompatible with this firewall: %s')|json_encode }},
            engine_protocol_mismatch: {{ lang._('Firewall Map collector incompatible — The Firewall Map application and its state collector use incompatible protocols. Reinstall or upgrade the Firewall Map package so both components come from the same version.')|json_encode }},
            reason_protocol: {{ lang._('Protocol mismatch')|json_encode }},
            reason_pf_abi: {{ lang._('PF ABI mismatch')|json_encode }},
            collector_running: {{ lang._('Running')|json_encode }},
            collector_incompatible: {{ lang._('Incompatible')|json_encode }},
            collector_failed: {{ lang._('Failed')|json_encode }},
            collector_starting: {{ lang._('Starting')|json_encode }},
            collector_stopped: {{ lang._('Not running')|json_encode }},
            unknown: {{ lang._('unknown')|json_encode }},
            none: {{ lang._('none')|json_encode }},
        });
        const PROVIDERS = plain({
            auto: {{ lang._('Automatic')|json_encode }}, maxmind: 'MaxMind GeoLite2', maxmind_paid: 'MaxMind GeoIP2 City', dbip: 'DB-IP Lite',
        });
        const escape = (text) => $('<div/>').text(text === null || text === undefined ? '' : String(text)).html();
        const duration = (seconds) => {
            seconds = Math.abs(seconds);
            if (seconds < 90) return T.seconds.replace('%s', Math.round(seconds));
            if (seconds < 5400) return T.minutes.replace('%s', Math.round(seconds / 60));
            if (seconds < 172800) return T.hours.replace('%s', Math.round(seconds / 3600));
            return T.days.replace('%s', Math.round(seconds / 86400));
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
            $('#version').text(data.version || T.unknown);
            const c = data.collector || {};
            $('#collector-status').html(c.running
                ? state(null, c.mode === 'live' ? T.running_live : T.running_background)
                : `<span class="text-muted"><i class="fa fa-circle-stop fa-fw"></i> ${escape(T.stopped)}</span>`);
            $('#collector-update').html(when(c.last_map_update, now));
            $('#collector-recording').text(!c.recording ? T.recording_off : c.widget_in_use ? T.recording_on : T.recording_no_widget);
            const sample = c.last_sample;
            const ms = (seconds) => Math.round(seconds * 1000).toLocaleString();
            $('#collector-sample').text(sample ? T.sample.replace('%s', ms(sample.wall)).replace('%s', ms(sample.cpu)) : '—');

            const engine = data.state_collector || {};
            const incompatible = engine.incompatible || null;
            const stateText = T[`collector_${engine.state}`] || T.collector_stopped;
            $('#engine-state').html(engine.state === 'incompatible' || engine.state === 'failed' ? state(stateText)
                : engine.state === 'running' ? state(null, stateText)
                : `<span class="text-muted">${escape(stateText)}</span>`);
            $('#engine-protocol').text(engine.protocol === null || engine.protocol === undefined
                ? (engine.state === 'incompatible' ? T.unknown : '—') : engine.protocol);
            $('#engine-expected-protocol').text(engine.expected_protocol || '—');
            // why it is incompatible, and for a PF ABI mismatch both state versions (unknown when not reported)
            const known = (value) => (value === null || value === undefined ? T.unknown : value);
            $('#engine-reason').text(incompatible ? T[`reason_${incompatible.reason}`] || incompatible.reason : '')
                .closest('tr').toggleClass('hidden', !incompatible);
            const pfAbi = !!incompatible && incompatible.reason === 'pf_abi';
            $('#engine-collector-pf').text(pfAbi ? known(incompatible.collector_pf_state_version) : '')
                .closest('tr').toggleClass('hidden', !pfAbi);
            $('#engine-running-pf').text(pfAbi ? known(incompatible.running_pf_state_version) : '')
                .closest('tr').toggleClass('hidden', !pfAbi);
            const helper = engine.helper || {};
            const telemetry = engine.telemetry || {};
            const count = (value) => Number(value || 0).toLocaleString();
            const fill = (template, ...values) => values.reduce((text, value) => text.replace('%s', value), template);
            $('#engine-helper').html(helper.pid
                ? escape(fill(T.engine_helper, helper.pid, count(helper.starts), helper.pf_state_version))
                  + (engine.version_warning ? `<br><span class="text-warning">${escape(fill(T.engine_version_warning,
                      helper.freebsd_version, engine.kernel_version))}</span>` : '')
                : '—');
            $('#engine-limit').text(engine.state_limit ? fill(T.engine_limit, count(engine.state_limit),
                megabytes(telemetry.heap_budget || 0)) : '—');
            $('#engine-sample').text(telemetry.sequence ? fill(T.engine_sample, count(engine.states),
                ms(telemetry.dump_seconds || 0), ms(telemetry.processing_seconds || 0), megabytes(telemetry.heap_peak || 0))
                + (engine.baseline ? ` (${T.engine_baseline})` : '') : '—');
            // the tracked set and the quality axes (an estimated flow total is marked ≈)
            const axis = (n, names) => T[`quality_${names[n] || names[0]}`];
            $('#engine-tracking').html(telemetry.sequence ? escape(fill(T.engine_tracking,
                telemetry.regime ? T.regime_bounded : T.regime_exact, count(telemetry.tracked_flows),
                count(telemetry.tracked_limit), (telemetry.flows_estimated ? '≈' : '') + count(telemetry.flows_total)))
                + `<br><small class="text-muted">${escape(fill(T.engine_quality,
                    axis(telemetry.quality_discovery, ['exact', 'bounded']),
                    axis(telemetry.quality_ranking, ['exact', 'warming', 'bounded']),
                    axis(telemetry.quality_attribution, ['exact', 'warming', 'partial'])))}</small>` : '—');
            $('#engine-omitted').text(telemetry.sequence ? fill(T.engine_omitted, count(telemetry.skipped_af_translation),
                count(telemetry.candidates_omitted), count(telemetry.threat_remotes_omitted),
                count(telemetry.event_history_evicted)) : '—');
            const rejected = engine.ingest_rejected || {};
            $('#engine-rejected').text(fill(T.engine_rejected, count(rejected.filterlog), count(rejected.eve)));
            const problem = incompatible ? (incompatible.reason === 'protocol' ? T.engine_protocol_mismatch
                    : fill(T.engine_incompatible, incompatible.error))
                : engine.refused ? fill(T.engine_refused, `${engine.refused.reason} (${count(engine.refused.actual)} / ${count(engine.refused.limit)})`)
                : engine.last_error ? engine.last_error : null;
            $('#engine-problem').html(problem ? state(problem) : escape(T.none));

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
            $('#update-geodb:not(.busy)').prop('disabled', db.state === 'downloading');
            $('#geo-state').html(db.state === 'downloading' ? `<i class="fa fa-spinner fa-pulse fa-fw"></i> ${escape(T.downloading)}`
                : state((db.errors || []).map((error) => error.message).join('; ') || db.last_error));

            // the PF tables the collector classifies with; a chosen list without one never classifies silently
            const lists = data.threat_lists || {};
            const listName = (row) => `${escape(row.description || row.label)}${row.description || row.label !== row.name
                ? `<br><small class="text-muted">${escape(row.name)}</small>` : ''}`;
            const rows = (lists.lists || []).map((row) => `<tr>
                <td>${listName(row)}</td>
                <td>${row.status === 'ok' ? escape(Number(row.entries).toLocaleString()) : '—'}</td>
                <td>${row.status === 'ok' ? state(null) : row.status === 'pending' ? escape(T.list_pending)
                    : state(T[`list_${row.status}`] || row.status)}</td></tr>`)
                .concat((lists.unavailable || []).map((row) => `<tr>
                <td>${listName(row)}</td><td>—</td><td>${state(T.list_unavailable)}</td></tr>`));
            $('#threat-lists').html(rows.length ? rows.join('')
                : `<tr><td colspan="3" class="text-muted">${escape(T.lists_none)}</td></tr>`);

            const abuse = data.abuseipdb || {};
            $('#abuse-count').text(abuse.count ? `${Number(abuse.count).toLocaleString()} (IPv4 ${Number(abuse.count_v4 || 0).toLocaleString()}, IPv6 ${Number(abuse.count_v6 || 0).toLocaleString()})` : '—');
            $('#abuse-updated').html(abuse.updated ? when(abuse.updated, now) : escape(T.never));
            $('#abuse-state').html(abuse.configured ? state(abuse.error) : `<span class="text-muted">${escape(T.no_key)}</span>`);
            $('#update-abuseipdb:not(.busy)').prop('disabled', !abuse.configured);
        };

        let timer = null;
        const refresh = function () {
            clearTimeout(timer);
            ajaxGet('/api/firewallmap/service/overview', {}, function (data, status) {
                // a failed request keeps what is shown (never "Stopped" or "not downloaded" for want of an answer)
                const ok = status === 'success' && data && data.collector;
                $('#overview-error').toggleClass('hidden', !!ok).text(ok ? '' : T.unavailable);
                if (ok) {
                    render(data);
                }
                // while a download runs, follow it closely
                timer = setTimeout(refresh, ok && data.database && data.database.state === 'downloading' ? 2000 : 15000);
            });
        };
        $('.update-now').click(function () {
            // busy: render() leaves the button alone until its own answer is shown
            const $button = $(this).prop('disabled', true).addClass('busy');
            const label = $button.html();
            ajaxCall(`/api/firewallmap/service/update/${$button.data('what')}`, {}, function (data, status) {
                if (status !== 'success' || !data || data.result !== 'started') {
                    $('#overview-error').removeClass('hidden').text(T.update_failed);
                    $button.removeClass('busy').prop('disabled', false);
                    return;
                }
                // a repeat right after a download is skipped by the firewall (provider limits): the
                // button only says the download started, then refresh shows its result
                $button.html(`<i class="fa fa-check fa-fw"></i> ${escape(T.started)}`);
                setTimeout(refresh, 1500);
                setTimeout(() => {
                    $button.html(label).removeClass('busy').prop('disabled', false);
                    refresh();
                }, 10000);
            });
        });

        updateServiceControlUI('firewallmap');
        refresh();
    });
</script>

<div id="overview-error" class="alert alert-warning hidden" role="alert"></div>

<div class="content-box __mb">
    <table class="table table-condensed">
        <thead><tr><th colspan="2">{{ lang._('Collector') }}</th></tr></thead>
        <tbody>
            <tr><td style="width: 25%;">{{ lang._('Firewall Map version') }}</td><td id="version"></td></tr>
            <tr><td>{{ lang._('Status') }}</td><td id="collector-status"></td></tr>
            <tr><td>{{ lang._('Last map update') }}</td><td id="collector-update"></td></tr>
            <tr><td>{{ lang._('Background recording') }}</td><td id="collector-recording"></td></tr>
            <tr><td>{{ lang._('Last sample') }}</td><td id="collector-sample"></td></tr>
        </tbody>
    </table>
</div>

<div class="content-box __mb">
    <table class="table table-condensed">
        <thead><tr><th colspan="2">{{ lang._('State collector') }}</th></tr></thead>
        <tbody>
            <tr><td style="width: 25%;">{{ lang._('State collector') }}</td><td id="engine-state"></td></tr>
            <tr><td>{{ lang._('Collector protocol') }}</td><td id="engine-protocol"></td></tr>
            <tr><td>{{ lang._('Expected protocol') }}</td><td id="engine-expected-protocol"></td></tr>
            <tr class="hidden"><td>{{ lang._('Reason') }}</td><td id="engine-reason"></td></tr>
            <tr class="hidden"><td>{{ lang._('Collector PF state version') }}</td><td id="engine-collector-pf"></td></tr>
            <tr class="hidden"><td>{{ lang._('Running PF state version') }}</td><td id="engine-running-pf"></td></tr>
            <tr><td>{{ lang._('Process') }}</td><td id="engine-helper"></td></tr>
            <tr><td>{{ lang._('State limit') }}</td><td id="engine-limit"></td></tr>
            <tr><td>{{ lang._('Last collector sample') }}</td><td id="engine-sample"></td></tr>
            <tr><td>{{ lang._('Flows') }}</td><td id="engine-tracking"></td></tr>
            <tr><td>{{ lang._('Left out') }}</td><td id="engine-omitted"></td></tr>
            <tr><td>{{ lang._('Rejected log lines') }}</td><td id="engine-rejected"></td></tr>
            <tr><td>{{ lang._('Problems') }}</td><td id="engine-problem"></td></tr>
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
        <thead><tr><th style="width: 25%;">{{ lang._('Threat lists') }}</th><th>{{ lang._('Entries') }}</th>
            <th class="text-right"><button type="button" class="btn btn-default btn-xs update-now" id="update-lists" data-what="lists"><i class="fa fa-download fa-fw"></i> {{ lang._('Update now') }}</button></th></tr></thead>
        <tbody id="threat-lists"></tbody>
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
