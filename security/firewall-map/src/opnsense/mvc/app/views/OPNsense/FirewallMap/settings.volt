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

<script src="/ui/js/firewall-map-allocation.js?v={{ allocationVersion }}"></script>
<script>
    $(document).ready(function () {
        const keyField = (name) => $(`#firewallmap\\.general\\.${name}`);
        const provider = $('#firewallmap\\.general\\.provider');
        let status = {};
        // DB-IP Lite needs no key: its rows (and removing a stored MaxMind key) show only for MaxMind
        const showRows = function () {
            const maxmind = provider.val() !== 'dbip';
            keyField('license_key').closest('tr').toggle(maxmind);
            keyField('remove_license_key').closest('tr').toggle(maxmind && Boolean(status.license_key_set));
            keyField('remove_abuseipdb_key').closest('tr').toggle(Boolean(status.abuseipdb_configured));
            // a hidden box must not remove a key on Apply
            if (!maxmind || !status.license_key_set) {
                keyField('remove_license_key').prop('checked', false);
            }
            if (!status.abuseipdb_configured) {
                keyField('remove_abuseipdb_key').prop('checked', false);
            }
        };
        // the keys are never sent back: say whether one is stored instead
        const describeKeys = function () {
            ajaxGet('/api/firewallmap/settings/status', {}, function (data) {
                status = data || {};
                // lang._() returns HTML-escaped text and .attr() takes plain text: decode once
                const plain = (html) => $('<textarea/>').html(html).text();
                const stored = plain({{ lang._('A key is stored')|json_encode }});
                const alias = plain({{ lang._('Using the key of the GeoIP alias')|json_encode }});
                keyField('license_key').attr('placeholder', status.license_key_set ? stored
                    : (status.database && status.database.key_source === 'alias' ? alias : ''));
                keyField('abuseipdb_key').attr('placeholder', status.abuseipdb_configured ? stored : '');
                keyField('remove_license_key').prop('checked', false);
                keyField('remove_abuseipdb_key').prop('checked', false);
                // a chosen threat list or set without a PF table classifies nothing: say so here too
                const unused = (status.threat_lists_unavailable || []).concat(status.sets_missing || []);
                $('#classificationWarning').toggleClass('hidden', !unused.length)
                    .find('.names').text(unused.join(', '));
                showRows();
            });
        };
        provider.change(showRows);
        // one model behind every tab: the tabs' forms (frm_settings-*) load from one request
        mapDataToFormUI({'frm_settings': '/api/firewallmap/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
            // the form is filled without change events: show the provider's rows now
            showRows();
            describeKeys();
        });

        // ranking profiles: built-ins can be activated and cloned; custom profiles (added with the
        // grid's + or cloned) also edited and deleted (never the active one). Changes take effect on
        // Apply, like every other setting.
        // looked up each time: initializing the grid replaces the table element
        const profileGrid = () => $("#{{ formGridProfile['table_id'] }}");
        const escape = (text) => $('<div/>').text(text).html();
        let profilesLoaded = false;
        const loadProfiles = function () {
            if (profilesLoaded) {
                profileGrid().bootgrid('reload');
                return;
            }
            profilesLoaded = true;
            profileGrid().UIBootgrid({
                search: '/api/firewallmap/profiles/search_item',
                get: '/api/firewallmap/profiles/get_item/',
                set: '/api/firewallmap/profiles/set_item/',
                add: '/api/firewallmap/profiles/add_item/',
                del: '/api/firewallmap/profiles/del_item/',
                commands: {
                    // the Active column's toggle: exactly one profile ranks, so it only activates
                    toggle: {
                        requires: [],
                        method: function (event, cell) {
                            if (cell.getData().active === '1') {
                                return;
                            }
                            $(this).removeClass('fa-square-o').addClass('fa-spinner fa-pulse');
                            ajaxCall(`/api/firewallmap/profiles/activate/${$(this).data('row-id')}`, {}, function () {
                                profileGrid().bootgrid('reload');
                                $(document).trigger('settings-changed');
                            });
                        },
                        title: (cell) => cell.getData().active === '1'
                            ? {{ lang._('Active profile')|json_encode }} : {{ lang._('Activate')|json_encode }}
                    },
                    // a built-in is shown read only (OPNsense's info command), a custom one edited
                    info: {
                        requires: [],
                        classname: 'fa fa-fw fa-info-circle',
                        title: {{ lang._('View')|json_encode }},
                        sequence: 90,
                        filter: (cell) => cell.getData().builtin === '1',
                        method: function () {
                            viewProfile($(this).data('row-id'));
                        }
                    },
                    edit: {filter: (cell) => cell.getData().builtin !== '1'},
                    delete: {filter: (cell) => cell.getData().builtin !== '1' && cell.getData().active !== '1'}
                },
                options: {
                    selection: false,
                    multiSelect: false,
                    rowSelect: false,
                    formatters: {
                        profile_type: (column, row) => escape(row.builtin === '1'
                            ? {{ lang._('Built-in')|json_encode }} : {{ lang._('Custom')|json_encode }})
                    }
                }
            });
        };

        // tabs as on OPNsense's own pages: the selected one is kept in the URL
        $('#maintabs a').on('shown.bs.tab', function (event) {
            if (event.target.hash === '#tab_profiles') {
                // a grid initialized in a hidden tab would be laid out without a width
                loadProfiles();
            }
            if (window.location.hash !== event.target.hash) {
                history.pushState(null, null, event.target.hash);
            }
        });
        const showTab = function () {
            const tab = $('#maintabs a').filter((index, link) => link.hash === window.location.hash);
            (tab.length ? tab : $('#maintabs a[href="#tab_general"]')).tab('show');
        };
        $(window).on('hashchange', showTab);
        showTab();

        // a validation error on another tab: show that tab and its field
        $(document).on('validation-failed', function (event, data) {
            if (data.formid !== 'settings_tabs') {
                return;
            }
            const field = $('#settings_tabs .has-error').first();
            const pane = field.closest('.tab-pane');
            if (pane.length) {
                $(`#maintabs a[href="#${pane.attr('id')}"]`).one('shown.bs.tab', () => field[0].scrollIntoView())
                    .tab('show');
            }
        });

        // the ranking profile editor: two allocation bars over the dialog's own fields (the fields
        // stay the state, are loaded and saved as before, and show the server's validation)
        const profileDialog = $("#{{ formGridProfile['edit_dialog_id'] }}");
        const profileSave = $("#btn_{{ formGridProfile['edit_dialog_id'] }}_save");
        const profileField = (key) => $(`#profile\\.${key}`);
        const PROFILE_TEXT = {
            general: {{ lang._('General ranking')|json_encode }},
            general_short: {{ lang._('General')|json_encode }},
            shorts: [{{ lang._('Data')|json_encode }}, {{ lang._('Packets')|json_encode }}, {{ lang._('Conns')|json_encode }},
                {{ lang._('Conn/s')|json_encode }}, {{ lang._('Total')|json_encode }}, {{ lang._('Blocked')|json_encode }},
                {{ lang._('Threat')|json_encode }}, {{ lang._('IDS')|json_encode }}],
            unreserved: {{ lang._('General ranking (unreserved): %s%')|json_encode }},
            over: {{ lang._('Over-allocated by %s%')|json_encode }},
            bad: {{ lang._('Enter whole percentages from 0 to 100.')|json_encode }},
            total: {{ lang._('Total: %s%')|json_encode }},
            remaining: {{ lang._('Total: %s% (%s% remaining)')|json_encode }},
            exceeded: {{ lang._('Total: %s% (%s% over)')|json_encode }},
            traffic: {{ lang._('Traffic behavior')|json_encode }},
            evidence: {{ lang._('Security evidence')|json_encode }},
            security_intro: {{ lang._('S1, S2 and S3 reserve a minimum share of the places on the map for security flows, filled from the most severe class down. Unused reserved places return to general ranking, and security flows can take more than their share when their ranking score is high enough. The shares scale with Maximum flows on the map, rounded up per class.')|json_encode }},
            ranking_intro: {{ lang._('How flows are scored against one another, security flows included. A higher percentage gives that property more influence on which flows appear on the map. Drag a boundary to move points between its two neighbours; the priorities total exactly 100.')|json_encode }}
        };
        const fill = (template, ...values) => values.reduce((text, value) => text.replace('%s', value), template);
        // the field's row becomes a compact cell: its label, input, help and validation message
        const fieldCell = (key, css, short) => {
            const field = profileField(key);
            const row = $(`#row_profile\\.${key}`);
            const label = row.find('.control-label b').text();
            const help = row.find(`[data-for="help_for_profile.${key}"] small`).text();
            field.attr({type: 'number', min: 0, max: 100, step: 1, inputmode: 'numeric', 'aria-label': label});
            const cell = $('<div class="fwmap-allocation-field"/>').append(
                $('<label/>').attr('for', field.attr('id')).append($('<span class="fwmap-allocation-swatch"/>').addClass(css), ' ', $('<span/>').text(label)),
                $('<div class="input-group input-group-sm"/>').append(field, '<span class="input-group-addon">%</span>'),
                $('<small class="text-muted"/>').text(help),
                $(`#help_block_profile\\.${key}`));
            // nothing of the row is left for core's validation to show again
            row.remove();
            return {cell, segment: {label, short, css, field}};
        };
        const sectionBody = (key) => profileField(key).closest('tbody');
        const securityStatus = $('<p class="fwmap-allocation-status"/>');
        const rankingTotal = $('<p class="fwmap-allocation-status"/>');
        const refreshSave = () => profileSave.prop('disabled', !(security.state().valid && ranking.state().valid));
        // Security visibility: General (what the shares leave) | S1 | S2 | S3
        const securityBody = sectionBody('s1_min_percent');
        const classes = [['s1_min_percent', 'progress-bar-success', 'S1'], ['s2_min_percent', 'progress-bar-warning', 'S2'],
            ['s3_min_percent', 'progress-bar-danger', 'S3']].map(([key, css, short]) => fieldCell(key, css, short));
        const securityCell = $('<td colspan="3"/>').append($('<p class="text-muted"/>').text(PROFILE_TEXT.security_intro));
        securityBody.prepend($('<tr/>').append(securityCell));
        const security = FirewallMapAllocation.create({
            container: securityCell,
            segments: [{label: PROFILE_TEXT.general, short: PROFILE_TEXT.general_short, css: 'progress-bar-info', derived: true},
                ...classes.map((entry) => entry.segment)],
            changed: () => {
                const current = security.state();
                securityStatus.toggleClass('text-danger', !current.valid).text(current.bad ? PROFILE_TEXT.bad
                    : current.over > 0 ? fill(PROFILE_TEXT.over, current.over) : fill(PROFILE_TEXT.unreserved, current.values[0]));
                refreshSave();
            }
        });
        securityCell.append(securityStatus, $('<div class="row"/>').append(classes.map((entry) => $('<div class="col-sm-4"/>').append(entry.cell))));
        // Ranking priorities: the eight weights, traffic behaviour then security evidence
        const rankingBody = sectionBody('byte_rate');
        const weights = ['byte_rate', 'packet_rate', 'active_states', 'new_state_rate', 'flow_volume', 'pf_blocked', 'threat_intelligence', 'ids_evidence']
            .map((key, index) => fieldCell(key, `fwmap-weight-${index}`, PROFILE_TEXT.shorts[index]));
        const rankingCell = $('<td colspan="3"/>').append($('<p class="text-muted"/>').text(PROFILE_TEXT.ranking_intro));
        rankingBody.prepend($('<tr/>').append(rankingCell));
        const ranking = FirewallMapAllocation.create({
            container: rankingCell,
            segments: weights.map((entry) => entry.segment),
            changed: () => {
                const current = ranking.state();
                rankingTotal.toggleClass('text-danger', !current.valid).text(current.bad ? PROFILE_TEXT.bad
                    : current.over < 0 ? fill(PROFILE_TEXT.remaining, current.total, -current.over)
                    : current.over > 0 ? fill(PROFILE_TEXT.exceeded, current.total, current.over) : fill(PROFILE_TEXT.total, 100));
                refreshSave();
            }
        });
        const group = (title, entries) => $('<div class="col-md-6"/>').append($('<h5/>').text(title), entries.map((entry) => entry.cell));
        rankingCell.append(rankingTotal, $('<div class="row"/>').append(group(PROFILE_TEXT.traffic, weights.slice(0, 5)),
            group(PROFILE_TEXT.evidence, weights.slice(5))));
        // a profile was loaded into the dialog
        profileDialog.on('opnsense_bootgrid_mapped', () => {
            security.refresh();
            ranking.refresh();
        });
        // a built-in profile shown read only: the same dialog, its fields and handles disabled, a
        // clone offered instead of Save (the server refuses changes to a built-in anyway)
        const profileForm = $(`#frm_${profileDialog.attr('id')}`);
        const profileTitle = profileDialog.find('.modal-title');
        const editTitle = profileTitle.text();
        const cloneButton = $('<button type="button" class="btn btn-primary hidden"/>')
            .text({{ lang._('Clone to edit')|json_encode }}).insertAfter(profileSave);
        let viewed = null;
        const viewProfile = (uuid) => {
            ajaxGet(`/api/firewallmap/profiles/get_item/${uuid}`, {}, (data) => {
                viewed = uuid;
                setFormData(profileForm.attr('id'), data);
                profileForm.find('input, select, textarea').prop('disabled', true);
                profileForm.find('.selectpicker').selectpicker('refresh');
                security.readOnly(true);
                ranking.readOnly(true);
                security.refresh();
                ranking.refresh();
                profileTitle.text(fill({{ lang._('Ranking profile: %s (built-in)')|json_encode }}, data.profile.name));
                profileSave.addClass('hidden');
                cloneButton.removeClass('hidden');
                profileDialog.modal('show');
            });
        };
        cloneButton.on('click', () => {
            const uuid = viewed;
            profileDialog.one('hidden.bs.modal', () => profileGrid().find(`.command-copy[data-row-id="${uuid}"]`).trigger('click'));
            profileDialog.modal('hide');
        });
        // leaving the view: everything editable again for the next edit, clone or add
        profileDialog.on('hidden.bs.modal', () => {
            if (viewed === null) {
                return;
            }
            viewed = null;
            profileForm.find('input, select, textarea').prop('disabled', false);
            profileForm.find('.selectpicker').selectpicker('refresh');
            security.readOnly(false);
            ranking.readOnly(false);
            profileTitle.text(editTitle);
            profileSave.removeClass('hidden');
            cloneButton.addClass('hidden');
        });

        updateServiceControlUI('firewallmap');

        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                const done = new $.Deferred();
                // every tab's fields in one request; a validation error rejects, so the button stops
                // spinning (as on OPNsense's own pages)
                saveFormToEndpoint('/api/firewallmap/settings/set', 'settings_tabs',
                    () => done.resolve(), true, () => done.reject());
                return done;
            },
            onAction: function () {
                keyField('license_key').val('');
                keyField('abuseipdb_key').val('');
                describeKeys();
                // open maps in other tabs refresh at once (the collector may restart) instead of
                // waiting out their adaptive delay (the renderer's REFRESH_APPLIED_KEY)
                try {
                    window.localStorage.setItem('firewall-map.applied', String(Date.now()));
                } catch (_) {
                    // storage blocked: open maps notice at their next refresh
                }
            }
        });
    });
</script>

<style>
    /* the ranking profile's allocation bars: Bootstrap's stacked progress bar, taller so a segment
       can carry its name and share, with a handle on each boundary */
    .fwmap-allocation { position: relative; margin: 12px 0 10px; }
    /* one row that never wraps, redrawn at once (Bootstrap animates progress widths: mid-way the
       segments would briefly overflow and the last one drop out of sight) */
    .fwmap-allocation-bar { display: flex; flex-wrap: nowrap; height: 40px; margin: 0; }
    .fwmap-allocation-bar .progress-bar { float: none; flex: 0 1 auto; transition: none; }
    .fwmap-allocation-bar .progress-bar { display: flex; flex-direction: column; justify-content: center;
        padding: 0 2px; min-width: 0; overflow: hidden; white-space: nowrap; line-height: 1.2; color: #1f2328; font-size: 12px; }
    .fwmap-allocation-value { font-weight: bold; font-size: 14px; }
    /* a zero share takes no room at all: the two handles beside each other mark it */
    .fwmap-allocation-bar .fwmap-allocation-zero { padding: 0; }
    /* a handle: the map's panel splitter (firewall-map.css .fwmap-splitter-v), a thin bar inside
       the colour bar on the boundary; the whole bar height takes the pointer */
    .fwmap-allocation-handle { position: absolute; top: 0; height: 40px; width: 12px; transform: translateX(-50%);
        cursor: col-resize; touch-action: none; user-select: none; z-index: 2; }
    .fwmap-allocation-handle::after { content: ""; position: absolute; left: 4.5px; top: 10px; height: 20px; width: 3px;
        border-radius: 2px; background: rgba(0, 0, 0, .35); box-shadow: 0 0 0 1px rgba(255, 255, 255, .45);
        transition: background .15s; }
    .fwmap-allocation-handle:hover::after, .fwmap-allocation-handle:focus-visible::after,
    .fwmap-allocation-handle.fwmap-dragging::after { background: rgba(0, 0, 0, .7); }
    /* focus shows as the darker bar (above), with no outline of its own */
    .fwmap-allocation-handle:focus, .fwmap-allocation-handle:focus-visible { outline: none; }
    .fwmap-allocation-handle.disabled { cursor: not-allowed; opacity: 0.4; }
    .fwmap-allocation-readonly .fwmap-allocation-handle { cursor: default; }
    .fwmap-allocation-status { margin: 0 0 8px; }
    /* one line per field (name, value, what it measures), wrapping in narrow columns */
    .fwmap-allocation-field { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 10px; margin-bottom: 6px; }
    .fwmap-allocation-field label { flex: 0 0 11em; margin: 0; }
    .fwmap-allocation-field .input-group { flex: 0 0 7em; width: 7em; }
    .fwmap-allocation-field .input-group .form-control { width: 100%; }
    .fwmap-allocation-field small { flex: 1 1 14em; }
    .fwmap-allocation-field .help-block { flex: 0 0 100%; margin: 0; }
    .fwmap-allocation-swatch { display: inline-block; float: none; width: 12px; height: 12px; vertical-align: -1px; }
    /* a handle's tooltip: the two neighbours it moves points between, one line */
    .fwmap-allocation-tooltip .tooltip-inner { max-width: none; white-space: nowrap; padding: 5px 10px; }
    .fwmap-allocation-tip .fa { margin: 0 8px; opacity: .8; }
    .fwmap-allocation-tip .fwmap-allocation-swatch { box-shadow: 0 0 0 1px rgba(255, 255, 255, .6); }
    /* the eight ranking priorities: the theme's contextual colours are only five, so a fixed
       colour-blind-safe set (Okabe-Ito), each neighbour clearly apart, with readable text on each */
    .fwmap-weight-0 { background-color: #0072B2; color: #fff !important; }
    .fwmap-weight-1 { background-color: #56B4E9; }
    .fwmap-weight-2 { background-color: #009E73; color: #fff !important; }
    .fwmap-weight-3 { background-color: #F0E442; }
    .fwmap-weight-4 { background-color: #999999; }
    .fwmap-weight-5 { background-color: #E69F00; }
    .fwmap-weight-6 { background-color: #CC79A7; }
    .fwmap-weight-7 { background-color: #D55E00; color: #fff !important; }
</style>

<div class="alert alert-warning hidden" role="alert" id="classificationWarning">
    <i class="fa fa-triangle-exclamation fa-fw"></i>
    {{ lang._('Not used, because they have no PF table:') }} <strong class="names"></strong>.
    {{ lang._('Enable Maintain blocklist aliases (Security tab) for the curated feeds and the AbuseIPDB blacklist, or create the aliases.') }}
</div>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    {{ partial('layout_partials/base_tabs_header', ['formData': formSettings]) }}
    <li><a data-toggle="tab" href="#tab_profiles">{{ lang._('Profiles') }}</a></li>
</ul>

<div class="tab-content content-box" id="settings_tabs">
{% for tab in formSettings['tabs'] %}
    <div id="tab_{{ tab['tab_id'] }}" class="tab-pane fade{% if tab['tab_id'] == formSettings['activetab'] %} in active{% endif %}">
        {{ partial('layout_partials/base_form', ['fields': tab, 'id': 'frm_settings-' ~ tab['tab_id']]) }}
    </div>
{% endfor %}
    <div id="tab_profiles" class="tab-pane fade">
        {{ partial('layout_partials/base_bootgrid_table', formGridProfile + {'hide_delete': true}) }}
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/firewallmap/service/reconfigure', 'data_service_widget': 'firewallmap'}) }}
{{ partial('layout_partials/base_dialog', ['fields': formDialogProfile, 'id': formGridProfile['edit_dialog_id'], 'label': lang._('Edit ranking profile')]) }}
