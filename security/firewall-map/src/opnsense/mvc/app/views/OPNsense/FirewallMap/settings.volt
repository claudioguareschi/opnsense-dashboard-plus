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
                showRows();
            });
        };
        provider.change(showRows);
        mapDataToFormUI({'frm_settings': '/api/firewallmap/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
            // the form is filled without change events: show the provider's rows now
            showRows();
            describeKeys();
        });

        /* ---- Ranking profiles: one active operational policy (built-ins and custom copies) ---- */
        const t = (html) => $('<textarea/>').html(html).text();
        const FEATURES = [
            ['byte_rate', t({{ lang._('Byte rate')|json_encode }})],
            ['packet_rate', t({{ lang._('Packet rate')|json_encode }})],
            ['active_states', t({{ lang._('Active states')|json_encode }})],
            ['new_state_rate', t({{ lang._('New-state rate')|json_encode }})],
            ['flow_volume', t({{ lang._('Flow volume')|json_encode }})],
            ['pf_blocked', t({{ lang._('PF blocked activity')|json_encode }})],
            ['threat_intelligence', t({{ lang._('Threat intelligence')|json_encode }})],
            ['ids_evidence', t({{ lang._('IDS evidence')|json_encode }})]
        ];
        const FLOORS = [['s3_min_percent', 'S3'], ['s2_min_percent', 'S2'], ['s1_min_percent', 'S1']];
        const editor = $('#profileEditor');
        let editing = null;
        let profiles = [];
        const button = (icon, title, color) => $('<button type="button" class="btn btn-xs"/>')
            .addClass(`btn-${color || 'default'}`).attr('title', title).append($('<i/>').addClass(`fa fa-fw ${icon}`));
        const pill = (text, color) => $('<span class="label profile-pill"/>').addClass(`label-${color}`).text(text);
        const failed = (data) => {
            const message = (data && data.message) || t({{ lang._('The profile could not be saved.')|json_encode }});
            BootstrapDialog.show({type: BootstrapDialog.TYPE_DANGER, title: t({{ lang._('Ranking profiles')|json_encode }}),
                                  message: $('<div/>').text(message), buttons: [{label: t({{ lang._('Close')|json_encode }}),
                                  action: (dialog) => dialog.close()}]});
        };
        const post = (url, done) => ajaxCall(url, {}, function (data) {
            if (data && (data.result === 'saved' || data.result === 'deleted')) {
                loadProfiles();
                if (done) done(data);
            } else {
                failed(data);
            }
        });
        const loadProfiles = function () {
            ajaxGet('/api/firewallmap/settings/profiles', {}, function (data) {
                profiles = (data && data.profiles) || [];
                const body = $('#profileTable tbody').empty();
                profiles.forEach(function (profile) {
                    const name = $('<td/>').append($('<strong/>').text(profile.name));
                    if (profile.active) name.append(' ', pill(t({{ lang._('Active')|json_encode }}), 'success'));
                    if (profile.builtin) name.append(' ', pill(t({{ lang._('Built-in')|json_encode }}), 'default'));
                    if (profile.problem) name.append(' ', pill(t({{ lang._('Invalid')|json_encode }}), 'danger').attr('title', profile.problem));
                    const actions = $('<div class="btn-group"/>');
                    if (!profile.active) {
                        actions.append(button('fa-check', t({{ lang._('Activate')|json_encode }}), 'primary').click(function () {
                            stdDialogConfirm(t({{ lang._('Activate ranking profile')|json_encode }}),
                                t({{ lang._('The collector restarts with this profile; the ranking settles over a few seconds.')|json_encode }}),
                                t({{ lang._('Activate')|json_encode }}), t({{ lang._('Cancel')|json_encode }}),
                                () => post(`/api/firewallmap/settings/activate_profile/${profile.uuid}`));
                        }));
                    }
                    if (!profile.builtin) {
                        actions.append(button('fa-pencil', t({{ lang._('Edit')|json_encode }})).click(() => openEditor(profile)));
                    }
                    actions.append(button('fa-clone', t({{ lang._('Copy')|json_encode }})).click(
                        () => post(`/api/firewallmap/settings/copy_profile/${profile.uuid}`, function (result) {
                            ajaxGet('/api/firewallmap/settings/profiles', {}, function (data) {
                                const copy = ((data && data.profiles) || []).find((item) => item.uuid === result.uuid);
                                if (copy) openEditor(copy);
                            });
                        })));
                    if (!profile.builtin && !profile.active) {
                        actions.append(button('fa-trash', t({{ lang._('Delete')|json_encode }})).click(function () {
                            stdDialogConfirm(t({{ lang._('Delete ranking profile')|json_encode }}), profile.name,
                                t({{ lang._('Delete')|json_encode }}), t({{ lang._('Cancel')|json_encode }}),
                                () => post(`/api/firewallmap/settings/del_profile/${profile.uuid}`));
                        }));
                    }
                    body.append($('<tr/>').append(name, $('<td/>').text(profile.description || ''),
                                                  $('<td class="text-right text-nowrap"/>').append(actions)));
                });
            });
        };
        const updateTotal = function () {
            const total = FEATURES.reduce((sum, [key]) => sum + (parseFloat($(`#profile_${key}`).val()) || 0), 0);
            const exact = Math.abs(total - 100) < 1e-9;
            $('#profileTotal').text(`${+total.toFixed(6)} / 100`).toggleClass('label-success', exact).toggleClass('label-danger', !exact);
        };
        const ruleRow = function (cidr, multiplier) {
            const row = $('<tr/>');
            row.append($('<td/>').append($('<input type="text" class="form-control rule-cidr"/>').val(cidr || '')
                .attr('placeholder', '192.168.1.25 or 192.168.10.0/24')));
            row.append($('<td/>').append($('<input type="number" class="form-control rule-multiplier" min="0.000001" step="any"/>')
                .val(multiplier || '')));
            row.append($('<td class="text-right"/>').append(button('fa-trash', t({{ lang._('Remove')|json_encode }}))
                .click(() => row.remove())));
            $('#profileRules tbody').append(row);
        };
        const openEditor = function (profile) {
            editing = profile;
            editor.find('.has-error').removeClass('has-error');
            editor.find('.profile-error').remove();
            $('#profile_name').val(profile.name);
            $('#profile_description').val(profile.description || '');
            FEATURES.forEach(([key]) => $(`#profile_${key}`).val(profile.weights[key]));
            FLOORS.forEach(([key]) => $(`#profile_${key}`).val(profile.floors[key]));
            $('#profile_default_multiplier').val(profile.default_multiplier);
            $('#profile_direction').val(profile.direction || 'equal').selectpicker('refresh');
            $('#profileRules tbody').empty();
            (profile.assets || '').split('\n').filter((line) => line.trim()).forEach(function (line) {
                const [cidr, multiplier] = line.trim().split(/\s+/);
                ruleRow(cidr, multiplier);
            });
            updateTotal();
            editor.modal('show');
        };
        const saveEditor = function () {
            const values = {name: $('#profile_name').val(), description: $('#profile_description').val(),
                            default_multiplier: $('#profile_default_multiplier').val(), direction: $('#profile_direction').val()};
            FEATURES.forEach(([key]) => { values[key] = $(`#profile_${key}`).val(); });
            FLOORS.forEach(([key]) => { values[key] = $(`#profile_${key}`).val(); });
            values.assets = $('#profileRules tbody tr').map(function () {
                const cidr = $(this).find('.rule-cidr').val().trim();
                const multiplier = $(this).find('.rule-multiplier').val().trim();
                return cidr || multiplier ? `${cidr} ${multiplier}` : null;
            }).get().join('\n');
            ajaxCall(`/api/firewallmap/settings/set_profile/${editing.uuid}`, {profile: values}, function (data) {
                editor.find('.has-error').removeClass('has-error');
                editor.find('.profile-error').remove();
                if (data && data.result === 'saved') {
                    editor.modal('hide');
                    loadProfiles();
                    return;
                }
                Object.entries((data && data.validations) || {}).forEach(function ([field, message]) {
                    const key = field.replace(/^profile\./, '');
                    const target = key === 'assets' ? $('#profileRules') : $(`#profile_${key}`);
                    target.closest('.form-group').addClass('has-error')
                        .append($('<span class="help-block profile-error"/>').text(message));
                });
                if (!data || !data.validations) failed(data);
            });
        };
        editor.on('input', '.profile-weight', updateTotal);
        $('#profileAddRule').click(() => ruleRow('', ''));
        $('#profileSave').click(saveEditor);
        loadProfiles();

        updateServiceControlUI('firewallmap');

        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                const done = new $.Deferred();
                // a validation error rejects, so the button stops spinning (as on OPNsense's own pages)
                saveFormToEndpoint('/api/firewallmap/settings/set', 'frm_settings',
                    () => done.resolve(), true, () => done.reject());
                return done;
            },
            onAction: function () {
                keyField('license_key').val('');
                keyField('abuseipdb_key').val('');
                describeKeys();
            }
        });
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': formSettings, 'id': 'frm_settings']) }}
</div>

<div class="content-box" id="rankingProfiles">
    <div class="table-responsive">
        <table class="table table-condensed" id="profileTable">
            <thead>
                <tr>
                    <th colspan="3">
                        {{ lang._('Ranking profiles') }}
                        <div class="text-muted small" style="font-weight: normal;">
                            {{ lang._('The active profile decides which flows every map and dashboard shows. Built-in profiles cannot be changed: copy one to make your own.') }}
                        </div>
                    </th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

<div class="modal fade" id="profileEditor" tabindex="-1" role="dialog" aria-labelledby="profileEditorTitle">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="{{ lang._('Close') }}"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="profileEditorTitle">{{ lang._('Ranking profile') }}</h4>
            </div>
            <div class="modal-body form-horizontal">
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_name">{{ lang._('Name') }}</label>
                    <div class="col-sm-9"><input type="text" class="form-control" id="profile_name" maxlength="64"></div>
                </div>
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_description">{{ lang._('Description') }}</label>
                    <div class="col-sm-9"><input type="text" class="form-control" id="profile_description" maxlength="255"></div>
                </div>
                <h5><strong>{{ lang._('Quality') }}</strong> <span class="label profile-pill" id="profileTotal"></span>
                    <small class="text-muted">{{ lang._('weights total exactly 100') }}</small></h5>
{% for key, label in ['byte_rate': 'Byte rate', 'packet_rate': 'Packet rate', 'active_states': 'Active states', 'new_state_rate': 'New-state rate', 'flow_volume': 'Flow volume', 'pf_blocked': 'PF blocked activity', 'threat_intelligence': 'Threat intelligence', 'ids_evidence': 'IDS evidence'] %}
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_{{ key }}">{{ lang._(label) }}</label>
                    <div class="col-sm-3"><input type="number" class="form-control profile-weight" id="profile_{{ key }}" min="0" max="100" step="any"></div>
                </div>
{% endfor %}
                <h5><strong>{{ lang._('Asset importance') }}</strong>
                    <small class="text-muted">{{ lang._('multipliers, not part of the 100; the longest matching network wins; not a security severity') }}</small></h5>
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_default_multiplier">{{ lang._('Default multiplier') }}</label>
                    <div class="col-sm-3"><input type="number" class="form-control" id="profile_default_multiplier" min="0.000001" step="any"></div>
                </div>
                <div class="form-group">
                    <div class="col-sm-9 col-sm-offset-3">
                        <table class="table table-condensed" id="profileRules">
                            <thead><tr><th>{{ lang._('Network or host') }}</th><th>{{ lang._('Multiplier') }}</th><th></th></tr></thead>
                            <tbody></tbody>
                        </table>
                        <button type="button" class="btn btn-default btn-xs" id="profileAddRule"><i class="fa fa-fw fa-plus"></i> {{ lang._('Add rule') }}</button>
                    </div>
                </div>
                <h5><strong>{{ lang._('Security visibility') }}</strong>
                    <small class="text-muted">{{ lang._('minimum percent of the ranked flows kept for each security class, not part of the 100') }}</small></h5>
{% for key, label in ['s3_min_percent': 'S3 minimum (%)', 's2_min_percent': 'S2 minimum (%)', 's1_min_percent': 'S1 minimum (%)'] %}
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_{{ key }}">{{ lang._(label) }}</label>
                    <div class="col-sm-3"><input type="number" class="form-control" id="profile_{{ key }}" min="0" max="100" step="any"></div>
                </div>
{% endfor %}
                <h5><strong>{{ lang._('Modifiers') }}</strong></h5>
                <div class="form-group">
                    <label class="col-sm-3 control-label" for="profile_direction">{{ lang._('Direction') }}</label>
                    <div class="col-sm-9">
                        <select class="selectpicker" id="profile_direction" data-width="fit">
                            <option value="equal">{{ lang._('Equal: inbound and outbound count the same') }}</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="profileSave">{{ lang._('Save') }}</button>
            </div>
        </div>
    </div>
</div>

<style>
    .profile-pill { border-radius: 10px; }
    #profileRules input { min-width: 0; }
</style>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/firewallmap/service/reconfigure', 'data_service_widget': 'firewallmap'}) }}
