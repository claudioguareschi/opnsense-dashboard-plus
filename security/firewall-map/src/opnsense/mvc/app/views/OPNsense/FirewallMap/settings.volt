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

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/firewallmap/service/reconfigure', 'data_service_widget': 'firewallmap'}) }}
