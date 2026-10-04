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
        // the keys are never sent back: say whether one is stored instead
        const describeKeys = function () {
            ajaxGet('/api/firewallmap/settings/status', {}, function (status) {
                const stored = "{{ lang._('A key is stored') }}";
                const alias = "{{ lang._('Using the key of the GeoIP alias') }}";
                keyField('license_key').attr('placeholder', status.license_key_set ? stored
                    : (status.database && status.database.key_source === 'alias' ? alias : ''));
                keyField('abuseipdb_key').attr('placeholder', status.abuseipdb_configured ? stored : '');
            });
        };
        mapDataToFormUI({'frm_settings': '/api/firewallmap/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
            describeKeys();
        });

        // DB-IP Lite needs no key
        $('#firewallmap\\.general\\.provider').change(function () {
            keyField('license_key').closest('tr').toggle($(this).val() !== 'dbip');
        });

        $('#reconfigureAct').SimpleActionButton({
            onPreAction: function () {
                const done = new $.Deferred();
                saveFormToEndpoint('/api/firewallmap/settings/set', 'frm_settings', function () {
                    done.resolve();
                });
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

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/firewallmap/settings/reconfigure'}) }}
