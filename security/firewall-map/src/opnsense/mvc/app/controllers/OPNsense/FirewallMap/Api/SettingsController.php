<?php

/*
 * Copyright (C) 2026 Claudio Guareschi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
namespace OPNsense\FirewallMap\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\FirewallMap\FirewallMap;

/**
 * Firewall-wide Firewall Map+ settings (geolocation database), edited from the widget's
 * settings dialog. The license key is write-only: it is never returned to the browser.
 */
class SettingsController extends ApiControllerBase
{
    private const ABUSE_ALIAS = 'FWMAP_AbuseIPDB';
    private const ABUSE_ALIAS_DESCRIPTION = 'Firewall Map+ AbuseIPDB blacklist (100% confidence; no rules added)';

    private function status()
    {
        $status = json_decode((new Backend())->configdRun('firewallmap geodb status'), true);
        return is_array($status) ? $status : [];
    }

    public function getAction()
    {
        $general = (new FirewallMap())->general;
        return [
            'provider' => (string)$general->provider,
            'update_days' => (string)$general->update_days,
            'abuseipdb_configured' => (string)$general->abuseipdb_key !== '',
            // read directly: this runs on every widget and page load
            'abuseipdb_blacklist' => json_decode((string)@file_get_contents('/var/db/firewallmap/abuseipdb.json'), true) ?: [],
            'threat_lists' => (string)$general->threat_lists,
            'record_threats' => (string)$general->record_threats,
            'abuseipdb_alias' => (string)$general->abuseipdb_alias,
            'database' => $this->status(),
        ];
    }

    /**
     * Add or remove the external alias FWMAP_AbuseIPDB. Firewall Map+ only fills its table
     * (firewallmap_abuseipdb.py sync); the administrator decides which rules use it.
     * Returns [alias model, changed, error].
     */
    private function reconcileAbuseAlias(bool $enabled): array
    {
        $model = new Alias();
        $found = null;
        $foundUuid = null;
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            if ((string)$alias->name === self::ABUSE_ALIAS) {
                $found = $alias;
                $foundUuid = $uuid;
                break;
            }
        }
        /* an alias of that name made by someone else is never filled or removed */
        $ours = $found !== null && (string)$found->type === 'external' &&
            (string)$found->description === self::ABUSE_ALIAS_DESCRIPTION;
        if ($enabled) {
            if ($found !== null && !$ours) {
                return [$model, false, sprintf(
                    gettext('An alias named %s already exists and was not created by Firewall Map+.'),
                    self::ABUSE_ALIAS
                )];
            }
            if ($found !== null) {
                return [$model, false, null];
            }
            $model->aliases->alias->add()->setNodes([
                'enabled' => '1',
                'name' => self::ABUSE_ALIAS,
                'type' => 'external',
                'description' => self::ABUSE_ALIAS_DESCRIPTION,
            ]);
        } else {
            if (!$ours) {
                return [$model, false, null];
            }
            if (!empty($model->whereUsed(self::ABUSE_ALIAS))) {
                return [$model, false, sprintf(
                    gettext('%s is used in firewall rules or other aliases: remove it there first.'),
                    self::ABUSE_ALIAS
                )];
            }
            $model->aliases->alias->del($foundUuid);
        }
        $messages = [];
        foreach ($model->performValidation() as $message) {
            $messages[] = $message->getMessage();
        }
        return [$model, true, empty($messages) ? null : implode(' ', $messages)];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $model = new FirewallMap();
        $general = $model->general;
        $ensure = false;
        $fetchBlacklist = false;
        $aliasBefore = (string)$general->abuseipdb_alias;
        /* the database is only re-checked when something that decides which one to fetch changed */
        $databaseBefore = [(string)$general->provider, (string)$general->update_days, (string)$general->license_key];
        foreach (['provider', 'update_days'] as $field) {
            if ($this->request->hasPost($field) && $this->request->getPost($field) !== '') {
                $general->$field = $this->request->getPost($field);
            }
        }
        if ($this->request->hasPost('record_threats')) {
            $general->record_threats = $this->request->getPost('record_threats') === '1' ? '1' : '0';
            $ensure = $general->record_threats == '1';
        }
        if ($this->request->hasPost('abuseipdb_alias')) {
            $general->abuseipdb_alias = $this->request->getPost('abuseipdb_alias') === '1' ? '1' : '0';
        }
        if ($this->request->hasPost('threat_lists')) {
            $general->threat_lists = (string)$this->request->getPost('threat_lists');
        }
        if ($this->request->hasPost('abuseipdb_key')) {
            /* write-only like the MaxMind key: empty keeps it, "-" removes it */
            $abuse = trim((string)$this->request->getPost('abuseipdb_key'));
            if ($abuse === '-') {
                $general->abuseipdb_key = '';
            } elseif ($abuse !== '') {
                $general->abuseipdb_key = $abuse;
                $fetchBlacklist = true;
            }
        }
        if ($this->request->hasPost('license_key')) {
            $key = trim((string)$this->request->getPost('license_key'));
            if ($key === '-') {
                /* explicit reset: fall back to the GeoIP alias key */
                $general->license_key = '';
            } elseif ($key !== '') {
                $general->license_key = $key;
            }
        }
        $messages = [];
        foreach ($model->performValidation() as $message) {
            $messages[] = $message->getMessage();
        }
        if (!empty($messages)) {
            return ['result' => 'failed', 'validations' => $messages];
        }
        [$aliasModel, $aliasChanged, $aliasError] = $this->reconcileAbuseAlias((string)$general->abuseipdb_alias === '1');
        if ($aliasError !== null) {
            return ['result' => 'failed', 'validations' => [$aliasError]];
        }
        $model->serializeToConfig();
        if ($aliasChanged) {
            $aliasModel->serializeToConfig();
        }
        Config::getInstance()->save();
        /* Reload in place: preserve live flow/alert history while rebuilding the chosen list index. */
        (new Backend())->configdRun('firewallmap reload');
        if ((string)$general->abuseipdb_alias !== $aliasBefore || $aliasChanged) {
            /* Apply the alias definition without creating or changing any firewall rule. */
            (new Backend())->configdRun('filter reload skip_alias');
            (new Backend())->configdRun('template reload OPNsense/Filter');
            (new Backend())->configdRun('filter refresh_aliases');
            (new Backend())->configdRun('firewallmap abuseipdb sync');
        }
        if ($fetchBlacklist) {
            (new Backend())->configdRun('firewallmap abuseipdb refresh', true);
        }
        if ($ensure) {
            (new Backend())->configdRun('firewallmap ensure', true);
        }
        $databaseAfter = [(string)$general->provider, (string)$general->update_days, (string)$general->license_key];
        if ($databaseAfter !== $databaseBefore) {
            (new Backend())->configdRun('firewallmap geodb update', true);
        }
        return ['result' => 'saved'];
    }

    /**
     * Tables that can serve as threat lists: blocklist-type aliases and feed tables.
     */
    public function tablesAction()
    {
        $result = json_decode((new Backend())->configdRun('firewallmap tables'), true);
        return is_array($result) ? $result : ['tables' => [], 'automatic' => []];
    }
}
