<?php

/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\FirewallMap\BlocklistAliases;

/**
 * Firewall-wide Firewall Map+ settings, edited from the widget's settings dialog: the geolocation
 * provider and key, the AbuseIPDB key, the threat lists, threat recording and the blocklist
 * aliases. OPNsense's standard settings controller (config lock, field-keyed validation messages,
 * the {"firewallmap": {"general": {...}}} shape), with two differences:
 * - the keys are write-only: never returned; an empty key keeps the stored one, "-" removes it;
 * - saving applies what changed: the blocklist aliases, the list index, downloads.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'firewallmap';
    protected static $internalModelClass = 'OPNsense\FirewallMap\FirewallMap';

    private const KEYS = ['license_key', 'abuseipdb_key'];

    /** The AbuseIPDB list download status, read directly: this runs on every widget and page load. */
    private function blacklistStatus()
    {
        $file = '/var/db/firewallmap/abuseipdb.json';
        return is_file($file) ? (json_decode((string)file_get_contents($file), true) ?: []) : [];
    }

    private function databaseStatus()
    {
        $status = json_decode((new Backend())->configdRun('firewallmap geodb status'), true);
        return is_array($status) ? $status : [];
    }

    /** What the blocklist aliases follow: the switch, the chosen lists and whether an AbuseIPDB key exists. */
    private function aliasInputs($general)
    {
        return [
            (string)$general->blocklist_aliases,
            (string)$general->threat_lists,
            (string)$general->abuseipdb_key !== '',
        ];
    }

    private function snapshot($general)
    {
        return [
            'aliases' => $this->aliasInputs($general),
            'lists' => (string)$general->threat_lists,
            'record' => (string)$general->record_threats,
            'abuse_key' => (string)$general->abuseipdb_key,
            'database' => [(string)$general->provider, (string)$general->update_days, (string)$general->license_key],
        ];
    }

    /** The settings without the keys, and the status the dialog shows beside them. */
    public function getAction()
    {
        $result = parent::getAction();
        $general = $this->getModel()->general;
        foreach (self::KEYS as $key) {
            $result[static::$internalModelName]['general'][$key] = '';
        }
        $result['status'] = [
            'abuseipdb_configured' => (string)$general->abuseipdb_key !== '',
            'abuseipdb_blacklist' => $this->blacklistStatus(),
            'database' => $this->databaseStatus(),
        ];
        return $result;
    }

    /** The posted settings, with the write-only keys handled: empty keeps the stored key, "-" removes it. */
    private function postedGeneral()
    {
        $posted = $this->request->getPost(static::$internalModelName);
        $general = is_array($posted) && is_array($posted['general'] ?? null) ? $posted['general'] : [];
        foreach (self::KEYS as $key) {
            if (array_key_exists($key, $general)) {
                $value = trim((string)$general[$key]);
                if ($value === '') {
                    unset($general[$key]);
                } else {
                    $general[$key] = $value === '-' ? '' : $value;
                }
            }
        }
        return $general;
    }

    /** Core's setAction (lock, set, validate, save), plus the keys, the aliases and what to apply. */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Config::getInstance()->lock();
        $model = $this->getModel();
        $before = $this->snapshot($model->general);
        $model->setNodes(['general' => $this->postedGeneral()]);
        $result = $this->validate();
        if (!empty($result['result'])) {
            return $result;
        }
        $aliasesChanged = false;
        if ($this->aliasInputs($model->general) !== $before['aliases']) {
            [$aliases, $aliasesChanged, $error] = BlocklistAliases::reconcile(
                (string)$model->general->blocklist_aliases === '1',
                (string)$model->general->threat_lists,
                (string)$model->general->abuseipdb_key !== ''
            );
            if ($error !== null) {
                $field = static::$internalModelName . '.general.blocklist_aliases';
                return ['result' => 'failed', 'validations' => [$field => $error]];
            }
            if ($aliasesChanged) {
                $aliases->serializeToConfig();
            }
        }
        $result = $this->save(false, true);
        $this->apply($before, $aliasesChanged);
        return $result;
    }

    /** What saving changed, applied: list index, aliases, downloads, threat recording. */
    private function apply($before, $aliasesChanged)
    {
        $after = $this->snapshot($this->getModel()->general);
        $backend = new Backend();
        /* reload in place: keep live flow and alert history while the chosen list index is rebuilt */
        $backend->configdRun('firewallmap reload');
        if ($aliasesChanged || $after['aliases'][0] !== $before['aliases'][0]) {
            /* alias definitions only: no firewall rule is created or changed */
            BlocklistAliases::apply();
        }
        if ($after['lists'] !== $before['lists']) {
            $backend->configdRun('firewallmap feeds update', true);
        }
        /* the free plan allows only a few list downloads a day: fetch again only for a new key */
        if ($after['abuse_key'] !== '' && $after['abuse_key'] !== $before['abuse_key']) {
            $backend->configdRun('firewallmap abuseipdb refresh', true);
        }
        if ($after['record'] === '1' && $before['record'] !== '1') {
            $backend->configdRun('firewallmap ensure', true);
        }
        if ($after['database'] !== $before['database']) {
            /* a new key or provider: download now, not after an earlier failure's wait */
            $backend->configdRun('firewallmap geodb retry', true);
        }
    }

    /**
     * "Retry now" on the map's geolocation card: download the database without waiting out the
     * earlier failure. Runs in the background; the map shows its progress.
     */
    public function retryGeodbAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        (new Backend())->configdRun('firewallmap geodb retry', true);
        return ['result' => 'started'];
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
