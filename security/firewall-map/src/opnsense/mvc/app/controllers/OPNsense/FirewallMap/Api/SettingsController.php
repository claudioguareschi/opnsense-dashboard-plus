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
use OPNsense\FirewallMap\BlocklistAliases;

/**
 * Firewall Map+ settings (Reporting: Firewall Map: Settings): OPNsense's standard get and set; the
 * Apply button calls service/reconfigure. The keys are write-only fields: never sent back, an empty
 * key keeps the stored one, and "Remove the stored key" clears it.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'firewallmap';
    protected static $internalModelClass = 'OPNsense\FirewallMap\FirewallMap';

    /**
     * Validation checks the blocklist aliases against the curated feeds (see the model): ask configd
     * for them before the config lock is taken, not while holding it.
     */
    public function setAction()
    {
        if ($this->request->isPost()) {
            BlocklistAliases::feeds();
        }
        return parent::setAction();
    }

    /** "Remove the stored key": a write-only field cannot be emptied by posting an empty value */
    protected function setActionHook()
    {
        $general = $this->getModel()->general;
        foreach (['license_key', 'abuseipdb_key'] as $key) {
            if ((string)$general->{'remove_' . $key} === '1') {
                $general->$key->applyDefault();
            }
        }
    }

    /** The AbuseIPDB list download status, read directly: the map page asks for it on every load. */
    private function blacklistStatus()
    {
        $file = '/var/db/firewallmap/abuseipdb.json';
        $status = is_file($file) ? (json_decode((string)file_get_contents($file), true) ?: []) : [];
        /* the key's fingerprint stays on the firewall */
        unset($status['key_id']);
        return $status;
    }

    private function databaseStatus()
    {
        $status = json_decode((new Backend())->configdRun('firewallmap geodb status'), true);
        return is_array($status) ? $status : [];
    }

    /**
     * What the settings page and the map show beside the settings: whether keys are stored, the
     * downloads' status and threat recording (the map's threat tab switches it).
     */
    public function statusAction()
    {
        $general = $this->getModel()->general;
        /* chosen threat lists and sets the collector could not use (no PF table): never silent */
        $overview = json_decode((string)(new Backend())->configdRun('firewallmap overview'), true);
        $classification = is_array($overview) ? ($overview['threat_lists'] ?? []) : [];
        return [
            'threat_lists_unavailable' => array_column($classification['unavailable'] ?? [], 'name'),
            'sets_missing' => $classification['missing'] ?? [],
            'license_key_set' => $general->license_key->getValue() !== '',
            'abuseipdb_configured' => $general->abuseipdb_key->getValue() !== '',
            'record_threats' => (string)$general->record_threats,
            'abuseipdb_blacklist' => $this->blacklistStatus(),
            'database' => $this->databaseStatus(),
        ];
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
}
