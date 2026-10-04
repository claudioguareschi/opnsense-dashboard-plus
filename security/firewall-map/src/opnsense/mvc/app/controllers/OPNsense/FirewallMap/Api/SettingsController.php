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
use OPNsense\Core\Syslog;
use OPNsense\FirewallMap\BlocklistAliases;

/**
 * Firewall Map+ settings (Reporting: Firewall Map: Settings): OPNsense's standard get and set, and
 * reconfigure for the Apply button. The keys are write-only fields: never sent back, an empty key
 * keeps the stored one, and "Remove the stored key" clears it.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'firewallmap';
    protected static $internalModelClass = 'OPNsense\FirewallMap\FirewallMap';

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
        return [
            'license_key_set' => $general->license_key->getValue() !== '',
            'abuseipdb_configured' => $general->abuseipdb_key->getValue() !== '',
            'record_threats' => (string)$general->record_threats,
            'abuseipdb_blacklist' => $this->blacklistStatus(),
            'database' => $this->databaseStatus(),
        ];
    }

    /**
     * Apply the saved settings. Every step only does what the settings ask for and is not done yet,
     * so applying twice changes nothing: the blocklist aliases (definitions only, never rules), the
     * collector's settings, and the feed, AbuseIPDB and geolocation downloads.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        Config::getInstance()->lock();
        $general = $this->getModel()->general;
        [$aliases, $changes, $error] = BlocklistAliases::reconcile(
            (string)$general->blocklist_aliases === '1',
            (string)$general->threat_lists,
            $general->abuseipdb_key->getValue() !== ''
        );
        if ($error === null && $changes) {
            $aliases->serializeToConfig();
            Config::getInstance()->save();
        }
        Config::getInstance()->unlock();
        $log = new Syslog('firewallmap', null, LOG_DAEMON);
        if ($error !== null) {
            $log->warning("settings not applied: {$error}");
            return ['status' => 'failed', 'status_msg' => $error];
        }
        if ($changes) {
            BlocklistAliases::apply();
            $log->notice('blocklist aliases: ' . implode(', ', $changes));
        }
        $log->notice('settings applied');
        /* the scripts read the settings from the file this template renders, never from config.xml */
        $backend->configdRun('template reload OPNsense/FirewallMap');
        /* reload in place: keep live flow and alert history while the chosen list index is rebuilt */
        $backend->configdRun('firewallmap reload');
        $backend->configdRun('firewallmap feeds update', true);
        /* downloads only for a new key, or once a day: the free plan allows only a few a day */
        $backend->configdRun('firewallmap abuseipdb update', true);
        $backend->configdRun('firewallmap abuseipdb sync', true);
        $backend->configdRun('firewallmap ensure', true);
        /* a new key or provider downloads now, not after an earlier failure's wait */
        $backend->configdRun('firewallmap geodb retry', true);
        return ['status' => 'ok'];
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
