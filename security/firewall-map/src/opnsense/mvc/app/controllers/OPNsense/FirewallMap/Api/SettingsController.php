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
use OPNsense\FirewallMap\FirewallMap;

/**
 * Firewall-wide Firewall Map+ settings (geolocation database), edited from the widget's
 * settings dialog. The license key is write-only: it is never returned to the browser.
 */
class SettingsController extends ApiControllerBase
{
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
            'database' => $this->status(),
        ];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $model = new FirewallMap();
        $general = $model->general;
        foreach (['provider', 'update_days'] as $field) {
            if ($this->request->hasPost($field) && $this->request->getPost($field) !== '') {
                $general->$field = $this->request->getPost($field);
            }
        }
        if ($this->request->hasPost('record_threats')) {
            $general->record_threats = $this->request->getPost('record_threats') === '1' ? '1' : '0';
            $ensure = $general->record_threats == '1';
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
        $model->serializeToConfig();
        Config::getInstance()->save();
        if (!empty($fetchBlacklist)) {
            (new Backend())->configdRun('firewallmap abuseipdb refresh', true);
        }
        if (!empty($ensure)) {
            (new Backend())->configdRun('firewallmap ensure', true);
        }
        (new Backend())->configdRun('firewallmap geodb update', true);
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

    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        (new Backend())->configdRun('firewallmap geodb refresh', true);
        return ['result' => 'started'];
    }
}
