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
use OPNsense\FirewallMap\FieldTypes\RankingProfileField;
use OPNsense\FirewallMap\FirewallMap;

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

    /**
     * Ranking profiles. The built-ins are fixed (the scripts define them); custom profiles are this
     * model's profiles.profile rows, each made by copying a built-in or another custom profile. The active one is general.ranking_profile, by UUID. Every change
     * is applied at once: the scripts read the rendered settings, and the collector restarts only
     * when the active profile's definition changed (editing an inactive profile changes nothing).
     */
    private function applyProfiles()
    {
        $backend = new Backend();
        $backend->configdRun('template reload OPNsense/FirewallMap');
        $backend->configdRun('firewallmap reload');
    }

    private function isBuiltin($uuid)
    {
        return isset(RankingProfileField::builtins()[(string)$uuid]);
    }

    private function profileRow($uuid, $node)
    {
        $row = ['uuid' => $uuid, 'name' => (string)$node->name, 'description' => (string)$node->description,
                'builtin' => false, 'weights' => [], 'floors' => [],
                'default_multiplier' => (float)(string)$node->default_multiplier,
                'assets' => (string)$node->assets, 'direction' => (string)$node->direction];
        foreach (FirewallMap::FEATURES as $feature) {
            $row['weights'][$feature] = (float)(string)$node->$feature;
        }
        foreach (FirewallMap::FLOORS as $floor) {
            $row['floors'][$floor] = (float)(string)$node->$floor;
        }
        return $row;
    }

    /** Every profile with its definition, built-ins first, and which one is active. */
    public function profilesAction()
    {
        $model = $this->getModel();
        $active = (string)$model->general->ranking_profile;
        $profiles = array_values(RankingProfileField::builtins());
        foreach ($model->profiles->profile->iterateItems() as $uuid => $node) {
            $profiles[] = $this->profileRow($uuid, $node);
        }
        foreach ($profiles as &$profile) {
            $profile['active'] = $profile['uuid'] === $active;
        }
        return ['active' => $active, 'profiles' => $profiles];
    }

    public function getProfileAction($uuid = null)
    {
        return $this->getBase('profile', 'profiles.profile', $uuid);
    }

    /** A custom profile keeps its UUID when edited; a built-in cannot be edited (copy it). */
    public function setProfileAction($uuid)
    {
        if ($this->isBuiltin($uuid) || $this->getModel()->getNodeByReference('profiles.profile.' . $uuid) === null) {
            return ['result' => 'failed'];
        }
        $result = $this->setBase('profile', 'profiles.profile', $uuid);
        if (($result['result'] ?? '') === 'saved') {
            $this->applyProfiles();
        }
        return $result;
    }

    /** The active profile cannot be deleted: activate another one first. */
    public function delProfileAction($uuid)
    {
        if ((string)$this->getModel()->general->ranking_profile === (string)$uuid) {
            return ['result' => 'failed', 'message' => gettext('Activate another profile before deleting this one.')];
        }
        $result = $this->delBase('profiles.profile', $uuid);
        if (($result['result'] ?? '') === 'deleted') {
            $this->applyProfiles();
        }
        return $result;
    }

    /** A copy of a built-in or custom profile: a new custom profile with its own UUID. */
    public function copyProfileAction($uuid)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $builtins = RankingProfileField::builtins();
        if (isset($builtins[(string)$uuid])) {
            $source = $builtins[(string)$uuid];
        } else {
            $node = $this->getModel()->getNodeByReference('profiles.profile.' . $uuid);
            if ($node === null) {
                return ['result' => 'failed'];
            }
            $source = $this->profileRow((string)$uuid, $node);
        }
        $values = ['name' => mb_substr(sprintf(gettext('Copy of %s'), $source['name']), 0, 64),
                   'description' => (string)($source['description'] ?? ''),
                   'default_multiplier' => (string)$source['default_multiplier'],
                   'assets' => (string)$source['assets'], 'direction' => (string)$source['direction']];
        foreach (FirewallMap::FEATURES as $feature) {
            $values[$feature] = (string)$source['weights'][$feature];
        }
        foreach (FirewallMap::FLOORS as $floor) {
            $values[$floor] = (string)$source['floors'][$floor];
        }
        Config::getInstance()->lock();
        $model = $this->getModel();
        $node = $model->profiles->profile->Add();
        $node->setNodes($values);
        $result = $this->validate($node, 'profile');
        if (!empty($result['validations'])) {
            return ['result' => 'failed', 'validations' => $result['validations']];
        }
        $this->save(false, true);
        $this->applyProfiles();
        return ['result' => 'saved', 'uuid' => $node->getAttribute('uuid')];
    }

    /** Make a profile the active one: the collector restarts with it. */
    public function activateProfileAction($uuid)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Config::getInstance()->lock();
        $model = $this->getModel();
        $model->general->ranking_profile = (string)$uuid;
        $messages = $model->performValidation();
        foreach ($messages as $message) {
            if ($message->getField() === 'general.ranking_profile' ||
                strpos($message->getField(), 'profiles.profile.' . $uuid . '.') === 0) {
                return ['result' => 'failed', 'message' => $message->getMessage()];
            }
        }
        $this->save(false, true);
        $this->applyProfiles();
        return ['result' => 'saved'];
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
