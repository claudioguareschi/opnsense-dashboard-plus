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
use OPNsense\Core\Config;
use OPNsense\FirewallMap\FieldTypes\RankingProfileField;
use OPNsense\FirewallMap\FirewallMap;
use OPNsense\FirewallMap\Reports;

/**
 * Ranking profiles (Reporting: Firewall Map: Settings), as a standard grid with an edit dialog.
 * Exactly one profile is active: general.ranking_profile holds its UUID. The built-ins are fixed
 * (the scripts define them) and can only be activated or copied; custom profiles are the model's
 * profiles.profile rows. Changes are saved to the configuration and take effect on Apply
 * (service/reconfigure renders the settings and the collector restarts when the active profile's
 * definition changed); editing an inactive profile changes nothing the collector does.
 */
class ProfilesController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'profile';
    protected static $internalModelClass = 'OPNsense\FirewallMap\FirewallMap';

    private function isBuiltin($uuid)
    {
        return isset(RankingProfileField::builtins()[(string)$uuid]);
    }

    /** A built-in's definition in the model's field names (to show it in the dialog for a copy). */
    private function builtinValues($profile)
    {
        $values = ['name' => $profile['name'], 'description' => $profile['description'] ?? '',
                   'default_multiplier' => (string)$profile['default_multiplier'],
                   'assets' => (string)$profile['assets'], 'direction' => (string)$profile['direction']];
        foreach (FirewallMap::FEATURES as $feature) {
            $values[$feature] = (string)$profile['weights'][$feature];
        }
        foreach (FirewallMap::FLOORS as $floor) {
            $values[$floor] = (string)$profile['floors'][$floor];
        }
        return $values;
    }

    /** Every profile, built-ins first, with whether it is built in and whether it is active. */
    public function searchItemAction()
    {
        $model = $this->getModel();
        $active = (string)$model->general->ranking_profile;
        $records = [];
        foreach (RankingProfileField::builtins() as $uuid => $profile) {
            $records[] = ['uuid' => $uuid, 'name' => $profile['name'], 'description' => $profile['description'] ?? '',
                          'builtin' => '1', 'active' => $uuid === $active ? '1' : '0'];
        }
        foreach ($model->profiles->profile->iterateItems() as $uuid => $node) {
            $records[] = ['uuid' => $uuid, 'name' => (string)$node->name, 'description' => (string)$node->description,
                          'builtin' => '0', 'active' => $uuid === $active ? '1' : '0'];
        }
        return $this->searchRecordsetBase($records);
    }

    /** A custom profile, a new one, or a built-in's definition (shown only to be copied). */
    public function getItemAction($uuid = null)
    {
        $builtins = RankingProfileField::builtins();
        if (isset($builtins[(string)$uuid])) {
            /* an unsaved row carries the built-in's values into the dialog */
            $node = $this->getModel()->profiles->profile->Add();
            $node->setNodes($this->builtinValues($builtins[(string)$uuid]));
            $result = ['profile' => $node->getNodes()];
        } else {
            $result = $this->getBase('profile', 'profiles.profile', $uuid);
        }
        if ($this->request->get('fetchmode') === 'copy' && isset($result['profile']['name'])) {
            $result['profile']['name'] = mb_substr(sprintf(gettext('Copy of %s'), $result['profile']['name']), 0, 64);
        }
        return $result;
    }

    public function addItemAction()
    {
        /* configd's reports before the base class takes the config lock (Reports) */
        Reports::warm();
        return $this->addBase('profile', 'profiles.profile');
    }

    /** A custom profile keeps its UUID when edited; a built-in cannot be edited (copy it). */
    public function setItemAction($uuid)
    {
        if ($this->isBuiltin($uuid) || $this->getModel()->getNodeByReference('profiles.profile.' . $uuid) === null) {
            return ['result' => 'failed'];
        }
        Reports::warm();
        return $this->setBase('profile', 'profiles.profile', $uuid);
    }

    /** The active profile cannot be deleted: activate another one first. */
    public function delItemAction($uuid)
    {
        if ((string)$this->getModel()->general->ranking_profile === (string)$uuid) {
            return ['result' => 'failed'];
        }
        Reports::warm();
        return $this->delBase('profiles.profile', $uuid);
    }

    /** Make a profile the active one (the collector restarts with it on Apply). */
    public function activateAction($uuid)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Reports::warm();
        Config::getInstance()->lock();
        $model = $this->getModel();
        $model->general->ranking_profile = (string)$uuid;
        /* the whole model: the activated profile's own row must be valid as well, or the collector
           would refuse it and rank with Balanced while the grid shows it active */
        $row = 'profiles.profile.' . $uuid . '.';
        foreach ($model->performValidation(true) as $message) {
            $field = $message->getField();
            if ($field === 'general.ranking_profile' || strpos($field, $row) === 0) {
                return ['result' => 'failed', 'message' => $message->getMessage()];
            }
        }
        $this->save(false, true);
        return ['result' => 'saved'];
    }
}
