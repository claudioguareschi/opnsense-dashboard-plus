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
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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

namespace OPNsense\FirewallMap;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class FirewallMap extends BaseModel
{
    /** The collector's feature vocabulary and limits (collector/profile.h, lib/profiles.py). */
    public const FEATURES = ['byte_rate', 'packet_rate', 'active_states', 'new_state_rate', 'flow_volume',
                             'pf_blocked', 'threat_intelligence', 'ids_evidence'];
    public const FLOORS = ['s3_min_percent', 's2_min_percent', 's1_min_percent'];
    private const ASSET_RULES_MAX = 4096;
    private const MULTIPLIER_MIN = 0.000001;
    private const MULTIPLIER_MAX = 1000000;

    /**
     * Asset rules from their text, one "CIDR multiplier" per line (an address alone is a host):
     * [[network, prefix, multiplier]...], or an error message. The same checks as the collector:
     * canonical networks (no host bits), multipliers within its limits, one multiplier per prefix.
     */
    public static function parseAssets($text)
    {
        $rules = [];
        $seen = [];
        foreach (preg_split('/\r?\n/', (string)$text) as $number => $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $parts = preg_split('/\s+/', $line);
            if (count($parts) !== 2) {
                return sprintf(gettext('Asset rule %d: enter a network and a multiplier.'), $number + 1);
            }
            [$network, $multiplier] = $parts;
            [$address, $prefix] = array_pad(explode('/', $network, 2), 2, null);
            $bytes = filter_var($address, FILTER_VALIDATE_IP) !== false ? inet_pton($address) : false;
            $bits = $bytes === false ? 0 : strlen($bytes) * 8;
            if ($prefix === null) {
                $prefix = (string)$bits;
            }
            if ($bytes === false || !preg_match('/^(0|[1-9][0-9]{0,2})$/', $prefix) || (int)$prefix > $bits) {
                return sprintf(gettext('Asset rule %d: %s is not a network.'), $number + 1, $network);
            }
            for ($bit = (int)$prefix; $bit < $bits; $bit++) {
                if (ord($bytes[intdiv($bit, 8)]) & (0x80 >> ($bit % 8))) {
                    return sprintf(gettext('Asset rule %d: %s has host bits set; enter the network address.'),
                                   $number + 1, $network);
                }
            }
            if (!is_numeric($multiplier) || (float)$multiplier < self::MULTIPLIER_MIN ||
                (float)$multiplier > self::MULTIPLIER_MAX) {
                return sprintf(gettext('Asset rule %d: the multiplier is from 0.000001 to 1000000.'), $number + 1);
            }
            $key = inet_ntop($bytes) . '/' . (int)$prefix;
            if (isset($seen[$key]) && $seen[$key] !== (float)$multiplier) {
                return sprintf(gettext('Asset rule %d: %s already has another multiplier.'), $number + 1, $key);
            }
            if (!isset($seen[$key])) {
                $seen[$key] = (float)$multiplier;
                $rules[] = [$key, (float)$multiplier];
            }
        }
        if (count($rules) > self::ASSET_RULES_MAX) {
            return sprintf(gettext('At most %d asset rules.'), self::ASSET_RULES_MAX);
        }
        return $rules;
    }

    /** A custom profile's own checks: weights totalling 100, floors at most 100%, asset rules. */
    private function validateProfile($profile, $messages)
    {
        $field = 'profiles.profile.' . $profile->getAttributes()['uuid'] . '.';
        $total = 0.0;
        foreach (self::FEATURES as $feature) {
            $total += (float)(string)$profile->$feature;
        }
        if (abs($total - 100) > 1e-9) {
            $messages->appendMessage(new Message(
                sprintf(gettext('The quality weights total %s; they must total exactly 100.'), round($total, 6)),
                $field . 'byte_rate'
            ));
        }
        $floors = 0.0;
        foreach (self::FLOORS as $floor) {
            $floors += (float)(string)$profile->$floor;
        }
        if ($floors > 100) {
            $messages->appendMessage(new Message(
                gettext('The security visibility floors total more than 100%.'),
                $field . 's3_min_percent'
            ));
        }
        $rules = self::parseAssets((string)$profile->assets);
        if (is_string($rules)) {
            $messages->appendMessage(new Message($rules, $field . 'assets'));
        }
    }


    /** Whether "Maintain blocklist aliases" can be applied: our aliases never replace or drop others' */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $general = $this->general;
        $removeKey = (string)$general->remove_abuseipdb_key === '1';
        $changed = $validateFullModel || $removeKey || $general->blocklist_aliases->isFieldChanged() ||
            $general->threat_lists->isFieldChanged() || $general->abuseipdb_key->isFieldChanged();
        if ($changed) {
            [, , $error] = BlocklistAliases::reconcile(
                (string)$general->blocklist_aliases === '1',
                (string)$general->threat_lists,
                !$removeKey && $general->abuseipdb_key->getValue() !== ''
            );
            if ($error !== null) {
                $messages->appendMessage(new Message($error, 'general.blocklist_aliases'));
            }
        }
        /* a handful of rows: every custom profile is checked on every save */
        foreach ($this->profiles->profile->iterateItems() as $profile) {
            $this->validateProfile($profile, $messages);
        }
        $latitude = trim((string)$general->latitude);
        $longitude = trim((string)$general->longitude);
        $decimalDegrees = '/^-?(?:[0-9]+(?:\\.[0-9]+)?)$/D';
        if (($latitude === '') !== ($longitude === '')) {
            $messages->appendMessage(new Message('Enter both latitude and longitude, or leave both empty.', 'general.latitude'));
        } elseif ($latitude !== '' && (!preg_match($decimalDegrees, $latitude) || !preg_match($decimalDegrees, $longitude) ||
                  (float)$latitude < -90 || (float)$latitude > 90 ||
                  (float)$longitude < -180 || (float)$longitude > 180)) {
            $messages->appendMessage(new Message('Enter decimal degrees: latitude from -90 to 90 and longitude from -180 to 180.',
                                                 'general.latitude'));
        }
        return $messages;
    }
}
