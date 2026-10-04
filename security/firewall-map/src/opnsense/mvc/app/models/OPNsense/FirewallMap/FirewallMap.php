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
