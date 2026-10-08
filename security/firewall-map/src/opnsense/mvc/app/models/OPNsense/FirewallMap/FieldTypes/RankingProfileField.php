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
namespace OPNsense\FirewallMap\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;
use OPNsense\Core\Backend;

/**
 * The active ranking profile, by UUID (never by name or position): the built-in profiles as the
 * collector lists them. Asking for them takes a configd call, so the list is built only when the
 * settings form or a validation needs it, once per request.
 */
class RankingProfileField extends BaseListField
{
    private function loadOptions()
    {
        if (!$this->hasStaticOptions()) {
            $options = [];
            $report = json_decode((string)(new Backend())->configdRun('firewallmap profiles'), true);
            foreach ($report['profiles'] ?? [] as $profile) {
                if (!empty($profile['uuid']) && !empty($profile['name'])) {
                    $options[$profile['uuid']] = $profile['name'];
                }
            }
            $this->setStaticOptions($options);
        }
        $this->internalOptionList = $this->getStaticOptions();
    }

    public function getNodeData()
    {
        $this->loadOptions();
        return parent::getNodeData();
    }

    public function getValidators()
    {
        $this->loadOptions();
        return parent::getValidators();
    }
}
