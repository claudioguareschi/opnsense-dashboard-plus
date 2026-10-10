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
use OPNsense\FirewallMap\Reports;

/**
 * The pf tables that can serve as country or operational classification sets: every table loaded
 * now except OPNsense's internal ones, as the collector lists them, or only the aliases of one type
 * (<AliasType> in the model: country sets offer GeoIP aliases). Asking for them takes a configd
 * call, so the list is built only when the settings form or a validation needs it, once per request.
 */
class ClassificationSetField extends BaseListField
{
    private $aliasType = '';

    public function setAliasType($value)
    {
        $this->aliasType = (string)$value;
    }

    private function loadOptions()
    {
        if (!$this->hasStaticOptions('')) {
            $offered = ['' => []];
            $report = Reports::tables();
            foreach ($report['sets'] ?? [] as $table) {
                if (!empty($table['name'])) {
                    $label = $table['description'] !== '' ? sprintf('%s (%s)', $table['name'], $table['description']) : $table['name'];
                    $offered[''][$table['name']] = $label;
                    $offered[$table['type'] ?? ''][$table['name']] = $label;
                }
            }
            foreach ($offered as $type => $options) {
                $this->setStaticOptions($options, $type);
            }
        }
        $this->internalOptionList = $this->getStaticOptions($this->aliasType);
        /* a stored table stays listed and valid, so saving still works: one of another type keeps
           its label (it still classifies), one that is gone (alias deleted) is marked */
        $tables = $this->getStaticOptions('');
        foreach (explode(',', $this->getInitialValue()) as $name) {
            if ($name !== '' && !isset($this->internalOptionList[$name])) {
                $this->internalOptionList[$name] = $tables[$name] ?? sprintf(gettext('%s (not found)'), $name);
            }
        }
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
