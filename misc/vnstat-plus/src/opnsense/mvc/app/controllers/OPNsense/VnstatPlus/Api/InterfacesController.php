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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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

namespace OPNsense\VnstatPlus\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class InterfacesController extends ApiControllerBase
{
    /**
     * Return only interfaces selected in VNStat, pairing each device name with its OPNsense label.
     */
    public function listAction()
    {
        $tracked = array_filter(array_map('trim', explode("\n", trim(
            (new Backend())->configdRun('vnstat dbiflist')
        ))));
        $config = Config::getInstance()->object();
        $configured = array_filter(array_map('trim', explode(
            ',',
            (string)($config->OPNsense->vnstat->general->interface ?? '')
        )));
        $interfaces = [];

        foreach ($config->interfaces->children() as $alias => $interface) {
            $device = (string)$interface->if;
            if (!in_array((string)$alias, $configured, true) || !in_array($device, $tracked, true)) {
                continue;
            }
            $description = trim((string)$interface->descr);
            $interfaces[] = [
                'value' => $device,
                'label' => $description !== '' ? $description : strtoupper((string)$alias),
            ];
        }

        return ['interfaces' => $interfaces];
    }
}
