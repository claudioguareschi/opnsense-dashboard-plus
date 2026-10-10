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

namespace OPNsense\DashboardPlus\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SystemController extends ApiControllerBase
{
    public function infoAction()
    {
        $backend = new Backend();
        $result = json_decode($backend->configdRun('dashboardplus system info'), true);

        if (!is_array($result)) {
            return ['status' => 'failed'];
        }

        $result['user'] = $this->getUserName();
        $result['status'] = 'ok';

        return $result;
    }

    /**
     * Memory, load, CPU frequency, temperatures, pf states, mbufs, swap and filesystems in
     * one request, for System Metrics+, Thermal Sensors+ and System Information+.
     */
    public function metricsAction()
    {
        $backend = new Backend();
        $result = json_decode($backend->configdRun('dashboardplus system metrics'), true);

        if (!is_array($result)) {
            return ['status' => 'failed'];
        }

        // the sensor types as OPNsense's own temperature endpoint translates them
        foreach ($result['temperatures'] ?? [] as $index => $sensor) {
            $result['temperatures'][$index]['type_translated'] =
                ($sensor['type'] ?? '') == 'zone' ? gettext('Zone') : gettext('CPU');
        }
        $result['status'] = 'ok';

        return $result;
    }

    /**
     * The assigned interfaces for Interfaces+: link status, media and primary addresses, as the
     * interfaces overview shows them, without its SFP module reads (interfaces.php).
     */
    public function interfacesAction()
    {
        $backend = new Backend();
        $result = json_decode($backend->configdRun('dashboardplus system interfaces'), true);

        if (!is_array($result) || !is_array($result['rows'] ?? null)) {
            return ['status' => 'failed'];
        }

        $result['status'] = 'ok';
        return $result;
    }

    /** Read-only QuickAssist topology, health and firmware-counter sample. */
    public function qatAction()
    {
        $backend = new Backend();
        $result = json_decode($backend->configdRun('dashboardplus system qat'), true);

        if (!is_array($result)) {
            return ['status' => 'failed'];
        }

        $result['status'] = 'ok';
        return $result;
    }
}
