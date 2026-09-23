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

        $nameservers = json_decode($backend->configdRun('system list nameservers'), true);
        $result['dns_servers'] = is_array($nameservers) ? array_values($nameservers) : [];
        $result['user'] = $this->getUserName();
        $result['status'] = 'ok';

        return $result;
    }

    public function frequencyAction()
    {
        $backend = new Backend();
        $result = json_decode($backend->configdRun('dashboardplus system frequency'), true);

        return is_array($result) ? $result : [];
    }
}
