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
use OPNsense\Core\Config;
use OPNsense\DashboardPlus\Carp;
use OPNsense\DashboardPlus\Metrics;
use OPNsense\DashboardPlus\QuickAssist;

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
        // read by metrics.sh through configd (shared by every viewer for five seconds), parsed here
        $result = Metrics::parse((new Backend())->configdRun('dashboardplus system metrics'));

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

    /**
     * CARP+: this firewall's CARP role over all its VIPs, each VIP, pfsync and config sync, and the
     * last CARP state changes, labelled with the configuration's interface and VIP names.
     */
    public function carpAction()
    {
        $backend = new Backend();
        $output = $backend->configdRun('dashboardplus system carp');
        $history = $backend->configdRun('dashboardplus system carp.history');
        $config = Config::getInstance()->object();
        $interfaces = [];
        foreach ($config->interfaces->children() as $identifier => $node) {
            $interfaces[$identifier] = ['if' => (string)$node->if, 'descr' => (string)$node->descr];
        }
        $vips = [];
        if (isset($config->virtualip)) {
            foreach ($config->virtualip->children() as $vip) {
                if ((string)$vip->mode === 'carp') {
                    $vips[] = ['interface' => (string)$vip->interface, 'vhid' => (string)$vip->vhid, 'descr' => (string)$vip->descr];
                }
            }
        }
        $hasync = isset($config->hasync) ? [
            'pfsyncinterface' => (string)$config->hasync->pfsyncinterface,
            'pfsyncpeerip' => (string)$config->hasync->pfsyncpeerip,
            'synchronizetoip' => (string)$config->hasync->synchronizetoip,
        ] : [];
        $result = Carp::summary($output, $history, [
            'interfaces' => $interfaces, 'vips' => $vips, 'hasync' => $hasync,
            'hostname' => (string)$config->system->hostname,
        ], microtime(true));
        $result['status'] = 'ok';
        return $result;
    }

    /**
     * Read-only QuickAssist topology, health and firmware-counter sample: the QAT sysctl tree,
     * read by configd and parsed here (QuickAssist.php), so a sample every two seconds starts no
     * interpreter.
     */
    public function qatAction()
    {
        $output = (new Backend())->configdRun('dashboardplus system qat');
        $result = QuickAssist::sample($output, microtime(true));
        $result['status'] = 'ok';
        return $result;
    }
}
