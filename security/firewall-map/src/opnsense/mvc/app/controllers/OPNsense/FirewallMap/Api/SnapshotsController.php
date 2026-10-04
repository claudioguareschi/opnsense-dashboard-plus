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

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\FirewallMap\ConfigdArgument;

/**
 * Saved map snapshots: everyone who may view the map takes, lists, reads and annotates them (see ACL);
 * deleting is in SnapshotAdminController, for administrators.
 */
class SnapshotsController extends ApiControllerBase
{
    private function run($action, $parameters = [])
    {
        $result = json_decode((new Backend())->configdpRun("firewallmap snapshot {$action}", $parameters) ?? '', true);
        return is_array($result) ? $result : ['result' => 'failed', 'error' => 'no response'];
    }

    public function saveAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $user = $this->session->has('Username') ? $this->session->get('Username') : '';
        return $this->run('save', [ConfigdArgument::text($user, 256)]);
    }

    public function listAction()
    {
        return $this->run('list');
    }

    public function getAction($id = null)
    {
        if (!ConfigdArgument::isSnapshotId($id)) {
            return ['result' => 'failed', 'error' => 'unknown snapshot'];
        }
        $minimum = max(1, min(100, (int)($this->request->get('blocks_min') ?? 1)));
        return $this->run('get', [(string)$id, (string)$minimum]);
    }

    public function noteAction($id = null)
    {
        if (!$this->request->isPost() || !ConfigdArgument::isSnapshotId($id)) {
            return ['result' => 'failed'];
        }
        return $this->run('note', [(string)$id, ConfigdArgument::text($this->request->getPost('note') ?? '', 1500)]);
    }
}
