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
use OPNsense\Core\ACL;
use OPNsense\Core\Backend;
use OPNsense\FirewallMap\AuditLog;
use OPNsense\FirewallMap\ConfigdArgument;
use OPNsense\FirewallMap\FlowSummary;

/**
 * Saved map snapshots: everyone who may view the map takes, lists, reads and annotates them (see ACL);
 * deleting is in SnapshotAdminController, for administrators.
 */
class SnapshotsController extends ApiControllerBase
{
    /** PF state rows are disclosed only through OPNsense's native Show States privilege. */
    private function mayShowStates()
    {
        return (new ACL())->isPageAccessible($this->getUserName(), '/api/diagnostics/firewall/query_states');
    }

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
        $user = (string)$this->getUserName();
        $result = $this->run('save', [ConfigdArgument::text($user, 256)]);
        if ($result['result'] === 'saved') {
            AuditLog::record($user, "saved snapshot {$result['snapshot']['id']}");
        }
        return $result;
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
        $result = $this->run('get', [(string)$id, (string)$minimum]);
        /* a capture (version 2) keeps every Focus: the viewer sees its own, as on the live map;
         * older captures have one flow list and are returned as saved */
        $focus = $this->request->get('focus');
        $focus = is_string($focus) && preg_match('/^[a-z0-9_-]{1,32}$/', $focus) ? $focus : null;
        if (isset($result['data']) && is_array($result['data'])) {
            $result['data'] = FlowSummary::applyFocus($result['data'], $focus);
        }
        /* Snapshots are shared incident records. Keep complete captures on disk, but never disclose
         * their embedded PF states to a user who cannot use Diagnostics: Show States. */
        if (!$this->mayShowStates() && isset($result['data']) && is_array($result['data'])) {
            unset($result['data']['states']);
        }
        return $result;
    }

    public function noteAction($id = null)
    {
        if (!$this->request->isPost() || !ConfigdArgument::isSnapshotId($id)) {
            return ['result' => 'failed'];
        }
        $result = $this->run('note', [(string)$id, ConfigdArgument::text($this->request->getPost('note') ?? '', 1500)]);
        if ($result['result'] === 'saved') {
            AuditLog::record((string)$this->getUserName(), "changed the note of snapshot {$id}");
        }
        return $result;
    }
}
