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

/*
 * Whether any user's dashboard holds the Firewall Map widget, written for the collector (threat
 * history is recorded in the background only then). Asked through OPNsense's User model, after
 * every configuration save (rc.syshook.d/config/50-firewallmap) and on install.
 */

require_once 'script/load_phalcon.php';

use OPNsense\Auth\User;

$inUse = false;
foreach ((new User())->user->iterateItems() as $user) {
    foreach ($user->dashboard->deserialize()['widgets'] ?? [] as $widget) {
        if (is_array($widget) && ($widget['id'] ?? '') === 'firewallmap') {
            $inUse = true;
            break 2;
        }
    }
}

$directory = '/var/db/firewallmap';
if (!is_dir($directory)) {
    mkdir($directory, 0750, true);
}
$file = "{$directory}/dashboards.json";
$content = json_encode(['widget_in_use' => $inUse]) . "\n";
/* a private temporary name, and the old file stays until the new one is complete (a full disk or
 * two runs at once never leave an empty file behind) */
$temporary = tempnam($directory, 'dashboards.');
if (
    $temporary === false
    || file_put_contents($temporary, $content) !== strlen($content)
    || !chmod($temporary, 0640)
    || !rename($temporary, $file)
) {
    if ($temporary !== false && is_file($temporary)) {
        unlink($temporary);
    }
    fwrite(STDERR, "could not write {$file}\n");
    exit(1);
}
echo $content;
