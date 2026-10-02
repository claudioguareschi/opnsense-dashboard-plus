#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschi@gmail.com>
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
 * Run on install and upgrade. Sets "Maintain blocklist aliases" the first time this version
 * sees the firewall: on when this plugin's FWMAP_* aliases already exist (earlier releases made
 * them whenever a feed was chosen), off otherwise. Then brings the aliases in line, so
 * FWMAP_AbuseIPDB appears next to the feed aliases. Rules are never touched.
 */

require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\FirewallMap\BlocklistAliases;
use OPNsense\FirewallMap\FirewallMap;

$stored = Config::getInstance()->object()->OPNsense->FirewallMap->general ?? null;
if ($stored === null || isset($stored->blocklist_aliases)) {
    exit(0);
}
$model = new FirewallMap();
$general = $model->general;
$general->blocklist_aliases = (BlocklistAliases::anyExisting() || (string)($stored->abuseipdb_alias ?? '') === '1') ? '1' : '0';
[$aliases, $changed, $error] = BlocklistAliases::reconcile(
    (string)$general->blocklist_aliases === '1',
    (string)$general->threat_lists,
    (string)$general->abuseipdb_key !== ''
);
$model->serializeToConfig();
if ($changed && $error === null) {
    $aliases->serializeToConfig();
}
Config::getInstance()->save();
if ($changed && $error === null) {
    BlocklistAliases::apply();
}
echo json_encode(['blocklist_aliases' => (string)$general->blocklist_aliases, 'aliases_changed' => $changed,
    'error' => $error]) . PHP_EOL;
