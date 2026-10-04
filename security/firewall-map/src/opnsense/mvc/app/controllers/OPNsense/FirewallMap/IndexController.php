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
namespace OPNsense\FirewallMap;

use OPNsense\Core\ACL;

/**
 * Full-size Firewall Map+ view, opened from the dashboard widget's link button.
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /** A file's modification time as its cache-busting version, 0 when it is not installed. */
    private function version($path)
    {
        $file = '/usr/local/opnsense/www/' . $path;
        return is_file($file) ? filemtime($file) : 0;
    }

    /**
     * The strings the page shares with the dashboard widget and the renderer, from the widget's
     * metadata and translated the way the dashboard translates them: one source for both.
     */
    private function sharedText()
    {
        $texts = [];
        $metadata = '/usr/local/opnsense/www/js/widgets/Metadata/FirewallMap.xml';
        $xml = is_file($metadata) ? simplexml_load_file($metadata) : false;
        if ($xml !== false && isset($xml->firewallmap->translations)) {
            foreach ($xml->firewallmap->translations->children() as $key => $value) {
                $texts[$key] = gettext((string)$value);
            }
        }
        /* safe inside the page's <script>: no tag, quote or ampersand survives unescaped */
        return json_encode((object)$texts, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }

    /**
     * What this user may do on the page, from the privileges of the endpoints each action calls,
     * so the page offers only actions that work (and never probes an endpoint it may not use).
     */
    private function permissions()
    {
        $acl = new ACL();
        $user = $this->getUserName();
        $may = function (array $urls) use ($acl, $user) {
            foreach ($urls as $url) {
                if (!$acl->isPageAccessible($user, $url)) {
                    return false;
                }
            }
            return true;
        };
        return json_encode([
            /* the plugin's settings privilege: investigations, Threats, snapshot deletion, Retry now */
            'manage' => $may(['/api/firewallmap/settings/status']),
            'aliases' => $may([
                '/api/firewall/alias/search_item', '/api/firewall/alias/get_item', '/api/firewall/alias/set_item',
                '/api/firewall/alias/add_item', '/api/firewall/alias/reconfigure', '/api/firewall/alias_util/add',
            ]),
            'states' => $may(['/api/diagnostics/firewall/query_states']),
            'kill' => $may(['/api/diagnostics/firewall/kill_states']),
        ]);
    }

    public function indexAction()
    {
        $this->view->title = gettext('Firewall Map');
        /* cache_safe() keys on the firmware version; the plugin's files change independently */
        $this->view->rendererVersion = $this->version('js/firewall-map-renderer.js');
        $this->view->pageVersion = $this->version('js/firewall-map-page.js');
        $this->view->styleVersion = $this->version('css/firewall-map.css');
        /* the ?debug=1 panel: only development packages install it, and only ?debug=1 loads it */
        $this->view->diagnosticsVersion = $this->request->get('debug') === '1'
            ? $this->version('js/firewall-map-diagnostics.js') : 0;
        $this->view->sharedText = $this->sharedText();
        $this->view->permissions = $this->permissions();
        $this->view->pick('OPNsense/FirewallMap/index');
    }
}
