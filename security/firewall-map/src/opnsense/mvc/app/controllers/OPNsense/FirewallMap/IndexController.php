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

/**
 * Full-size Firewall Map+ view, opened from the dashboard widget's link button.
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /** A script's modification time as its cache-busting version, 0 when it is not installed. */
    private function version($script)
    {
        $file = '/usr/local/opnsense/www/js/' . $script;
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

    public function indexAction()
    {
        $this->view->title = gettext('Firewall Map');
        /* cache_safe() keys on the firmware version; the plugin's renderer changes independently */
        $this->view->rendererVersion = $this->version('firewall-map-renderer.js');
        $this->view->pageVersion = $this->version('firewall-map-page.js');
        /* the ?debug=1 panel: installed by development packages only */
        $this->view->diagnosticsVersion = $this->version('firewall-map-diagnostics.js');
        $this->view->sharedText = $this->sharedText();
        $this->view->pick('OPNsense/FirewallMap/index');
    }
}
