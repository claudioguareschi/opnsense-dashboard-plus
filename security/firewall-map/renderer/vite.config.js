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

import fs from 'node:fs';
import path from 'node:path';
import {defineConfig} from 'vite';
import {BANNER} from './banner.js';

/*
 * The renderer bundles deck.gl, luma.gl, loaders.gl, math.gl and mjolnir.js (MIT). Their licenses
 * must travel with every copy: this collects the license text of each package that ends up in
 * the bundle into firewall-map-renderer.LICENSE, installed next to the bundle.
 */
function thirdPartyLicenses(fileName) {
  return {
    name: 'third-party-licenses',
    generateBundle(_, bundle) {
      const packages = new Map();
      for (const chunk of Object.values(bundle)) {
        for (const id of Object.keys(chunk.modules || {})) {
          const match = id.replace(/\\/g, '/').match(/^(.*\/node_modules\/(?:@[^/]+\/)?[^/]+)\//);
          if (match && !packages.has(match[1])) {
            packages.set(match[1], JSON.parse(fs.readFileSync(path.join(match[1], 'package.json'), 'utf8')));
          }
        }
      }
      const sections = [...packages].sort(([, a], [, b]) => a.name.localeCompare(b.name)).map(([root, pkg]) => {
        const file = fs.readdirSync(root).find((name) => /^(license|licence|copying)(\.|$)/i.test(name));
        const text = file ? fs.readFileSync(path.join(root, file), 'utf8').trim() : `License: ${pkg.license}`;
        return `${pkg.name} ${pkg.version} (${pkg.license})\n${'-'.repeat(72)}\n${text}\n`;
      });
      this.emitFile({type: 'asset', fileName, source: `Third-party software in firewall-map-renderer.js\n\n${sections.join('\n')}`});
    },
  };
}

export default defineConfig({
  // libraries test process.env.NODE_ENV; nothing else of Node's `process` is defined (no global)
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  plugins: [thirdPartyLicenses('firewall-map-renderer.LICENSE')],
  build: {
    lib: {
      entry: 'src/app.js',
      formats: ['iife'],
      name: 'FirewallMapRenderer',
      fileName: () => 'firewall-map-renderer.js',
    },
    outDir: 'dist-firewall-map',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // after minification, which would strip it
        postBanner: `${BANNER}\n/* Includes deck.gl, luma.gl, loaders.gl, math.gl and mjolnir.js (MIT License): see firewall-map-renderer.LICENSE. */`,
      },
    },
  },
});
