import {defineConfig} from 'vite';

// The map page (page/main.js and its modules) as one classic script, next to the renderer.
export default defineConfig({
  build: {
    lib: {
      entry: 'page/main.js',
      formats: ['iife'],
      name: 'FirewallMapPage',
      fileName: () => 'firewall-map-page.js',
    },
    outDir: 'dist-firewall-map-page',
    emptyOutDir: true,
    // readable in the browser's debugger: the page is small, the renderer is the big bundle
    minify: false,
  },
});
