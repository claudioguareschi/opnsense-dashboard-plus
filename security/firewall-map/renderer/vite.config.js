import {defineConfig} from 'vite';

export default defineConfig({
  define: {
    process: '{env:{NODE_ENV:"production"}}',
  },
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
        banner: 'var process = globalThis.process || {env:{NODE_ENV:"production"}};',
      },
    },
  },
});
