import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'path';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  base: '/m/',
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag) => tag.startsWith('sl-'),
        },
      },
    }),
    VitePWA({
      strategies: 'generateSW',
      registerType: 'autoUpdate',
      injectRegister: false,
      manifest: false,
      includeAssets: [
        'favicon.svg',
        'brand-mark.svg',
        'manifest.webmanifest',
        'pwa/*.png',
      ],
      workbox: {
        cleanupOutdatedCaches: true,
        maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        navigateFallback: 'index.html',
        navigateFallbackDenylist: [/^\/api\//, /^\/m\/api\//],
        globPatterns: ['**/*.{js,css,html,svg,png,ico,webmanifest}'],
        runtimeCaching: [
          {
            urlPattern: /\/api\//,
            handler: 'NetworkOnly',
          },
        ],
      },
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../webapp/src'),
      '@mobile': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 8087,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8089',
    },
    fs: {
      allow: ['..'],
    },
  },
  css: {
    preprocessorOptions: {
      scss: {
        api: 'modern',
      },
    },
  },
  build: {
    emptyOutDir: true,
    sourcemap: false,
  },
});
