import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    sourcemap: false,
    rollupOptions: {
      input: {
        login: resolve(__dirname, 'index.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'login' || chunk.name === 'index'
            ? 'login-assets/[name]-[hash].js'
            : 'admin-assets/[name]-[hash].js',
        chunkFileNames: (chunk) =>
          chunk.name === 'login-webauthn' || chunk.name === 'modulepreload-polyfill'
            ? 'login-assets/[name]-[hash].js'
            : 'admin-assets/[name]-[hash].js',
        assetFileNames: (asset) =>
          asset.name?.includes('login') || asset.name?.includes('index')
            ? 'login-assets/[name]-[hash][extname]'
            : 'admin-assets/[name]-[hash][extname]',
        manualChunks(id) {
          if (id.includes('/node_modules/@simplewebauthn/browser/')) return 'login-webauthn';
          return undefined;
        },
      },
    },
  },
});
