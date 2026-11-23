import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
import fs from 'node:fs';

const backendTarget = process.env.BACKEND_URL || 'https://logmorph.onrender.com';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: 'copy-200-html',
      closeBundle() {
        const distIndex = path.resolve(__dirname, './dist/index.html');
        const dist200 = path.resolve(__dirname, './dist/200.html');
        if (fs.existsSync(distIndex)) {
          fs.copyFileSync(distIndex, dist200);
        }
      },
    },
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    host: true, // Listen on all network interfaces so user can test on localhost
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/auth': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/health': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router'],
          icons: ['lucide-react'],
        },
      },
    },
  },
});
