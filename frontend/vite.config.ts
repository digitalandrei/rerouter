import path from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Production: `vite build` emits static assets to dist/, served by Nginx.
// The controller API is never exposed directly; in production Nginx proxies
// /api/ -> http://127.0.0.1:9277 (loopback-bind invariant, docs/deployment.md).
// In development the Vite dev server mirrors that proxy so the SPA can use
// same-origin credentialed fetch exactly as it does behind Nginx.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      // Matches the "@/*" path in tsconfig (shadcn convention).
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:9277',
        changeOrigin: false,
      },
    },
  },
})
