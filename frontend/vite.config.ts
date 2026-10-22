import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// Build config for the gateway SPA.
//
// base: '/' is mandatory — the app is mounted under /admin/... and /user/... and
// every emitted asset URL must be absolute (/assets/<name>-<hash>.js) so deep
// links served by the shell resolve regardless of the current path depth.
export default defineConfig({
  base: '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      '@audit': fileURLToPath(new URL('./scripts/audit-dist.mjs', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Vite's default inlines a modulepreload polyfill as an inline <script> in
    // index.html. That collides with both the CSP (script-src 'self') and the
    // build audit (which forbids inline script bodies). Disable it so every
    // script is src-referenced.
    modulePreload: { polyfill: false },
    // No external references, no sourcemap that could inline sources.
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.spec.ts'],
    globals: true,
  },
})
