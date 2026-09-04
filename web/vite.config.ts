// ABOUTME: Vite build and test config for the vmobs web interface.
// ABOUTME: The app is served under /ui/ by vmobsd, so base must match that mount.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` talks to a local vmobsd so the UI is developed against the
    // real API, never a fixture. SPEC §13: the UI holds no private data path.
    proxy: {
      '/api': 'http://127.0.0.1:8420',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'],
    globals: true,
  },
})
