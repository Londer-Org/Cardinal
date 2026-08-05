import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // Emitted straight into the directory that //go:embed picks up, so a
    // `make ui && go build` sequence produces one self-contained binary.
    outDir: 'dist',
    emptyOutDir: true,
    // No inlining: the CSP forbids inline script and style, so anything Vite
    // decided to inline would be blocked at runtime rather than at build time.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
})
