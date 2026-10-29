import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The public indexer sends a duplicated Access-Control-Allow-Origin header,
// which browsers reject. Proxy it through our own origin instead.
const INDEXER_TARGET = 'https://explorer.stellereum.org';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api/v2': { target: INDEXER_TARGET, changeOrigin: true, secure: true }
    }
  },
  preview: {
    port: 5173,
    proxy: {
      '/api/v2': { target: INDEXER_TARGET, changeOrigin: true, secure: true }
    }
  },
  build: {
    outDir: '../dist-explorer',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2020',
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom']
        }
      }
    }
  }
});
