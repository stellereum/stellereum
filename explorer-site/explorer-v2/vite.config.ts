import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The public indexer sends a duplicated Access-Control-Allow-Origin header,
// which browsers reject. Proxy it through our own origin instead.
const INDEXER_TARGET = 'https://explorer.stellereum.org';
const RPC_TARGET = 'https://rpc.stellereum.org';

const proxy = {
  '/api/v2': { target: INDEXER_TARGET, changeOrigin: true, secure: true },
  // The node's JSON-RPC lives at the root, not under /rpc: strip the prefix.
  '/rpc': {
    target: RPC_TARGET,
    changeOrigin: true,
    secure: true,
    rewrite: (path: string) => path.replace(/^\/rpc/, ''),
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy,
  },
  preview: {
    port: 5173,
    proxy,
  },
  build: {
    outDir: '../dist-explorer-v2',
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
