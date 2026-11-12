import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    chunkSizeWarningLimit: 1550,
    rollupOptions: {
      output: {
        manualChunks(id) {
          const norm = id.replace(/\\/g, '/');
          if (!norm.includes('/node_modules/')) {
            return undefined;
          }
          if (norm.includes('/node_modules/elkjs/')) {
            return 'elk-vendor';
          }
          if (norm.includes('/node_modules/@xyflow/')) {
            return 'flow-vendor';
          }
          if (
            norm.includes('/node_modules/react/') ||
            norm.includes('/node_modules/react-dom/') ||
            norm.includes('/node_modules/scheduler/') ||
            norm.includes('/node_modules/zustand/') ||
            norm.includes('/node_modules/use-sync-external-store/')
          ) {
            return 'react-vendor';
          }
          return undefined;
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5179,
    strictPort: true,
  },
});
