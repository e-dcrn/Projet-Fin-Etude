import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Configuration Vite : serveur de dev sur http://localhost:5173
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    open: true,
  },
});
