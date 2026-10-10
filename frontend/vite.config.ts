import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://localhost:3000', '/proxy': 'http://localhost:3000' } },
  preview: { port: 4173, proxy: { '/api': process.env.API_URL ?? 'http://localhost:3000' } },
});
