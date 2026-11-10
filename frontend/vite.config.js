import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// /api 요청은 Spring Boot(8080)로 전달 → CORS 설정 불필요
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
});
