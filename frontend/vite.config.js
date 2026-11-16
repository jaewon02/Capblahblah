import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 개발: /api 요청은 Flask(8080)로 전달 → CORS 설정 불필요. 배포: npm run build 결과를 Flask가 그대로 내보냄
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
});
