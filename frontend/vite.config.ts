import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false, ws: true } },
  },
  // 폰트 등 자산을 data: URI 로 끼워 넣지 않는다(CSP 가 data: 를 허용하지 않음)
  build: { sourcemap: false, assetsInlineLimit: 0 },
});
