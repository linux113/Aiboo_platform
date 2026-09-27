import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: { "@": path.resolve(__dirname, "src") },
    },
    server: {
      port: parseInt(env.VITE_DEV_PORT || "3000"),
      proxy: {
        "/api": {
          target: env.VITE_API_PROXY || "http://localhost:4000",
          changeOrigin: true,
        },
        "/socket.io": {
          target: env.VITE_SOCKET_PROXY || "http://localhost:4000",
          ws: true,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: "dist",
      sourcemap: mode !== "production",
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ["react", "react-dom"],
            utils: ["axios", "socket.io-client"],
          },
        },
      },
    },
  };
});
