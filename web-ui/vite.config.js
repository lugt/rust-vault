import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// The WASM pkg/ lives in ../web/pkg and is copied into public/ at build time.
// Vite serves public/ at the root, so import "./pkg/vault_wasm.js" resolves.
export default defineConfig({
  plugins: [vue()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    fs: { allow: [".."] },
  },
});
