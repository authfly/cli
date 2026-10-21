import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The widgets come from authfly/authkit (.deps/authkit/packages/ui/react, pinned in deps.lock): dedupe resolves their imports here.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { dedupe: ["react", "react-dom", "clsx", "tailwind-merge"] },
  build: { outDir: "dist" },
});
