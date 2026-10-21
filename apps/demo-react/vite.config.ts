import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The widgets live in packages/ui/react (a plain local set, outside this app): dedupe resolves their imports here.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { dedupe: ["react", "react-dom", "clsx", "tailwind-merge"] },
  build: { outDir: "dist" },
});
