import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    // testing-library only registers its DOM cleanup between tests when it
    // can see a global afterEach
    globals: true,
  },
});
