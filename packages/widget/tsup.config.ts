import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs", "iife"],
    globalName: "TokenTrap",
    dts: true,
    sourcemap: true,
    clean: true,
    outExtension({ format }) {
      if (format === "iife") return { js: ".global.js" };
      if (format === "cjs") return { js: ".cjs" };
      return { js: ".js" };
    },
  },
  {
    entry: ["src/engine.ts"],
    format: ["esm", "cjs"],
    globalName: "TokenTrapEngine",
    dts: true,
    sourcemap: true,
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      return { js: ".js" };
    },
  },
  {
    // Flat <script>-tag surface: window.TokenTrap.init(...) etc.
    entry: ["src/cdn.ts"],
    format: ["iife"],
    globalName: "TokenTrap",
    dts: false,
    sourcemap: true,
    clean: false,
    outExtension() {
      return { js: ".global.js" };
    },
  },
]);
