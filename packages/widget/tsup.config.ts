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
  {
    entry: { php2shell: "src/php2shell/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: false,
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      return { js: ".js" };
    },
  },
  {
    entry: { "php2shell-node": "src/php2shell/node.ts" },
    format: ["esm", "cjs"],
    platform: "node",
    dts: true,
    sourcemap: true,
    clean: false,
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      return { js: ".js" };
    },
  },
  {
    entry: { "php2shell-cli": "src/php2shell/cli.ts" },
    format: ["esm"],
    platform: "node",
    dts: false,
    sourcemap: true,
    clean: false,
    outExtension() {
      return { js: ".js" };
    },
  },
]);
