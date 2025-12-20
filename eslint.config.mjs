import js from "@eslint/js";
import globals from "globals";
import nextPlugin from "@next/eslint-plugin-next";
import tseslint from "typescript-eslint";

/**
 * ESLint v9+ flat config.
 *
 * Goals:
 * - Lint JS/TS/TSX in a Next.js App Router repo
 * - Apply Next "core-web-vitals" rules
 */
const allSourceFiles = ["**/*.{js,mjs,cjs,ts,tsx}"];

export default [
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "dist/**",
      "out/**",
      "coverage/**",
    ],
  },
  // Base language options (globals, module syntax)
  {
    files: allSourceFiles,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  // JS recommended rules
  js.configs.recommended,
  // TS parsing + recommended TS rules
  ...tseslint.configs.recommended,
  // Keep this repo permissive/minimal: allow `any` for backend JSON blobs.
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  // Next.js rules (works for JS/TS)
  {
    files: allSourceFiles,
    plugins: {
      "@next/next": nextPlugin,
    },
    rules: {
      ...nextPlugin.configs["core-web-vitals"].rules,
    },
  },
];
