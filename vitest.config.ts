import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,

    include: ["src/**/*.spec.ts"],

    coverage: {
      enabled: true,
      all: true,
      reporter: ["json", "text", "html"],
      cleanOnRerun: true,
      reportsDirectory: "./coverage",

      include: ["src/**/!(*.spec).ts"],
    },
  },
});
