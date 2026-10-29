import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser-tests",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  use: { channel: process.env.TR_BROWSER_CHANNEL || undefined, headless: true, serviceWorkers: "block" },
});
