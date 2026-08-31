import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: "line",
  outputDir: `${repositoryRoot}/.cache/playwright-results`,
  use: {
    baseURL: "http://localhost:9444",
    locale: "ru-RU",
    timezoneId: "Asia/Omsk",
    colorScheme: "light",
    reducedMotion: "reduce",
    viewport: { width: 1280, height: 900 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "uv run python tests/browser/fixture_server.py --port 9444",
    cwd: repositoryRoot,
    url: "http://localhost:9444/health/live",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000
  }
});
