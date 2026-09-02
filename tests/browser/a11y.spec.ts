import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import {
  adminLogin,
  adminPassphrase,
  createProfile,
  login,
  resetFixture
} from "./support";

async function expectNoSeriousAccessibilityFindings(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const findings = results.violations
    .filter((violation) =>
      violation.impact === "serious" || violation.impact === "critical"
    )
    .map((violation) => ({
      id: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.length,
      targets: violation.nodes.map((node) => node.target)
    }));
  expect(findings).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await resetFixture(page);
});

test("login, dashboard and profile have no serious accessibility findings", async ({ page }) => {
  await page.goto("/login");
  await expectNoSeriousAccessibilityFindings(page);
  await login(page);
  await expectNoSeriousAccessibilityFindings(page);
  await createProfile(page);
  await expectNoSeriousAccessibilityFindings(page);
});

test("administrator can sign in using only the keyboard", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByLabel("Логин")).toBeFocused();
  await page.keyboard.type(adminLogin);
  await page.keyboard.press("Tab");
  await page.keyboard.type(adminPassphrase);
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Подключения" })).toBeVisible();
});

test.describe("mobile viewport", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("panel remains usable without horizontal overflow", async ({ page }) => {
    await login(page);
    await createProfile(page);
    const hasHorizontalOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth
    );
    expect(hasHorizontalOverflow).toBe(false);
    await expect(page.getByRole("button", { name: "Отключить профиль" })).toBeVisible();
    await expectNoSeriousAccessibilityFindings(page);
  });
});
