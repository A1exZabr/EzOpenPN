import { expect, test } from "@playwright/test";
import path from "node:path";

import {
  adminLogin,
  adminPassphrase,
  createProfile,
  imageDirectory,
  login,
  resetFixture
} from "./support";

test.beforeEach(async ({ page }) => {
  await resetFixture(page);
});

test("login page records safe deterministic evidence", async ({ page }) => {
  await page.goto("/login");
  await expect(
    page.getByText("sudo ezopenpn admin reset-password").last()
  ).toBeVisible();
  await page.screenshot({
    path: path.join(imageDirectory, "panel-login.png"),
    fullPage: true,
    animations: "disabled",
    mask: [page.getByLabel("Пароль")]
  });
});

test("invalid administrator credentials are rejected", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Логин").fill(adminLogin);
  await page.getByLabel("Пароль").fill("not the fixture phrase");
  await page.getByRole("button", { name: "Открыть панель" }).click();
  await expect(page.getByRole("alert")).toHaveText("Логин или пароль не подошли.");
  await expect(page).toHaveURL(/\/login$/);
});

test("administrator completes the profile lifecycle", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await login(page);
  await createProfile(page);

  await expect(page.getByText("Активен", { exact: true })).toBeVisible();
  await expect(page.locator(".qr-code svg")).toHaveCount(3);
  await expect(page.locator(".guide li")).toHaveCount(4);
  await expect(
    page.getByText("sudo ezopenpn admin reset-password").last()
  ).toBeVisible();

  await page.getByRole("button", { name: "Скопировать" }).first().click();
  await expect(page.getByRole("button", { name: "Скопировано" })).toBeVisible();
  const copied = await page.evaluate(async () => navigator.clipboard.readText());
  expect(copied.length > 20).toBe(true);

  await page.screenshot({
    path: path.join(imageDirectory, "profile-card.png"),
    fullPage: true,
    animations: "disabled",
    mask: [page.locator("code"), page.locator(".qr-code")]
  });

  await page.getByRole("button", { name: "Отключить профиль" }).click();
  await expect(page.getByText("Отключён", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Включить профиль" }).click();
  await expect(page.getByText("Активен", { exact: true })).toBeVisible();

  await page
    .getByLabel("Я понимаю, что прежняя ссылка перестанет работать.")
    .check();
  await page.getByRole("button", { name: "Удалить профиль" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Добавьте первое устройство" })).toBeVisible();
});

test("authenticated forms reject requests without CSRF proof", async ({ page }) => {
  await login(page);
  const response = await page.request.post("/profiles", {
    form: { name: "Планшет" },
    maxRedirects: 0
  });
  expect(response.status()).toBe(403);
  expect(await response.text()).toBe("Действие отклонено.");
});

test("expired administrator session returns to login", async ({ page }) => {
  await login(page);
  const response = await page.request.post("/__fixture__/expire-session");
  expect(response.status()).toBe(204);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Войти на сервер" })).toBeVisible();
});

test("copy control uses the safe fallback without Clipboard API", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "clipboard", {
      configurable: true,
      get: () => undefined
    });
    Document.prototype.execCommand = function (command: string): boolean {
      const active = document.activeElement;
      const captured = active instanceof HTMLTextAreaElement ? active.value : "";
      (window as Window & { fixtureCopied?: string }).fixtureCopied = captured;
      return command === "copy";
    };
  });
  await login(page);
  await createProfile(page, "Ноутбук");
  await page.getByRole("button", { name: "Скопировать" }).first().click();
  await expect(page.getByRole("button", { name: "Скопировано" })).toBeVisible();
  const copied = await page.evaluate(
    () => (window as Window & { fixtureCopied?: string }).fixtureCopied ?? ""
  );
  expect(copied.length > 20).toBe(true);
});
