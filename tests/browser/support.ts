import { expect, type Page } from "@playwright/test";
import { fileURLToPath } from "node:url";

export const adminLogin = "owner";
export const adminPassphrase = ["browser", "fixture", "phrase"].join(" ");
export const imageDirectory = fileURLToPath(
  new URL("../../docs/images/", import.meta.url)
);

export async function resetFixture(page: Page): Promise<void> {
  const response = await page.request.post("/__fixture__/reset");
  expect(response.status()).toBe(204);
}

export async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Логин").fill(adminLogin);
  await page.getByLabel("Пароль").fill(adminPassphrase);
  await page.getByRole("button", { name: "Открыть панель" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(
    page.getByRole("heading", { name: "Подключения" })
  ).toBeVisible();
}

export async function createProfile(page: Page, name = "Телефон"): Promise<void> {
  await page.getByLabel("Название устройства").fill(name);
  await page.getByRole("button", { name: "Создать профиль" }).click();
  await expect(page).toHaveURL(/\/profiles\/[0-9a-f-]+$/);
  await expect(page.getByRole("heading", { name })).toBeVisible();
}
