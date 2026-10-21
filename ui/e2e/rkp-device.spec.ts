import type { Page } from "@playwright/test"

import { expect, test } from "./fixtures"

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() =>
    localStorage.setItem("duck-toolbox/acknowledged", JSON.stringify(["rkp-device"])),
  )
})

async function recordProvisionCommands(page: Page) {
  await page.evaluate(() => {
    const scope = window as unknown as Record<string, unknown>
    const host = scope.ksu as { exec: (shell: string, options: string, callback: string) => void }
    const original = host.exec
    scope.provisionCommands = []
    host.exec = (shell, options, callback) => {
      if (shell.includes("'rkp-device' 'provision'"))
        (scope.provisionCommands as string[]).push(shell)
      original(shell, options, callback)
    }
  })
}

async function issue(page: Page) {
  await page.getByRole("button", { name: "签发 RKP keybox", exact: true }).click()
  await expect(page.locator("#rkp-manufacturer-mode")).toBeDisabled()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "签发 RKP keybox", exact: true })
    .click()
  await expect(page.getByRole("heading", { name: "结果", exact: true })).toBeVisible()
  await expect(page.locator("#rkp-manufacturer-mode")).toBeEnabled()
}

test("sends the optional manufacturer and omits it after clearing", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN" })
  await recordProvisionCommands(page)
  await page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" }).click()
  await page.getByRole("option", { name: "自定义", exact: true }).click()
  const manufacturer = page.getByRole("textbox", {
    name: "自定义",
    exact: true,
  })
  await expect(manufacturer).toHaveValue("")
  for (const value of ["  Google  ", ""]) {
    await manufacturer.fill(value)
    await page.getByRole("button", { name: "签发 RKP keybox", exact: true }).click()
    await expect(page.locator("#rkp-manufacturer")).toBeDisabled()
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "签发 RKP keybox", exact: true })
      .click()
    await expect(page.getByRole("heading", { name: "结果", exact: true })).toBeVisible()
    await expect(manufacturer).toBeEnabled()
  }
  const commands = await page.evaluate(
    () => (window as unknown as { provisionCommands: string[] }).provisionCommands,
  )
  expect(commands).toHaveLength(2)
  expect(commands[0]).toContain("'--manufacturer' 'Google'")
  expect(commands[1]).not.toContain("--manufacturer")
  await page.screenshot({ path: "test-results/rkp-device-manufacturer-zh.png", fullPage: true })
})

test("renders the actual product manufacturer and can be switched off", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN", query: { manufacturer: " Xiaomi " } })
  await recordProvisionCommands(page)
  const manufacturer = page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" })
  await expect(manufacturer).toHaveText("不发送")
  await manufacturer.click()
  await page.getByRole("option", { name: "Xiaomi（当前设备）", exact: true }).click()
  await expect(manufacturer).toHaveText("Xiaomi（当前设备）")
  await expect(page.getByRole("textbox", { name: "自定义", exact: true })).toHaveCount(0)
  await issue(page)
  await page.screenshot({
    path: "test-results/rkp-device-manufacturer-device-zh.png",
    fullPage: true,
  })
  await manufacturer.click()
  await page.getByRole("option", { name: "不发送", exact: true }).click()
  await issue(page)
  const commands = await page.evaluate(
    () => (window as unknown as { provisionCommands: string[] }).provisionCommands,
  )
  expect(commands).toHaveLength(2)
  expect(commands[0]).toContain("'--manufacturer' 'Xiaomi'")
  expect(commands[0]).not.toContain("'QTI'")
  expect(commands[1]).not.toContain("--manufacturer")
})

test("hides the current-device option when the manufacturer is missing", async ({ page, open }) => {
  for (const value of ["", "  "]) {
    await open("/rkp-device", { locale: "zh-CN", query: { manufacturer: value } })
    await page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" }).click()
    await expect(page.getByRole("option")).toHaveText(["不发送", "自定义"])
    await page.getByRole("option", { name: "自定义", exact: true }).click()
    await expect(page.getByRole("textbox", { name: "自定义", exact: true })).toBeEnabled()
    await expect(page.getByRole("button", { name: "签发 RKP keybox", exact: true })).toBeEnabled()
  }
})

test("clears a selected device option if refresh loses the manufacturer", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { locale: "zh-CN" })
  const manufacturer = page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" })
  await manufacturer.click()
  await page.getByRole("option", { name: "Google（当前设备）", exact: true }).click()
  await page.evaluate(() => history.replaceState(null, "", "?manufacturer=#/rkp-device"))
  await page.getByRole("button", { name: "重新检查", exact: true }).click()
  await expect(manufacturer).toHaveText("不发送")
  await manufacturer.click()
  await expect(page.getByRole("option")).toHaveText(["不发送", "自定义"])
})

test("exports and reports when the server omits certificate manufacturer", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { locale: "zh-CN", query: { rkp_manufacturer: "missing" } })
  await page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" }).click()
  await page.getByRole("option", { name: "Google（当前设备）", exact: true }).click()
  await issue(page)
  await expect(page.getByText("服务器未返回 manufacturer", { exact: true }).first()).toBeVisible()
  await expect(page.getByText("请求的 manufacturer", { exact: true })).toBeVisible()
  await expect(page.getByText("证书中的 manufacturer", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: /安装到/ }).first()).toBeEnabled()
  await page.screenshot({
    path: "test-results/rkp-manufacturer-not-returned-zh.png",
    fullPage: true,
  })
})

for (const [failure, message] of [
  ["mismatch", "签发证书中的 manufacturer 与请求值不匹配，未导出 keybox。"],
]) {
  test(`rejects ${failure} manufacturer in the issued certificate`, async ({ page, open }) => {
    await open("/rkp-device", { locale: "zh-CN", query: { rkp_manufacturer: failure! } })
    await page.getByRole("combobox", { name: "协议", exact: true }).click()
    await page.getByRole("option", { name: "CSR_V2", exact: true }).click()
    await page.getByRole("combobox", { name: "RKP Provisioning manufacturer（可选）" }).click()
    await page.getByRole("option", { name: "Google（当前设备）", exact: true }).click()
    await page.getByRole("button", { name: "签发 RKP keybox", exact: true }).click()
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "签发 RKP keybox", exact: true })
      .click()
    await expect(page.getByText(message!, { exact: true })).toBeVisible()
    await expect(page.getByRole("heading", { name: "结果", exact: true })).toHaveCount(0)
  })
}

test("explicit V1 issuance reports structural verification", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN" })
  await page.getByRole("combobox", { name: "协议" }).click()
  await page.getByRole("option", { name: "V1 AIDL", exact: true }).click()
  await page.getByRole("button", { name: "签发 RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "签发 RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("仅结构校验；加密签名材料由服务器验证", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("V1", { exact: true })).toBeVisible()
  await page.screenshot({ path: "test-results/rkp-device-v1-zh.png", fullPage: true })
})

test("automatic mode can issue on a V1-only device without V2 resources", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { rkp: "v1-only" } })
  await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeEnabled()
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("Structure checked; encrypted evidence is verified by the server", {
      exact: true,
    }),
  ).toBeVisible()
})

test("warns before installing an issued RKP keybox into OMK", async ({ page, open }) => {
  await open("/rkp-device", { query: { backend: "oh-my-keymint" } })
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await page.getByRole("button", { name: "Install to Tricky Store", exact: true }).click()
  const dialog = page.getByRole("alertdialog")
  await expect(dialog.getByText("OMK keybox compatibility", { exact: true })).toBeVisible()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(page.getByText(/Keybox installed to/)).toBeHidden()
  await page.getByRole("button", { name: "Install to Tricky Store", exact: true }).click()
  await dialog.getByRole("button", { name: "Continue installation", exact: true }).click()
  await expect(page.getByText(/Keybox installed to/)).toBeVisible()
})

test("native V1 backup can be selected without an AIDL APK", async ({ page, open }) => {
  await open("/rkp-device", { query: { rkp: "v2-only" } })
  await page.getByRole("combobox", { name: "Protocol" }).click()
  await expect(page.getByRole("option", { name: "V1 AIDL", exact: true })).toBeDisabled()
  await page.getByRole("option", { name: "V1 Native (0x311e)", exact: true }).click()
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByText("V1", { exact: true })).toBeVisible()
  await expect(page.getByText("Native", { exact: true })).toBeVisible()
  await expect(
    page.getByText("Structure checked; encrypted evidence is verified by the server", {
      exact: true,
    }),
  ).toBeVisible()
})

test("native V1 is disabled when the vendor resources are missing", async ({ page, open }) => {
  await open("/rkp-device", { query: { rkp: "v1-only" } })
  await page.getByRole("combobox", { name: "Protocol" }).click()
  await expect(page.getByRole("option", { name: "V1 Native (0x311e)", exact: true })).toBeDisabled()
})

test("automatic mode shows the failed attempts before native V1 success", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { rkp_fail: "v2,v1" } })
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByRole("heading", { name: "Attempts", exact: true })).toBeVisible()
  await expect(
    page.getByText("[ta_rejected] v2 rejected the request", { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText("[ta_rejected] v1 rejected the request", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("Native", { exact: true })).toBeVisible()
})

test("automatic mode reports failure only after every method fails", async ({ page, open }) => {
  await open("/rkp-device")
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByRole("heading", { name: "Result", exact: true })).toBeVisible()
  await page.evaluate(() => history.replaceState(null, "", "?rkp_fail=v2,v1,v1-native"))
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("All available issuance methods failed. Review the errors for each attempt.", {
      exact: true,
    }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: "Result", exact: true })).toHaveCount(0)
})

test("identifies QTI and keeps firmware compatibility unverified", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN" })
  await expect(page.getByText("QTI", { exact: true }).first()).toBeVisible()
  await expect(page.getByText("已识别", { exact: true })).toBeVisible()
  await expect(page.getByText("尚未验证", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "签发 RKP keybox", exact: true })).toBeEnabled()
  await expect(
    page.getByText("识别到了非高通 SoC 厂商；该操作需要高通 KeyMint。", { exact: true }),
  ).toHaveCount(0)
  await page.getByText("识别依据", { exact: true }).click()
  await expect(page.getByText("ro.soc.manufacturer", { exact: true })).toBeVisible()
  await page.screenshot({ path: "test-results/rkp-device-qti-zh.png", fullPage: true })
})

test("shows kernel fallback evidence when the vendor property is absent", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { soc: "fallback" } })
  await expect(page.getByText("Detected", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeEnabled()
  await page.getByText("Detection evidence", { exact: true }).click()
  await expect(page.getByText("/sys/devices/soc0/family", { exact: true })).toBeVisible()
  await expect(page.getByText("Snapdragon", { exact: true })).toBeVisible()
})

for (const [soc, message] of [
  [
    "unknown",
    "The SoC vendor could not be identified from local properties or kernel information.",
  ],
  ["conflict", "Local SoC information conflicts. Review the detection evidence before continuing."],
  ["other", "A non-Qualcomm SoC vendor was identified; this operation requires Qualcomm KeyMint."],
]) {
  test(`distinguishes ${soc} hardware and blocks issuance`, async ({ page, open }) => {
    await open("/rkp-device", { query: { soc: soc! } })
    await expect(page.getByText(message!, { exact: true })).toBeVisible()
    await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeDisabled()
    if (soc !== "other")
      await expect(
        page.getByText(
          "A non-Qualcomm SoC vendor was identified; this operation requires Qualcomm KeyMint.",
          { exact: true },
        ),
      ).toHaveCount(0)
  })
}
