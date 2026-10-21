import type { Page } from "@playwright/test"

import { expect, test } from "./fixtures"

const message =
  'KeyMint transport failed: load KeymasterUtils: dlopen failed: dlopen failed: library "/vendor/lib64/libkeymasterdeviceutils.so" needed or dlopened by "/data/adb/modules/duck-toolbox/bin/duckd" is not accessible for the namespace "(default)"'
const longMessage = `${message}\n${"/vendor/lib64/" + "dependency".repeat(100)}\n`.repeat(12)
const failure = {
  code: "ta_transport_error",
  message,
  details: { library: "/vendor/lib64/" + "a".repeat(600) },
}

async function failCommand(page: Page, operation: "status" | "provision", error = failure) {
  await page.evaluate(
    ({ operation, error }) => {
      const scope = window as unknown as Record<string, unknown>
      const host = scope.ksu as {
        exec: (shell: string, options: string, callback: string) => void
      }
      const original = host.exec
      host.exec = (shell, options, callback) => {
        if (!shell.includes(`'rkp-device' '${operation}'`))
          return original(shell, options, callback)
        const respond = scope[callback] as (code: number, stdout: string, stderr: string) => void
        respond(
          1,
          JSON.stringify({
            ok: false,
            api: 1,
            command: `rkp-device.${operation}`,
            data: null,
            error,
          }),
          "",
        )
      }
    },
    { operation, error },
  )
}

async function expectPageFits(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      ),
    )
    .toBe(true)
}

for (const variant of [
  { name: "narrow", viewport: { width: 320, height: 568 }, locale: "en", theme: "light", message },
  {
    name: "landscape",
    viewport: { width: 568, height: 320 },
    locale: "en",
    theme: "dark",
    message: longMessage,
  },
  {
    name: "rtl",
    viewport: { width: 360, height: 640 },
    locale: "ar",
    theme: "light",
    message: longMessage,
  },
] as const) {
  test(`long errors fit the viewport and remain complete in ${variant.name}`, async ({
    page,
    open,
  }, testInfo) => {
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"])
    await page.addInitScript(() =>
      sessionStorage.setItem("duck-toolbox/acknowledged", JSON.stringify(["rkp-device"])),
    )
    await page.setViewportSize({ width: 360, height: 640 })
    await open("/rkp-device", { locale: variant.locale, theme: variant.theme })
    await expect(page.locator("[data-slot=badge]").first()).toBeVisible()
    const error = { ...failure, message: variant.message }
    await failCommand(page, "provision", error)
    await page
      .getByRole("main")
      .getByRole("button")
      .filter({ has: page.locator("svg.lucide-cpu") })
      .click()
    await page.getByRole("alertdialog").getByRole("button").last().click()
    const toast = page.locator("[data-sonner-toast][data-type=error]")
    await expect(toast).toBeVisible()
    await page.setViewportSize(variant.viewport)
    await expectPageFits(page)
    await expect
      .poll(async () => {
        const bounds = await toast.boundingBox()
        return (
          bounds !== null && bounds.y >= 0 && bounds.y + bounds.height <= variant.viewport.height
        )
      })
      .toBe(true)
    await page.screenshot({
      path: testInfo.outputPath(`${variant.name}-toast.png`),
      animations: "disabled",
    })
    await toast.locator("[data-action]").click()
    const dialog = page.getByRole("dialog")
    await expect(dialog).toBeVisible()
    await expectPageFits(page)
    await expect
      .poll(async () => {
        const bounds = await dialog.boundingBox()
        return (
          bounds !== null &&
          bounds.x >= 0 &&
          bounds.y >= 0 &&
          bounds.x + bounds.width <= variant.viewport.width &&
          bounds.y + bounds.height <= variant.viewport.height
        )
      })
      .toBe(true)
    const report = `rkp-device.provision: ${error.code}\n${error.message}\n\n${JSON.stringify(error.details, null, 2)}`
    await expect(dialog.locator("pre")).toHaveText(report)
    await expect
      .poll(() =>
        dialog.locator("pre").evaluate((element) => element.scrollWidth <= element.clientWidth),
      )
      .toBe(true)
    const footer = dialog.locator("[data-slot=dialog-footer]")
    await expect(footer).toBeInViewport()
    await expect(toast).toBeHidden()
    await page.screenshot({
      path: testInfo.outputPath(`${variant.name}-error.png`),
      animations: "disabled",
    })
    await dialog.locator("pre").scrollIntoViewIfNeeded()
    await expect(dialog.locator("pre")).toBeInViewport()
    await expect(footer).toBeInViewport()
    await footer.getByRole("button").first().click()
    // Windows clipboard text uses CRLF line endings.
    await expect
      .poll(async () =>
        (await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n"),
      )
      .toBe(report)
    await footer.getByRole("button").last().click()
    await expect(dialog).toBeHidden()
  })
}

test("inline query errors wrap long paths on narrow screens", async ({ page, open }) => {
  await page.setViewportSize({ width: 320, height: 568 })
  await page.addInitScript(() =>
    sessionStorage.setItem("duck-toolbox/acknowledged", JSON.stringify(["rkp-device"])),
  )
  await open("/")
  await expect(page.getByRole("heading").first()).toBeVisible()
  await failCommand(page, "status", { ...failure, message: longMessage })
  await page.getByRole("button", { name: /Device RKP Issuer/ }).click()
  const empty = page.locator("[data-slot=empty]")
  await expect(empty).toBeVisible()
  await expect(empty.locator("[data-slot=empty-description]")).toContainText(message)
  await expectPageFits(page)
  await empty.getByRole("button", { name: "Details" }).click()
  await expect(page.getByRole("dialog")).toBeVisible()
  await expectPageFits(page)
})
