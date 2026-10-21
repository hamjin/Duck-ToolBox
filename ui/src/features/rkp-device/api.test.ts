import { afterEach, describe, expect, it, vi } from "vitest"

import { setBridge } from "@/core/bridge"

import type { Protocol, Provision } from "./api"
import { rkpDeviceApi } from "./api"
import mock from "./mock"

const originalUrl = location.href
afterEach(() => {
  setBridge(null)
  history.replaceState(null, "", originalUrl)
})

function result(protocol: Protocol = "auto"): Provision {
  return mock.handlers["rkp-device.provision"]!(
    [],
    { protocol, "acknowledge-limitations": true },
    undefined,
  ) as Provision
}

function respond(data: Provision) {
  const exec = vi.fn(async () => ({
    errno: 0,
    stdout: JSON.stringify({ ok: true, api: 1, command: "rkp-device.provision", data }),
    stderr: "",
  }))
  setBridge({
    available: true,
    exec,
    toast: () => undefined,
    hostModule: () => null,
    listPackages: async () => [],
    packagesInfo: async () => [],
    iconUrl: () => null,
    exit: () => undefined,
  })
  return exec
}

describe("device RKP manufacturer option", () => {
  it.each([undefined, "", " \t\n"])("omits an empty manufacturer %j", async (value) => {
    const exec = respond(result())
    await rkpDeviceApi.provision("auto", value)
    expect(exec).toHaveBeenCalledWith(
      "'/data/adb/modules/duck-toolbox/bin/duckctl.sh' 'rkp-device' 'provision' '--acknowledge-limitations' '--protocol' 'auto'",
    )
  })

  it.each(["auto", "v1", "v2", "v1-native"] as const)(
    "passes a trimmed manufacturer as one argument with %s",
    async (protocol) => {
      const exec = respond(result(protocol))
      await rkpDeviceApi.provision(protocol, "  A&B /+=?#厂商  ")
      expect(exec).toHaveBeenCalledWith(
        expect.stringContaining(`'--protocol' '${protocol}' '--manufacturer' 'A&B /+=?#厂商'`),
      )
    },
  )
})

describe("device RKP successful-response validation", () => {
  it("accepts MediaTek AIDL and rejects a claimed Qualcomm native capability", async () => {
    history.replaceState(null, "", "/?soc=mediatek")
    const data = result()
    respond(data)
    await expect(rkpDeviceApi.provision()).resolves.toEqual(data)
    data.prerequisites.v2_available = true
    respond(data)
    await expect(rkpDeviceApi.provision()).rejects.toMatchObject({ code: "contract_mismatch" })
  })

  it("accepts an explicit not-returned manufacturer result", async () => {
    const data = result("v1")
    data.manufacturer = { status: "not_returned", requested: "Xiaomi", certificate: null }
    respond(data)
    await expect(rkpDeviceApi.provision("v1", "Xiaomi")).resolves.toMatchObject({
      manufacturer: data.manufacturer,
    })
  })

  it.each([
    { status: "not_returned", requested: "Xiaomi", certificate: "Xiaomi" },
    { status: "matched", requested: "Xiaomi", certificate: null },
    { status: "matched", requested: "Xiaomi", certificate: "Other" },
    { status: "not_requested", requested: "Xiaomi", certificate: null },
  ] as const)("rejects inconsistent manufacturer reports %j", async (manufacturer) => {
    const data = result("v1")
    data.manufacturer = manufacturer
    respond(data)
    await expect(rkpDeviceApi.provision("v1", "Xiaomi")).rejects.toMatchObject({
      code: "contract_mismatch",
    })
  })
  it.each(["auto", "v1", "v2", "v1-native"] as const)(
    "accepts the verification semantics of %s",
    async (protocol) => {
      history.replaceState(null, "", "/")
      const data = result(protocol)
      respond(data)
      await expect(rkpDeviceApi.provision(protocol)).resolves.toEqual(data)
    },
  )

  it.each([{ signature_valid: false }, { cert_type: "widevine" }, { keys_to_sign: 2 }])(
    "rejects a V2 success report with %j",
    async (invalid) => {
      history.replaceState(null, "", "/")
      const data = result("v2")
      Object.assign(data.local_verify!, invalid)
      respond(data)
      await expect(rkpDeviceApi.provision("v2")).rejects.toMatchObject({
        code: "contract_mismatch",
      })
    },
  )

  it.each(["v2,v1", "v2"])("accepts ordered fallback after %s fail", async (failures) => {
    history.replaceState(null, "", `/?rkp_fail=${failures}`)
    const data = result()
    respond(data)
    await expect(rkpDeviceApi.provision()).resolves.toEqual(data)
  })

  it("accepts fallback that skips the unavailable AIDL adapter", async () => {
    history.replaceState(null, "", "/?rkp=v2-only&rkp_fail=v2")
    const data = result()
    respond(data)
    await expect(rkpDeviceApi.provision()).resolves.toEqual(data)
  })

  it("rejects reversed failures even when the final method and errors agree", async () => {
    history.replaceState(null, "", "/?rkp_fail=v2,v1")
    const data = result()
    data.attempts = [data.attempts[1]!, data.attempts[0]!, data.attempts[2]!]
    respond(data)
    await expect(rkpDeviceApi.provision()).rejects.toMatchObject({
      code: "contract_mismatch",
    })
  })
})
