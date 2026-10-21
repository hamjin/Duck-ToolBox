import { afterEach, describe, expect, it } from "vitest"

import mock from "./mock"

const originalUrl = location.href
afterEach(() => history.replaceState(null, "", originalUrl))

function provision(protocol?: string, manufacturer?: string) {
  const flags: Record<string, string | true> = { "acknowledge-limitations": true }
  if (protocol !== undefined) flags.protocol = protocol
  if (manufacturer !== undefined) flags.manufacturer = manufacturer
  return mock.handlers["rkp-device.provision"]!([], flags, undefined)
}

describe("device RKP mock protocol contract", () => {
  it.each([
    ["missing", "certificate_manufacturer_missing"],
    ["mismatch", "certificate_manufacturer_mismatch"],
    ["malformed", "invalid_provisioning_info"],
  ])("rejects %s certificate metadata only when manufacturer is requested", (failure, code) => {
    history.replaceState(null, "", `/?rkp_manufacturer=${failure}`)
    expect(() => provision("v2", "Google")).toThrowError(expect.objectContaining({ code }))
    expect(() => provision("auto", "Google")).toThrowError(
      expect.objectContaining({ code: "all_methods_failed" }),
    )
    expect(provision("v2", "  ")).toMatchObject({ csr_protocol: "v2" })
  })

  it.each([
    ["v1-only", "v2"],
    ["v1-only", "v1-native"],
    ["v2-only", "v1"],
  ])("rejects unavailable protocol %s/%s", (scenario, protocol) => {
    history.replaceState(null, "", `/?rkp=${scenario}`)
    expect(() => provision(protocol)).toThrowError(
      expect.objectContaining({ code: "unsupported_device" }),
    )
  })

  it("uses automatic selection when the CLI protocol flag is omitted", () => {
    history.replaceState(null, "", "/?rkp=v1-only")
    expect(provision()).toMatchObject({ csr_protocol: "v1", local_verify: null })
  })

  it("retains V2 preference when both protocols have resources", () => {
    history.replaceState(null, "", "/")
    expect(provision()).toMatchObject({
      csr_protocol: "v2",
      local_verify: { signature_valid: true },
    })
  })

  it("allows explicit native V1 while automatic mode prefers V2", () => {
    history.replaceState(null, "", "/?rkp=v2-only")
    expect(provision("v1-native")).toMatchObject({
      csr_protocol: "v1",
      csr_backend: "native",
      local_verify: null,
    })
    expect(provision()).toMatchObject({ csr_protocol: "v2", csr_backend: "native" })
  })

  it("tries each available method until native V1 succeeds", () => {
    history.replaceState(null, "", "/?rkp_fail=v2,v1")
    expect(provision()).toMatchObject({
      csr_protocol: "v1",
      csr_backend: "native",
      attempts: [
        { method: "v2", error: { code: "ta_rejected" } },
        { method: "v1", error: { code: "ta_rejected" } },
        { method: "v1-native", error: null },
      ],
    })
  })

  it("returns one aggregate failure only after all available methods fail", () => {
    history.replaceState(null, "", "/?rkp_fail=v2,v1,v1-native")
    expect(() => provision()).toThrowError(expect.objectContaining({ code: "all_methods_failed" }))
    expect(() => provision("v2")).toThrowError(expect.objectContaining({ code: "ta_rejected" }))
  })

  it("skips methods without resources", () => {
    history.replaceState(null, "", "/?rkp=v2-only&rkp_fail=v2")
    expect(provision()).toMatchObject({
      attempts: [
        { method: "v2", error: { code: "ta_rejected" } },
        { method: "v1-native", error: null },
      ],
    })
  })

  it("rejects invalid protocol flags as usage errors", () => {
    expect(() => provision("v3")).toThrowError(expect.objectContaining({ code: "usage_error" }))
  })

  it("requires acknowledgement before checking device prerequisites", () => {
    history.replaceState(null, "", "/?soc=unknown")
    expect(() => mock.handlers["rkp-device.provision"]!([], {}, undefined)).toThrowError(
      expect.objectContaining({ code: "acknowledgement_required" }),
    )
  })
})
