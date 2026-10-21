# Device RKP protocol diagnosis: SM8550 / socrates

Tested on 2026-10-22 with a Redmi 22127RK46C (`socrates`), QTI SM8550,
Android 16. These findings apply to the connected device and its installed
firmware, not every Qualcomm implementation.

## V2: not implemented by this firmware

A small `app_process` probe loaded the device's RKP AIDL classes and called
`getHardwareInfo`. The report was:

```text
versionNumber=2
rpcAuthorName=Qualcomm Technologies
supportedEekCurve=2
supportedNumKeysInCsr=4
```

Calling `generateCertificateRequestV2` with a fixed public test key returned
`android.os.RemoteException: Method generateCertificateRequestV2 is unimplemented.`
No CSR from this local probe was sent to a provisioning server.

The native `0x3122` command returned status `-40` (`INVALID_TAG`) through both
the existing `send_cmd` adapter and the vendor's `init` / `sendCmd` shared-buffer
path. Changing buffers did not enable this command.

The [AOSP RKP interface versioning contract](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl)
does not require protocol v1/v2 implementations to implement
`generateCertificateRequestV2`; protocol v3 implementations must provide it.
Android's OS version alone does not establish RKP protocol support.

The backend now reports a scoped `unsupported_protocol` diagnostic when native
CSR_V2 returns `-40`. Its message retains the command and status and explains
that the private interface may not be implemented. Other rejections, including
`-40` for another command, retain their existing classification. Resource checks
still describe installed files, not proven private-ABI compatibility.

## V1 Native: private request field order

The device's `libqtikeymint.so` implements
`KeymasterSerialize::serializeGenerateCsr` and uses command `0x311e`.
Its private CBOR map is written in this order:

```text
55: production/test mode
 4: challenge
56: MAC key
57: MAC tag
58: EEK chain
```

Duck ToolBox used the shared canonical CBOR encoder, which sorted key `4` before
key `55`. Controlled offline probes used identical public-key, MAC, challenge and
EEK data, varying only field order and the transport's buffer handling:

| Transport | Field order | TA result | Response payload |
| --- | --- | --- | --- |
| `send_cmd`, separate request/response buffers | `4,55,56,57,58` | `-20` | No successful CSR |
| Vendor `init` / `sendCmd`, shared buffer | `4,55,56,57,58` | `-20` | No successful CSR |
| `send_cmd`, separate request/response buffers | `55,4,56,57,58` | `0` | 744 bytes |
| Vendor `init` / `sendCmd`, shared buffer | `55,4,56,57,58` | `0` | 744 bytes |

This firmware's private decoder is order-sensitive despite both maps being valid
CBOR. The fix prefers the vendor's observed order while retaining the original
canonical encoding as a compatibility fallback. COSE keys, MAC structures,
signed evidence and server CSR encoding keep their existing rules.

Both native transports are implemented. Native V1 tries these combinations in order:

1. Vendor field order with ordinary `send_cmd` buffers.
2. Vendor field order with the vendor-owned `init` / `sendCmd` shared buffer.
3. Canonical field order with ordinary `send_cmd` buffers.
4. Canonical field order with the vendor-owned shared buffer.

V2 tries both buffer modes with its existing request encoding. Each invocation
runs in a fresh isolated worker with the existing 30-second timeout. A rejected
call, unavailable ABI symbol, worker failure or locally invalid response advances
to the next choice. The first locally valid CSR ends compatibility fallback; the
server receives one submission for that method. A server rejection is handled by
the existing protocol-level retry policy, not by resubmitting the same CSR through
another buffer mode. All compatibility failures retain their labels and reasons.

The two V1 encodings carry identical challenge, MAC key/tag, public-key binding and
EEK values. Shared-buffer input capacity and reply pointer/length ranges are
checked before copying. The reply must be inside the live vendor buffer and beyond
the request, and is copied before the vendor object is destroyed.

The inspected device-library SHA-256 digests are:

- `libkeymasterdeviceutils.so`: `1c2172c492cbe8d1c4dc990c8d0fd8deed036d8bf9c0e337139d66f0caa3d7d2`
- `libqtikeymint.so`: `657093d0991515f91e6ea35192b0cfe66bcbd52196a3b906fabe64086ab1ddcb`

## Verification

The rebuilt backend completed a real Google provisioning round trip with
`--protocol v1-native --manufacturer Xiaomi`, reporting `csr_protocol=v1`,
`csr_backend=native` and one successful `v1-native` attempt. It exported four
certificates. The saved chain matched the certificate DER in the keybox, every
issuer signature verified, and the generated private key matched the leaf.
Both CSR DeviceInfo maps contained the manufacturer. The server still omitted
the certificate's optional manufacturer field, correctly reported as
`manufacturer.status=not_returned`.

Explicit V2 returned `unsupported_protocol` and left its output directory empty.
Automatic mode recorded the V2 diagnostic, then completed through V1 AIDL.
V1 Native success was not an AIDL fallback.

The previous installed backend and WebUI were backed up under
`/data/local/tmp/duck-rkp-protocol-build/backup`. The rebuilt backend and WebUI
were installed together, and their hashes matched the local build. A final
`v1-native` issuance through the installed module succeeded in the normal output
directory; the four certificate signatures and private-key binding were checked
again. The compatibility version was then deployed and verified by another native
issuance through the installed module.

A dedicated production-endpoint diagnostic also exercised the new Rust shared
buffer path directly. It generated an ephemeral test key in memory, requested a
fresh challenge, called the worker with `--buffer shared`, and received four
Google-signed certificates matching that key. Every issuer signature verified.
The diagnostic exported no keybox and retained no private key. On this firmware,
both V2 buffer modes still returned `-40`, with both reasons retained in the error.

Local checks passed: 118 device-RKP Rust tests, Clippy with warnings denied,
Rust formatting, the 600-line source limit, the Android arm64 release build,
the production WebUI build, and all 14 localized error-key sets. Regression
coverage checks the actual private-wire order, the independent HMAC vector,
response error classification and worker error serialization. Compatibility tests
cover success at each of the four V1 choices, shared-buffer V2 success, local
validation failures, bounded shared reply ranges, unchanged request semantics,
single server submission and complete failure diagnostics.

Probe sources, vendor disassembly and result summaries remain in the ignored
`target/device-rkp/socrates-protocols` directory. No private key or complete
certificate body is included in this report.
