# RKP manufacturer: SM8550 device investigation

Tested on 2026-10-22 with a Redmi 22127RK46C (`socrates`), QTI SM8550,
Android 16, and the Google production provisioning endpoint. The device reports
`ro.product.manufacturer=Xiaomi`. The installed backend initially used feature
contract 6 and rejected successful V1 issuance as `certificate_manufacturer_missing`.

## Findings

A local forwarding proxy captured one request from the installed V1 AIDL issuer.
It forwarded the original CBOR body unchanged to Google's HTTPS endpoint.

- The `signCertificates` URL contained `manufacturer=Xiaomi`.
- The CSR's authenticated DeviceInfo contained `manufacturer: Xiaomi`.
- The CSR's UnverifiedDeviceInfo contained the same manufacturer and the request
  fingerprint.
- Google returned HTTP 200 and a four-certificate chain with valid issuer signatures.
- The attestation-key certificate's provisioning extension
  `1.3.6.1.4.1.11129.2.1.30` contained top-level integer keys **1 and 5**, not 3.
  None of the other certificates supplied a manufacturer field either.
- A control request without the optional manufacturer also succeeded and lacked
  top-level key 3. A nested key 3 inside key 5 is not a manufacturer field.

This was not a missing WebUI argument, a missing CSR field, or a parser overlooking
the certificate. The previous implementation's strict export rule treated optional
server metadata as a required response. The simulated echo server had not established
that Google's production server would echo this request field.

[KeyAttestation's parser](https://github.com/hamjin/KeyAttestation/blob/aecec8c94e19d81321c89b07d2083a14200d88cf/app/src/main/java/io/github/vvb2060/keyattestation/attestation/ProvisioningInfo.java)
reads manufacturer from top-level CBOR key 3. The current
[AOSP provisioning extension documentation](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
does not require that field. Sending a request hint does not guarantee its inclusion
in the server-signed certificate.

## Corrected behavior

Missing manufacturer no longer blocks export. Successful results include a
`manufacturer` report with separate request and certificate values:

```json
{
  "status": "not_returned",
  "requested": "Xiaomi",
  "certificate": null
}
```

The other statuses are `matched` and `not_requested`. A present mismatched value,
wrong field type, duplicate field, or malformed extension still fails validation.
Automatic mode stops after a successful issuance even if manufacturer was omitted.
The WebUI shows “服务器未返回 manufacturer” and retains the install/export result.
Feature contract 7 requires updating the backend and WebUI together.

## Verification and deployment

The rebuilt Android arm64 backend first ran in an isolated device test directory.
The saved CSR matched the captured request, and the saved chain and all four
certificates in `keybox.xml` matched the returned DER bytes. The private key matched
the leaf certificate, every issuer signature verified, and private output files
retained mode `0600`. No certificate was rewritten or re-signed.

After backing up the installed backend and WebUI under
`/data/local/tmp/duck-rkp-manufacturer-fixed/backup`, both rebuilt artifacts were
installed. SHA-256 checks matched the local build. A final request through the
installed backend contacted Google directly using automatic mode: V2 was rejected
by the firmware with status -40; V1 AIDL then issued successfully and returned the
`not_returned` report above. The original Google-signed keybox was exported to the
module's normal output directory. No keybox was installed into a keystore module.

Checks: 113 device-RKP Rust tests, 20 CLI tests, 37 WebUI unit tests, 18 browser
tests, Clippy, type checking, ESLint, formatting, the source line limit, and both
the Android arm64 release and production WebUI builds. Raw captures stay in the
ignored local `target/device-rkp/manufacturer-investigation` directory; this report
contains no private keys or certificate bodies.
