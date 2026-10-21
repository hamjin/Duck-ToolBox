use std::io::Cursor;

use anyhow::{Context, Result, bail};
use ciborium::value::Value;
use duck_rkp::{
    cbor::{as_array, as_bytes, as_map, encode, int, map_get},
    verify::{VerifyReport, verify_csr},
};

use crate::error::DeviceRkpError;

pub(crate) const CSR_COMMAND: u32 = 0x3122;

/// The TA writes its response into one fixed shared buffer.
pub(crate) const BUFFER_SIZE: usize = 0xa000;
/// A request that cannot fit that buffer is refused before anything reaches vendor code.
pub(crate) const MAX_REQUEST_SIZE: usize = 0x9000;
/// Upper bound for the concatenated DER certificate chain the server returns.
pub(crate) const MAX_CERT_CHAIN_LEN: usize = 0x4000;

/// Builds the `CSR_V2` request the TA expects: `{4: challenge, 57: bstr([COSE_Key])}`,
/// prefixed with the little-endian command id.
pub(crate) fn build_request(challenge: &[u8], public_key: &Value) -> Result<Vec<u8>> {
    let payload = encode(&Value::Map(vec![
        (int(4), Value::Bytes(challenge.to_vec())),
        (
            int(57),
            Value::Bytes(encode(&Value::Array(vec![public_key.clone()]))?),
        ),
    ]))?;
    validate_request(&payload)?;
    let mut request = CSR_COMMAND.to_le_bytes().to_vec();
    request.extend_from_slice(&payload);
    Ok(request)
}

/// Only one typed CSR operation crosses the vendor ABI boundary.
pub(crate) fn validate_request(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_REQUEST_SIZE - 4 {
        bail!("CSR request is too large");
    }
    let value = decode_exact(payload)?;
    let entries = as_map(&value, "CSR request")?;
    if entries.len() != 2 || map_get(entries, 4).is_none() || map_get(entries, 57).is_none() {
        bail!("CSR request must contain only challenge and keysToSign");
    }
    let challenge = as_bytes(required_map_get(entries, 4, "challenge")?, "challenge")?;
    let keys = decode_exact(as_bytes(
        required_map_get(entries, 57, "keysToSign")?,
        "keysToSign bytes",
    )?)?;
    let keys = as_array(&keys, "keysToSign")?;
    if keys.len() != 1 {
        bail!("exactly one P-256 key is required");
    }
    validate_inputs(challenge, &keys[0])
}

/// Shared semantic contract for the single-key device issuers, independent of TA framing.
pub(crate) fn validate_inputs(challenge: &[u8], public_key: &Value) -> Result<()> {
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("server challenge must be 1..64 bytes");
    }
    let key = as_map(public_key, "P-256 key")?;
    if key.len() != 5
        || [1, 3, -1, -2, -3]
            .iter()
            .any(|label| map_get(key, *label).is_none())
    {
        bail!("unexpected P-256 key fields");
    }
    for (label, expected) in [(1, 2), (3, -7), (-1, 1)] {
        if map_get(key, label) != Some(&int(expected)) {
            bail!("keysToSign must use ES256 / P-256");
        }
    }
    let mut point = vec![4];
    for label in [-2, -3] {
        let coordinate = as_bytes(
            required_map_get(key, label, "P-256 coordinate")?,
            "P-256 coordinate",
        )?;
        if coordinate.len() != 32 {
            bail!("P-256 coordinates must contain 32 bytes");
        }
        point.extend_from_slice(coordinate);
    }
    p256::PublicKey::from_sec1_bytes(&point).context("invalid P-256 point")?;
    Ok(())
}

#[cfg(any(test, all(target_os = "android", target_arch = "aarch64")))]
pub(crate) fn command_response_payload(command: u32, response: &[u8]) -> Result<Vec<u8>> {
    response_payload(response).map_err(|error| {
        if command == CSR_COMMAND
            && matches!(error.downcast_ref::<DeviceRkpError>(), Some(DeviceRkpError::Rejected(-40)))
        {
            DeviceRkpError::UnsupportedProtocol(
                "native CSR_V2 (0x3122) was rejected with INVALID_TAG (-40); this firmware may not implement the private V2 CSR interface".into(),
            ).into()
        } else {
            error
        }
    })
}

#[cfg(any(test, all(target_os = "android", target_arch = "aarch64")))]
pub(crate) fn response_payload(response: &[u8]) -> Result<Vec<u8>> {
    if response.len() < 8 {
        return Err(DeviceRkpError::InvalidResponse("truncated header".into()).into());
    }
    let status = i32::from_le_bytes(response[..4].try_into().unwrap());
    if status != 0 {
        return Err(DeviceRkpError::Rejected(status).into());
    }
    let length = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
    if length == 0 || length > BUFFER_SIZE - 8 || length > response.len() - 8 {
        return Err(DeviceRkpError::InvalidResponse("invalid payload length".into()).into());
    }
    Ok(response[8..8 + length].to_vec())
}

pub(crate) fn unwrap_csr(payload: &[u8]) -> Result<Vec<u8>> {
    parse_csr_response(payload)
        .map_err(|error| DeviceRkpError::InvalidResponse(format!("{error:#}")).into())
}

fn parse_csr_response(payload: &[u8]) -> Result<Vec<u8>> {
    let value = decode_exact(payload)?;
    // The reference transport accepts both a bare AuthenticatedRequest array and
    // firmware that wraps it in field 61. Signature and binding checks follow either.
    if matches!(value, Value::Array(_)) {
        return Ok(payload.to_vec());
    }
    let entries = as_map(&value, "KeyMint CSR response")?;
    if entries.len() != 1 {
        bail!("KeyMint CSR response must contain exactly one field");
    }
    let encoded = map_get(entries, 61).context("KeyMint CSR response missing field 61")?;
    let csr = as_bytes(encoded, "AuthenticatedRequest")?;
    if csr.is_empty() {
        bail!("KeyMint returned an empty CSR");
    }
    Ok(csr.to_vec())
}

/// Validate signatures, then bind the signed request to this challenge and this key.
pub(crate) fn validate_csr(
    csr: &[u8],
    challenge: &[u8],
    public_key: &Value,
) -> Result<VerifyReport> {
    let validate = || -> Result<VerifyReport> {
        let report = verify_csr(csr)?;
        if !report.signature_valid || report.cert_type != "keymint" || report.keys_to_sign != 1 {
            bail!("expected one keymint key with a valid signature");
        }
        ensure_csr_binds(csr, challenge, public_key)?;
        Ok(report)
    };
    validate().map_err(|error| DeviceRkpError::InvalidCsr(format!("{error:#}")).into())
}

/// The signed payload must name this challenge and this key. Kept separate from
/// [`validate_csr`] so a CSR with a valid signature over a malformed payload can still
/// reach these shape checks in a test.
fn ensure_csr_binds(csr: &[u8], challenge: &[u8], public_key: &Value) -> Result<()> {
    // `verify_csr` bounds the outer arrays, but a hostile TA can still hand us short inner
    // ones, so every step is checked instead of indexed.
    let value = decode_exact(csr)?;
    let request = as_array(&value, "AuthenticatedRequest")?;
    let signed = as_array(array_get(request, 3, "SignedData")?, "SignedData")?;
    let signed_payload = decode_exact(as_bytes(
        array_get(signed, 2, "SignedData payload")?,
        "SignedData payload",
    )?)?;
    let signed_payload = as_array(&signed_payload, "signed payload")?;
    if as_bytes(array_get(signed_payload, 0, "challenge")?, "challenge")? != challenge {
        bail!("CSR challenge does not match the server challenge");
    }
    let contents = decode_exact(as_bytes(
        array_get(signed_payload, 1, "CSR payload bytes")?,
        "CSR payload bytes",
    )?)?;
    let contents = as_array(&contents, "CSR payload")?;
    let keys = as_array(array_get(contents, 3, "keysToSign")?, "keysToSign")?;
    let Some(issued) = keys.first() else {
        bail!("keysToSign must contain exactly one key, got 0");
    };
    if encode(issued)? != encode(public_key)? {
        bail!("CSR public key does not match the generated key");
    }
    Ok(())
}

/// A map lookup that reports a missing label instead of panicking; `map_get` is only used
/// where absence is already handled.
fn required_map_get<'a>(
    entries: &'a [(Value, Value)],
    key: i128,
    label: &str,
) -> Result<&'a Value> {
    map_get(entries, key).ok_or_else(|| anyhow::anyhow!("{label} is missing label {key}"))
}

/// A bounds-checked array index, so a malformed response is an error rather than a panic.
fn array_get<'a>(items: &'a [Value], index: usize, label: &str) -> Result<&'a Value> {
    items
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("{label} is missing entry {index}"))
}

/// The KeyMint `send_cmd` byte payload for one CSR request, checked before it is sent.
pub(crate) fn ta_payload(request: &[u8]) -> Result<&[u8]> {
    let Some((command, payload)) = request.split_at_checked(4) else {
        bail!("request is missing its command header");
    };
    if command == crate::v1::native::COMMAND.to_le_bytes() {
        crate::v1::native::validate_request(payload)?;
        return Ok(payload);
    }
    if command != CSR_COMMAND.to_le_bytes() {
        bail!("worker only accepts CSR_V2 or native V1 requests");
    }
    validate_request(payload)?;
    Ok(payload)
}

pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Value> {
    let mut reader = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut reader).context("decode CBOR")?;
    if reader.position() != bytes.len() as u64 {
        bail!("CBOR contains trailing data");
    }
    Ok(value)
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
