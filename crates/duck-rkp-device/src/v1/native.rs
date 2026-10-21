//! Legacy Qualcomm generateCsr framing, adapted from the native V1 contribution.
//! The command and vendor ABI require firmware validation on the target device.

use anyhow::{Context, Result, bail};
use ciborium::value::Value;
use duck_rkp::{
    cbor::{as_array, as_bytes, as_map, int, map_get},
    cose::key_mac_tag,
};

use super::Response;
use crate::protocol::{self, BUFFER_SIZE, MAX_REQUEST_SIZE, decode_exact};

pub(crate) const COMMAND: u32 = 0x311e;

pub(crate) struct Request {
    pub bytes: Vec<u8>,
    pub canonical_bytes: Vec<u8>,
    pub mac_tag: [u8; 32],
}

pub(crate) fn request(challenge: &[u8], public_key: &Value, eek: &[u8]) -> Result<Request> {
    let mut mac_key = [0; 32];
    getrandom::fill(&mut mac_key).context("generate native V1 MAC key")?;
    build_request(challenge, public_key, eek, &mac_key)
}

fn build_request(
    challenge: &[u8],
    public_key: &Value,
    eek: &[u8],
    mac_key: &[u8; 32],
) -> Result<Request> {
    protocol::validate_inputs(challenge, public_key)?;
    let mac_tag = key_mac_tag(mac_key, std::slice::from_ref(public_key))?;
    // Match KeymasterSerialize::serializeGenerateCsr's wire order. Some Qualcomm
    // firmware consumes testMode before challenge and rejects the canonically
    // sorted map (4 before 55) with -20, even though both maps are valid CBOR.
    // This exception is only for the private TA envelope, not COSE MAC/signature data.
    let fields = Value::Map(vec![
        (int(55), int(0)),
        (int(4), Value::Bytes(challenge.to_vec())),
        (int(56), Value::Bytes(mac_key.to_vec())),
        (int(57), Value::Bytes(mac_tag.to_vec())),
        (int(58), Value::Bytes(eek.to_vec())),
    ]);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&fields, &mut payload).context("encode native V1 vendor request")?;
    validate_request(&payload)?;
    let mut bytes = COMMAND.to_le_bytes().to_vec();
    bytes.extend_from_slice(&payload);
    let canonical_payload = duck_rkp::cbor::encode(&fields)?;
    validate_request(&canonical_payload)?;
    let mut canonical_bytes = COMMAND.to_le_bytes().to_vec();
    canonical_bytes.extend_from_slice(&canonical_payload);
    Ok(Request {
        bytes,
        canonical_bytes,
        mac_tag,
    })
}

/// The worker accepts one bounded production-mode request, never arbitrary TA commands.
pub(crate) fn validate_request(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_REQUEST_SIZE - 4 {
        bail!("native V1 request exceeds its size limit");
    }
    let value = decode_exact(payload)?;
    let fields = as_map(&value, "native V1 request")?;
    if fields.len() != 5 || required(fields, 55)? != &int(0) {
        bail!("native V1 requires only challenge, production mode, MAC key/tag and EEK chain");
    }
    let challenge = as_bytes(required(fields, 4)?, "challenge")?;
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("native V1 challenge must contain 1..64 bytes");
    }
    for label in [56, 57] {
        if as_bytes(required(fields, label)?, "native V1 MAC key/tag")?.len() != 32 {
            bail!("native V1 MAC key and tag must each contain 32 bytes");
        }
    }
    let chain = decode_exact(as_bytes(required(fields, 58)?, "EEK chain")?)?;
    let certificates = as_array(&chain, "EEK chain")?;
    if certificates.is_empty() {
        bail!("native V1 EEK chain is empty");
    }
    for certificate in certificates {
        let fields = as_array(certificate, "EEK certificate")?;
        if fields.len() != 4 {
            bail!("native V1 EEK certificate must be COSE_Sign1");
        }
        as_bytes(&fields[0], "EEK protected headers")?;
        as_map(&fields[1], "EEK unprotected headers")?;
        as_bytes(&fields[2], "EEK public key payload")?;
        as_bytes(&fields[3], "EEK signature")?;
    }
    Ok(())
}

/// Native V1 supplies the MAC key/tag to the TA; AIDL V1 obtains the tag from the HAL.
/// Both adapters feed the same opaque-evidence validator and server CSR assembler.
pub(crate) fn response(payload: &[u8], mac_tag: &[u8; 32]) -> Result<Response> {
    if payload.len() > BUFFER_SIZE {
        bail!("native V1 response exceeds its size limit");
    }
    let value = decode_exact(payload)?;
    let fields = as_map(&value, "native V1 response")?;
    if fields.len() != 2 {
        bail!("native V1 response must contain only DeviceInfo and ProtectedData");
    }
    Ok(Response {
        mac: mac_tag.to_vec(),
        device_info: as_bytes(required(fields, 59)?, "DeviceInfo")?.to_vec(),
        protected_data: as_bytes(required(fields, 60)?, "ProtectedData")?.to_vec(),
    })
}

fn required(fields: &[(Value, Value)], label: i128) -> Result<&Value> {
    map_get(fields, label).ok_or_else(|| anyhow::anyhow!("native V1 field {label} is missing"))
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
