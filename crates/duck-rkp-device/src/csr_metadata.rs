//! The provisioning server's unverified DeviceInfo, outside the HAL-signed evidence.

use anyhow::{Result, bail};
use ciborium::value::Value;
use duck_rkp::cbor::{as_array, as_map, decode, encode as cbor_encode, text};

use crate::protocol::BUFFER_SIZE;

pub(crate) fn encode(fingerprint: &str, manufacturer: &str) -> Result<Vec<u8>> {
    cbor_encode(&Value::Map(vec![
        (text("fingerprint"), text(fingerprint)),
        (text("manufacturer"), text(manufacturer)),
    ]))
}

/// As in KeyAttestation's V2 client, append UnverifiedDeviceInfo as the fifth item.
/// Rebuild only the outer array header: UDS certificates, DICE and SignedData retain
/// their exact bytes, including noncanonical or indefinite encodings from the HAL.
pub(crate) fn append_v2(csr: &[u8], metadata: &[u8]) -> Result<Vec<u8>> {
    if as_array(&decode(csr)?, "AuthenticatedRequest")?.len() != 4 {
        bail!("expected a four-item AuthenticatedRequest");
    }
    as_map(&decode(metadata)?, "UnverifiedDeviceInfo")?;
    let (header, end) = match csr[0] {
        0x84 => (1, csr.len()),
        0x98 => (2, csr.len()),
        0x99 => (3, csr.len()),
        0x9a => (5, csr.len()),
        0x9b => (9, csr.len()),
        0x9f => (1, csr.len() - 1),
        _ => bail!("invalid AuthenticatedRequest array header"),
    };
    let mut result = vec![0x85];
    result.extend_from_slice(&csr[header..end]);
    result.extend_from_slice(metadata);
    if result.len() > BUFFER_SIZE {
        bail!("V2 CSR with UnverifiedDeviceInfo exceeds the response limit");
    }
    Ok(result)
}

#[cfg(test)]
#[path = "csr_metadata_tests.rs"]
mod tests;
