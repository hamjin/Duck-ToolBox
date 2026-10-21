//! Check the server-signed RKP certificate metadata read by KeyAttestation.
//! Its ProvisioningInfo parser reads CBOR integer key 3 from this X.509 extension.
//! The original certificate bytes must be retained: editing the extension breaks
//! the issuer's signature, and XML metadata cannot substitute for it.

use anyhow::Result;
use ciborium::value::Value;
use duck_rkp::cbor::{decode, map_get};
use x509_cert::{
    Certificate,
    der::{Decode, asn1::ObjectIdentifier},
};

use crate::error::DeviceRkpError;

const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.30");

pub(crate) fn require_manufacturer(leaf_der: &[u8], expected: &str) -> Result<()> {
    let certificate =
        Certificate::from_der(leaf_der).map_err(|_| DeviceRkpError::InvalidProvisioningInfo)?;
    let mut extensions = certificate
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|extension| extension.extn_id == OID);
    let extension = extensions
        .next()
        .ok_or(DeviceRkpError::CertificateManufacturerMissing)?;
    if extensions.next().is_some() {
        return Err(DeviceRkpError::InvalidProvisioningInfo.into());
    }
    // extn_value has already removed the DER OCTET STRING wrapper exposed by Java's
    // X509Certificate.getExtensionValue; its contents are the CBOR map itself.
    let value = decode(extension.extn_value.as_bytes())
        .map_err(|_| DeviceRkpError::InvalidProvisioningInfo)?;
    let Value::Map(entries) = value else {
        return Err(DeviceRkpError::InvalidProvisioningInfo.into());
    };
    if entries
        .iter()
        .any(|(key, _)| !matches!(key, Value::Integer(_)))
    {
        return Err(DeviceRkpError::InvalidProvisioningInfo.into());
    }
    let value = map_get(&entries, 3).ok_or(DeviceRkpError::CertificateManufacturerMissing)?;
    let Value::Text(manufacturer) = value else {
        return Err(DeviceRkpError::InvalidProvisioningInfo.into());
    };
    if manufacturer.trim().is_empty() {
        return Err(DeviceRkpError::CertificateManufacturerMissing.into());
    }
    if manufacturer != expected {
        return Err(DeviceRkpError::CertificateManufacturerMismatch.into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "provisioning_info_tests.rs"]
mod tests;
