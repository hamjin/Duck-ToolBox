//! Check the server-signed RKP certificate metadata read by KeyAttestation.
//! Its ProvisioningInfo parser reads CBOR integer key 3 from this X.509 extension.
//! The original certificate bytes must be retained: editing the extension breaks
//! the issuer's signature, and XML metadata cannot substitute for it.

use anyhow::Result;
use ciborium::value::Value;
use duck_rkp::cbor::{decode, map_get};
use serde::Serialize;
use x509_cert::{
    Certificate,
    der::{Decode, asn1::ObjectIdentifier},
};

use crate::error::DeviceRkpError;

const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.30");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManufacturerStatus {
    #[default]
    NotRequested,
    Matched,
    NotReturned,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ManufacturerReport {
    pub status: ManufacturerStatus,
    pub requested: Option<String>,
    pub certificate: Option<String>,
}

/// A request hint does not oblige the issuer to include this optional extension field.
/// Missing metadata is reported explicitly; an actual mismatch still fails validation.
pub(crate) fn check_manufacturer(
    leaf_der: &[u8],
    expected: Option<&str>,
) -> Result<ManufacturerReport> {
    let Some(expected) = expected else {
        return Ok(ManufacturerReport::default());
    };
    let certificate = read_manufacturer(leaf_der)?;
    if certificate
        .as_deref()
        .is_some_and(|value| value != expected)
    {
        return Err(DeviceRkpError::CertificateManufacturerMismatch.into());
    }
    Ok(ManufacturerReport {
        status: if certificate.is_some() {
            ManufacturerStatus::Matched
        } else {
            ManufacturerStatus::NotReturned
        },
        requested: Some(expected.to_owned()),
        certificate,
    })
}

fn read_manufacturer(leaf_der: &[u8]) -> Result<Option<String>> {
    let certificate =
        Certificate::from_der(leaf_der).map_err(|_| DeviceRkpError::InvalidProvisioningInfo)?;
    let mut extensions = certificate
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|extension| extension.extn_id == OID);
    let Some(extension) = extensions.next() else {
        return Ok(None);
    };
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
    let Some(value) = map_get(&entries, 3) else {
        return Ok(None);
    };
    let Value::Text(manufacturer) = value else {
        return Err(DeviceRkpError::InvalidProvisioningInfo.into());
    };
    if manufacturer.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(manufacturer.clone()))
}

#[cfg(test)]
#[path = "provisioning_info_tests.rs"]
mod tests;
