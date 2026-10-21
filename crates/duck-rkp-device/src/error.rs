use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub(crate) enum DeviceRkpError {
    #[error(
        "only some devices support this feature and only RKP certificates can be issued; pass --acknowledge-limitations to continue"
    )]
    AcknowledgementRequired,
    #[error("device prerequisites are not met: {0}")]
    UnsupportedDevice(String),
    #[error("KeyMint worker exceeded its 30 second timeout")]
    Timeout,
    #[error("KeyMint transport failed: {0}")]
    Transport(String),
    #[error("KeyMint rejected the CSR request with status {0}")]
    Rejected(i32),
    #[error("invalid KeyMint response: {0}")]
    InvalidResponse(String),
    #[error("CSR validation failed: {0}")]
    InvalidCsr(String),
    #[error("the issued certificate does not match the generated P-256 key")]
    CertificateMismatch,
    #[error(
        "the issued certificate is missing RKP Provisioning manufacturer (OID 1.3.6.1.4.1.11129.2.1.30, CBOR key 3); the server must include it before signing"
    )]
    CertificateManufacturerMissing,
    #[error(
        "the issued certificate RKP Provisioning manufacturer does not match the requested manufacturer"
    )]
    CertificateManufacturerMismatch,
    #[error("the issued certificate RKP provisioning information is malformed")]
    InvalidProvisioningInfo,
    #[error("all available issuance methods failed: {0}")]
    AllMethodsFailed(String),
}

pub(crate) fn code_of(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<DeviceRkpError>() {
            return match error {
                DeviceRkpError::AcknowledgementRequired => "acknowledgement_required",
                DeviceRkpError::UnsupportedDevice(_) => "unsupported_device",
                DeviceRkpError::Timeout => "ta_timeout",
                DeviceRkpError::Transport(_) => "ta_transport_error",
                DeviceRkpError::Rejected(_) => "ta_rejected",
                DeviceRkpError::InvalidResponse(_) => "invalid_ta_response",
                DeviceRkpError::InvalidCsr(_) => "invalid_device_csr",
                DeviceRkpError::CertificateMismatch => "certificate_key_mismatch",
                DeviceRkpError::CertificateManufacturerMissing => {
                    "certificate_manufacturer_missing"
                }
                DeviceRkpError::CertificateManufacturerMismatch => {
                    "certificate_manufacturer_mismatch"
                }
                DeviceRkpError::InvalidProvisioningInfo => "invalid_provisioning_info",
                DeviceRkpError::AllMethodsFailed(_) => "all_methods_failed",
            };
        }
    }
    duck_rkp::error::code_of(error)
}
