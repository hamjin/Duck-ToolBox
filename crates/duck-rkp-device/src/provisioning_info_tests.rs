use super::*;
use rcgen::{CertificateParams, CustomExtension, KeyPair};

const OID_PARTS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30];
// Same CBOR fields read by KeyAttestation: {1: 1, 3: "Google", 4: "TEE"}.
const INFO: &[u8] = b"\xa3\x01\x01\x03\x66Google\x04\x63TEE";

fn certificate(values: &[&[u8]]) -> Vec<u8> {
    let mut params = CertificateParams::default();
    for value in values {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(OID_PARTS, value.to_vec()));
    }
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

#[test]
fn reads_the_keyattestation_extension_without_rewriting_the_certificate() {
    let der = certificate(&[INFO]);
    let original = der.clone();
    require_manufacturer(&der, "Google").unwrap();
    assert_eq!(der, original);
    let error = require_manufacturer(&der, "Xiaomi").unwrap_err();
    assert_eq!(
        crate::error::code_of(&error),
        "certificate_manufacturer_mismatch"
    );
}

#[test]
fn missing_extension_or_manufacturer_is_not_a_success() {
    for values in [
        vec![],
        vec![b"\xa1\x01\x01".as_slice()],
        vec![b"\xa1\x03\x60".as_slice()],
    ] {
        let error = require_manufacturer(&certificate(&values), "Google").unwrap_err();
        assert_eq!(
            crate::error::code_of(&error),
            "certificate_manufacturer_missing"
        );
    }
}

#[test]
fn malformed_ambiguous_or_wrongly_typed_metadata_is_rejected() {
    for values in [
        vec![b"\x80".as_slice()],                             // not a map
        vec![b"\xa1\x03\x01".as_slice()],                     // manufacturer is not text
        vec![b"\xa1\x03\x66Go".as_slice()],                   // truncated
        vec![b"\xa1\x03\x66Google\x00".as_slice()],           // trailing data
        vec![b"\xa2\x03\x66Google\x03\x66Google".as_slice()], // duplicate key
        vec![b"\xa1\x63bad\x66secret".as_slice()],            // not a numeric label
        vec![INFO, INFO],                                     // duplicate extension
    ] {
        let error = require_manufacturer(&certificate(&values), "Google").unwrap_err();
        assert_eq!(crate::error::code_of(&error), "invalid_provisioning_info");
        assert!(!format!("{error:#}").contains("secret"));
    }
}
