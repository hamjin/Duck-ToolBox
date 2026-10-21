use ciborium::value::Value;
use duck_rkp::{
    cbor::{bytes, decode, encode, int},
    cose::{DeviceKeys, RPC_CURVE_25519, build_csr},
    profile::{DeviceInfo, DiceCurve},
};
use p256::elliptic_curve::sec1::ToSec1Point as _;

use super::{
    BUFFER_SIZE, CSR_COMMAND, MAX_REQUEST_SIZE, build_request, response_payload, ta_payload,
    unwrap_csr, validate_csr, validate_request,
};
use crate::error::DeviceRkpError;

fn p256_public_key() -> (p256::SecretKey, Value) {
    p256_key([0x11; 32])
}

fn p256_key(seed: [u8; 32]) -> (p256::SecretKey, Value) {
    let key = p256::SecretKey::from_slice(&seed).unwrap();
    let point = key.public_key().to_sec1_point(false);
    let cose = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), bytes(point.x().unwrap().to_vec())),
        (int(-3), bytes(point.y().unwrap().to_vec())),
    ]);
    (key, cose)
}

fn envelope(status: i32, payload: &[u8]) -> Vec<u8> {
    let mut response = status.to_le_bytes().to_vec();
    response.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    response.extend_from_slice(payload);
    response
}

#[test]
fn request_is_command_prefixed_and_canonically_encoded() {
    let (_, key) = p256_public_key();
    let request = build_request(&[0xAA; 32], &key).unwrap();

    assert_eq!(request.get(..4), Some(CSR_COMMAND.to_le_bytes().as_slice()));
    assert_eq!(ta_payload(&request).unwrap(), &request[4..]);
}

#[test]
fn request_requires_a_canonical_keys_to_sign_envelope() {
    let (_, key) = p256_public_key();
    let request = build_request(&[0xAA; 32], &key).unwrap();
    let payload = &request[4..];
    let decoded = duck_rkp::cbor::decode(payload).unwrap();
    let Value::Map(entries) = decoded else {
        panic!("request payload must be a CBOR map");
    };

    assert_eq!(entries.len(), 2);
    let challenge = duck_rkp::cbor::map_get(&entries, 4).unwrap();
    assert_eq!(challenge, &bytes(vec![0xAA; 32]));
    let keys = duck_rkp::cbor::map_get(&entries, 57).unwrap();
    let inner = duck_rkp::cbor::decode(duck_rkp::cbor::as_bytes(keys, "keys").unwrap()).unwrap();
    assert_eq!(inner, Value::Array(vec![key]));
}

#[test]
fn ta_payload_rejects_another_command() {
    let mut request = 0x0200_u32.to_le_bytes().to_vec();
    request.extend_from_slice(&encode(&Value::Map(vec![])).unwrap());

    let error = ta_payload(&request).unwrap_err();
    assert!(error.to_string().contains("CSR_V2"));
}

#[test]
fn ta_payload_rejects_a_truncated_header() {
    assert!(ta_payload(&[0x22, 0x31]).is_err());
}

#[test]
fn native_v2_invalid_tag_has_a_protocol_diagnostic_without_hiding_other_rejections() {
    for (command, status, code) in [
        (CSR_COMMAND, -40_i32, "unsupported_protocol"),
        (crate::v1::native::COMMAND, -40, "ta_rejected"),
        (CSR_COMMAND, -20, "ta_rejected"),
    ] {
        let response = [status.to_le_bytes(), 0u32.to_le_bytes()].concat();
        let error = super::command_response_payload(command, &response).unwrap_err();
        assert_eq!(crate::error::code_of(&error), code);
        assert!(error.to_string().contains(&status.to_string()));
    }
    for command in [CSR_COMMAND, crate::v1::native::COMMAND] {
        let response = [
            0u32.to_le_bytes().as_slice(),
            1u32.to_le_bytes().as_slice(),
            &[0xa0],
        ]
        .concat();
        assert_eq!(
            super::command_response_payload(command, &response).unwrap(),
            [0xa0]
        );
    }
}

#[test]
fn validate_request_rejects_a_wrong_map_shape() {
    let (_, key) = p256_public_key();

    let extra = encode(&Value::Map(vec![
        (int(4), bytes(vec![0xAA; 32])),
        (
            int(57),
            bytes(encode(&Value::Array(vec![key.clone()])).unwrap()),
        ),
        (int(99), int(1)),
    ]))
    .unwrap();
    assert!(validate_request(&extra).is_err());

    let naked_map = encode(&Value::Map(vec![
        (int(4), bytes(vec![0xAA; 32])),
        (int(57), key),
    ]))
    .unwrap();
    assert!(validate_request(&naked_map).is_err());
}

#[test]
fn validate_request_rejects_bad_challenges() {
    let (_, key) = p256_public_key();
    let keys = bytes(encode(&Value::Array(vec![key.clone()])).unwrap());

    for challenge in [Vec::new(), vec![0xAA; 65]] {
        let payload = encode(&Value::Map(vec![
            (int(4), bytes(challenge)),
            (int(57), keys.clone()),
        ]))
        .unwrap();
        assert!(
            validate_request(&payload).is_err(),
            "challenge must be 1..64 bytes"
        );
    }
}

#[test]
fn validate_request_rejects_non_p256_keys() {
    let (_, mut key) = p256_public_key();
    let Value::Map(entries) = &mut key else {
        panic!("key must be a map");
    };
    entries[1] = (int(3), int(-35)); // ES384 instead of ES256

    let payload = encode(&Value::Map(vec![
        (int(4), bytes(vec![0xAA; 32])),
        (int(57), bytes(encode(&Value::Array(vec![key])).unwrap())),
    ]))
    .unwrap();
    assert!(validate_request(&payload).is_err());
}

#[test]
fn validate_request_rejects_a_point_that_is_not_on_the_curve() {
    let (_, mut key) = p256_public_key();
    let Value::Map(entries) = &mut key else {
        panic!("key must be a map");
    };
    entries[3] = (int(-2), bytes(vec![0x11; 32]));
    entries[4] = (int(-3), bytes(vec![0x22; 32]));

    let payload = encode(&Value::Map(vec![
        (int(4), bytes(vec![0xAA; 32])),
        (int(57), bytes(encode(&Value::Array(vec![key])).unwrap())),
    ]))
    .unwrap();
    assert!(validate_request(&payload).is_err());
}

#[test]
fn validate_request_rejects_oversized_payloads() {
    let oversized = vec![0_u8; MAX_REQUEST_SIZE];
    assert!(validate_request(&oversized).is_err());
}

#[test]
fn response_payload_enforces_the_status_and_length_fields() {
    assert!(response_payload(&[0x00, 0x00]).is_err());
    assert!(response_payload(&envelope(0, &[])).is_err());

    let error = response_payload(&envelope(-0x2711, &[0x01])).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<DeviceRkpError>()
            .map(ToString::to_string),
        Some(DeviceRkpError::Rejected(-0x2711).to_string())
    );

    let payload = vec![0xAB; 64];
    assert_eq!(response_payload(&envelope(0, &payload)).unwrap(), payload);

    let mut lying = envelope(0, &payload);
    lying[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(response_payload(&lying).is_err());

    let too_long = vec![0_u8; BUFFER_SIZE - 7];
    assert!(response_payload(&envelope(0, &too_long)).is_err());
}

#[test]
fn unwrap_csr_extracts_the_authenticated_request() {
    let csr = vec![0x99; 48];
    let payload = encode(&Value::Map(vec![(int(61), bytes(csr.clone()))])).unwrap();
    assert_eq!(unwrap_csr(&payload).unwrap(), csr);

    let empty = encode(&Value::Map(vec![(int(61), bytes(Vec::new()))])).unwrap();
    assert!(unwrap_csr(&empty).is_err());

    let missing = encode(&Value::Map(vec![(int(62), bytes(csr))])).unwrap();
    assert!(unwrap_csr(&missing).is_err());

    let two_fields = encode(&Value::Map(vec![
        (int(61), bytes(vec![0x01])),
        (int(62), bytes(vec![0x02])),
    ]))
    .unwrap();
    assert!(unwrap_csr(&two_fields).is_err());
}

#[test]
fn bare_and_wrapped_authenticated_requests_are_both_verified() {
    let (_, key) = p256_public_key();
    let csr = valid_csr_for(&key);
    let wrapped = encode(&Value::Map(vec![(int(61), bytes(csr.clone()))])).unwrap();
    for payload in [&csr, &wrapped] {
        let unwrapped = unwrap_csr(payload).unwrap();
        assert_eq!(unwrapped, csr);
        assert!(
            validate_csr(&unwrapped, &[0x44; 32], &key)
                .unwrap()
                .signature_valid
        );
    }
}

#[test]
fn malformed_response_envelopes_have_the_response_error_code() {
    for payload in [
        vec![0xff],
        encode(&Value::Map(vec![])).unwrap(),
        vec![0x80, 0x00],
    ] {
        let error = unwrap_csr(&payload).unwrap_err();
        assert_eq!(crate::error::code_of(&error), "invalid_ta_response");
    }
}

/// A structurally valid, correctly signed CSR for `key`, so the negative cases below reach
/// the inner shape checks instead of failing verification first.
fn valid_csr_for(key: &Value) -> Vec<u8> {
    let device = DeviceInfo {
        brand: "google".into(),
        model: "Pixel".into(),
        device: "pixel".into(),
        product: "pixel".into(),
        manufacturer: "Google".into(),
        ..DeviceInfo::default()
    };
    build_csr(
        &DeviceKeys::from_seed_with_curve([0x11; 32], DiceCurve::Ed25519),
        &[0x44; 32],
        std::slice::from_ref(key),
        &[0x55; 32],
        &[0x66; 8],
        &device,
        RPC_CURVE_25519,
    )
    .unwrap()
    .csr_bytes
}

/// Re-encodes the inner CSR payload after `edit`, leaving the signature stale: the shape
/// checks still run, and the tampered CSR cannot pass as valid either.
fn with_empty_keys_to_sign(csr: &[u8]) -> Vec<u8> {
    let mut value = decode(csr).unwrap();
    let Value::Array(request) = &mut value else {
        panic!("CSR must be an array");
    };
    let Value::Array(signed) = &mut request[3] else {
        panic!("SignedData must be an array");
    };
    let Value::Bytes(payload) = &mut signed[2] else {
        panic!("payload must be bytes");
    };
    let mut outer = decode(payload).unwrap();
    let Value::Array(outer_items) = &mut outer else {
        panic!("signed payload must be an array");
    };
    let Value::Bytes(inner) = &mut outer_items[1] else {
        panic!("CSR payload must be bytes");
    };
    let mut contents = decode(inner).unwrap();
    let Value::Array(items) = &mut contents else {
        panic!("CSR payload must be an array");
    };
    items[3] = Value::Array(Vec::new());
    *inner = encode(&Value::Array(items.clone())).unwrap();
    *payload = encode(&outer).unwrap();
    encode(&value).unwrap()
}

#[test]
fn an_empty_keys_to_sign_is_an_error_not_a_panic() {
    let (_, key) = p256_key([0x11; 32]);
    // A CSR whose inner keysToSign was emptied. `verify_csr` counts keys, so this never
    // reaches `ensure_csr_binds` through `validate_csr`; calling it directly is what keeps
    // the check total if that ever changes.
    let csr = with_empty_keys_to_sign(&valid_csr_for(&key));

    let error = super::ensure_csr_binds(&csr, &[0x44; 32], &key).unwrap_err();
    assert!(
        error.to_string().contains("keysToSign"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn validate_csr_rejects_a_challenge_that_is_not_the_servers() {
    let (_, key) = p256_public_key();
    let csr = valid_csr_for(&key);

    let error = validate_csr(&csr, &[0x99; 32], &key).unwrap_err();
    assert!(error.to_string().contains("challenge"));
}

#[test]
fn validate_csr_rejects_a_different_key() {
    let (_, key) = p256_key([0x11; 32]);
    let (_, other) = p256_key([0x22; 32]);
    let csr = valid_csr_for(&key);

    let error = validate_csr(&csr, &[0x44; 32], &other).unwrap_err();
    assert!(error.to_string().contains("public key"));
}
