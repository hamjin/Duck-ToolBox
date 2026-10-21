use super::*;
use duck_rkp::{
    cbor::{as_bytes, bytes, int, map_get_text},
    cose::{DeviceKeys, build_experimental_csr_v3, generate_ec_keypair},
    profile::DeviceInfo,
    verify::verify_csr,
};

fn authenticated_request() -> Vec<u8> {
    build_experimental_csr_v3(
        &DeviceKeys::from_seed([7; 32]),
        &[9; 32],
        &[generate_ec_keypair().unwrap().cose_public],
        &DeviceInfo::default(),
    )
    .unwrap()
}

#[test]
fn v2_metadata_preserves_all_authenticated_bytes_and_local_verification() {
    let csr = authenticated_request();
    let metadata = encode("test/fingerprint", "A&B 厂商").unwrap();
    for (header, trailer) in [
        (vec![0x84], vec![]),
        (vec![0x98, 4], vec![]),
        (vec![0x99, 0, 4], vec![]),
        (vec![0x9a, 0, 0, 0, 4], vec![]),
        (vec![0x9b, 0, 0, 0, 0, 0, 0, 0, 4], vec![]),
        (vec![0x9f], vec![0xff]),
    ] {
        let original = [header.as_slice(), &csr[1..], trailer.as_slice()].concat();
        let submitted = append_v2(&original, &metadata).unwrap();
        assert_eq!(&submitted[1..csr.len()], &csr[1..]);
        let value = decode(&submitted).unwrap();
        let fields = as_array(&value, "network CSR").unwrap();
        assert_eq!(fields[4], decode(&metadata).unwrap());
        assert!(verify_csr(&submitted).unwrap().signature_valid);
        // The manufacturer's request hint does not overwrite signed DeviceInfo.
        let signed = as_array(&fields[3], "SignedData").unwrap();
        let payload = decode(as_bytes(&signed[2], "signed payload").unwrap()).unwrap();
        let payload = as_array(&payload, "signed payload").unwrap();
        let body = decode(as_bytes(&payload[1], "CSR payload").unwrap()).unwrap();
        let body = as_array(&body, "CSR payload").unwrap();
        assert_eq!(
            map_get_text(as_map(&body[2], "DeviceInfo").unwrap(), "manufacturer"),
            Some(&text(DeviceInfo::default().manufacturer))
        );
    }
}

#[test]
fn v1_metadata_preserves_verified_device_info_and_encrypted_evidence() {
    let response = crate::v1::tests::response();
    let device_len = response.device_info.len();
    let original =
        crate::v1::assemble(response, &[9; 32], &crate::v1::tests::public_key()).unwrap();
    let metadata = encode("test/fingerprint", "Google").unwrap();
    let submitted = crate::v1::assemble_with_metadata(
        crate::v1::tests::response(),
        &[9; 32],
        &crate::v1::tests::public_key(),
        Some(&metadata),
    )
    .unwrap();
    assert_eq!(&submitted[..2 + device_len], &original[..2 + device_len]);
    assert_eq!(
        &submitted[2 + device_len + metadata.len()..],
        &original[3 + device_len..]
    );
    let value = decode(&submitted).unwrap();
    let fields = as_array(&value, "V1 CSR").unwrap();
    assert_eq!(
        as_array(&fields[0], "DeviceInfo wrapper").unwrap()[1],
        decode(&metadata).unwrap()
    );
}

#[test]
fn metadata_cannot_exceed_limits_or_replace_authenticated_request_items() {
    let csr = authenticated_request();
    let oversized = encode("fingerprint", &"x".repeat(BUFFER_SIZE)).unwrap();
    assert!(append_v2(&csr, &oversized).is_err());
    assert!(
        crate::v1::assemble_with_metadata(
            crate::v1::tests::response(),
            &[9; 32],
            &crate::v1::tests::public_key(),
            Some(&oversized),
        )
        .is_err()
    );
    let metadata = encode("fingerprint", "Google").unwrap();
    let decorated = append_v2(&csr, &metadata).unwrap();
    assert!(append_v2(&decorated, &metadata).is_err());
    assert!(append_v2(&csr, &cbor_encode(&bytes(vec![])).unwrap()).is_err());
    let mut value = decode(&decorated).unwrap();
    let Value::Array(fields) = &mut value else {
        unreachable!()
    };
    fields[4] = int(1);
    assert!(verify_csr(&cbor_encode(&value).unwrap()).is_err());
}
