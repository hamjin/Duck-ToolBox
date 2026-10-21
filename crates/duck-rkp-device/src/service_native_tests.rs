use super::*;
use crate::{
    error::DeviceRkpError,
    issuance::{Backend, Protocol},
    v1,
};
use duck_rkp::cbor::{as_bytes, as_map, map_get};

enum Outcome {
    Valid,
    Rejected,
    Timeout,
    Malformed,
    InvalidEvidence,
}

struct NativeTa {
    calls: RefCell<usize>,
    outcome: Outcome,
}

impl Exchange for NativeTa {
    fn csr(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        *self.calls.borrow_mut() += 1;
        assert_eq!(&request[..4], v1::native::COMMAND.to_le_bytes());
        let payload = protocol::ta_payload(request).unwrap();
        let value = duck_rkp::cbor::decode(payload).unwrap();
        let fields = as_map(&value, "native request").unwrap();
        assert_eq!(map_get(fields, 4), Some(&bytes(CHALLENGE.to_vec())));
        let mac_key: [u8; 32] = as_bytes(map_get(fields, 56).unwrap(), "MAC key")
            .unwrap()
            .try_into()
            .unwrap();
        let expected =
            duck_rkp::cose::key_mac_tag(&mac_key, &[cose_public_of(&test_key())]).unwrap();
        assert_eq!(map_get(fields, 57), Some(&bytes(expected.to_vec())));
        match self.outcome {
            Outcome::Rejected => return Err(DeviceRkpError::Rejected(-40).into()),
            Outcome::Timeout => return Err(DeviceRkpError::Timeout.into()),
            Outcome::Malformed => return Ok(vec![0xa0, 0]),
            _ => {}
        }
        let mut evidence = v1::tests::response();
        if matches!(self.outcome, Outcome::InvalidEvidence) {
            evidence.device_info = vec![0xa0];
        }
        encode(&Value::Map(vec![
            (int(59), bytes(evidence.device_info)),
            (int(60), bytes(evidence.protected_data)),
        ]))
    }

    fn csr_v1(&self, _request: &v1::Request) -> anyhow::Result<v1::Response> {
        panic!("explicit native selection must not call AIDL")
    }
}

struct NativeEnvironment;
impl Environment for NativeEnvironment {
    fn capabilities(&self, ctx: &Context) -> DeviceStatus {
        let mut status = FakeEnvironment.capabilities(ctx);
        status.v1_available = false;
        status.aidl_apk = None;
        status
    }
}

#[tokio::test]
async fn explicit_native_backup_exports_a_keybox_without_aidl_or_a_signature_claim() {
    let (_dir, ctx) = working_dir("rkp-native-roundtrip");
    let server = seeded_server();
    let ta = NativeTa {
        calls: RefCell::new(0),
        outcome: Outcome::Valid,
    };
    let data = provision(
        &ctx,
        true,
        Options {
            protocol: Protocol::V1Native,
            ..Options::default()
        },
        &FixedKeys,
        &ta,
        &server,
        &NativeEnvironment,
    )
    .await
    .unwrap();
    assert_eq!(data.csr_protocol, Protocol::V1);
    assert_eq!(data.csr_backend, Backend::Native);
    assert!(data.local_verify.is_none());
    assert_eq!(*ta.calls.borrow(), 1);
    let submitted = server.submitted.lock().unwrap();
    assert_eq!(submitted.len(), 1);
    let value = duck_rkp::cbor::decode(&submitted[0]).unwrap();
    let fields = duck_rkp::cbor::as_array(&value, "CSR").unwrap();
    assert_eq!(
        duck_rkp::cbor::as_array(&fields[0], "DeviceInfo wrapper")
            .unwrap()
            .len(),
        2
    );
    let summary = duck_tricky_store::keybox::validate::validate(&data.keybox_xml).unwrap();
    assert_eq!(summary.chain_lengths, vec![2]);
    assert!(PathBuf::from(data.artifacts.private_key_path).is_file());
}

#[tokio::test]
async fn native_errors_never_submit_evidence_write_artifacts_or_call_another_adapter() {
    for (outcome, expected) in [
        (Outcome::Rejected, "ta_rejected"),
        (Outcome::Timeout, "ta_timeout"),
        (Outcome::Malformed, "invalid_ta_response"),
        (Outcome::InvalidEvidence, "invalid_device_csr"),
    ] {
        let (_dir, ctx) = working_dir("rkp-native-failure");
        let server = seeded_server();
        let ta = NativeTa {
            calls: RefCell::new(0),
            outcome,
        };
        let error = provision(
            &ctx,
            true,
            Options {
                protocol: Protocol::V1Native,
                ..Options::default()
            },
            &FixedKeys,
            &ta,
            &server,
            &NativeEnvironment,
        )
        .await
        .unwrap_err();
        assert_eq!(crate::error::code_of(&error), expected);
        assert_eq!(*ta.calls.borrow(), 2);
        assert!(server.submitted.lock().unwrap().is_empty());
        assert_eq!(fs::read_dir(&ctx.paths.outputs_dir).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn native_backup_requires_a_complete_chain_for_the_selected_server_curve() {
    for chains in [
        vec![],
        vec![duck_rkp::http::EekChain {
            curve: 1,
            encoded: vec![0x80],
        }],
    ] {
        let (_dir, ctx) = working_dir("rkp-native-eek");
        let mut server = seeded_server();
        server.eek_chains = chains;
        let ta = NativeTa {
            calls: RefCell::new(0),
            outcome: Outcome::Valid,
        };
        let error = provision(
            &ctx,
            true,
            Options {
                protocol: Protocol::V1Native,
                ..Options::default()
            },
            &FixedKeys,
            &ta,
            &server,
            &NativeEnvironment,
        )
        .await
        .unwrap_err();
        assert_eq!(crate::error::code_of(&error), "invalid_rkp_response");
        assert_eq!(*ta.calls.borrow(), 0);
        assert!(server.submitted.lock().unwrap().is_empty());
    }
}

struct CompatibilityTa {
    success: Option<usize>,
    calls: RefCell<Vec<(usize, Vec<u8>)>>,
    valid: NativeTa,
}

impl Exchange for CompatibilityTa {
    fn csr(&self, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("compatibility attempts must select a buffer mode explicitly")
    }

    fn csr_with_buffer(
        &self,
        request: &[u8],
        buffer: crate::native_compat::BufferMode,
    ) -> anyhow::Result<Vec<u8>> {
        let value = duck_rkp::cbor::decode(protocol::ta_payload(request)?).unwrap();
        let fields = as_map(&value, "request").unwrap();
        let canonical = fields[0].0 == int(4);
        let index = usize::from(canonical) * 2
            + usize::from(buffer == crate::native_compat::BufferMode::Shared);
        self.calls
            .borrow_mut()
            .push((index, encode(&value).unwrap()));
        if self.success == Some(index) {
            return self.valid.csr(request);
        }
        match index {
            0 => Ok(vec![0xa0]), // Transport succeeded, but the reply is malformed.
            1 => Err(DeviceRkpError::Transport("shared symbols missing".into()).into()),
            2 => Err(DeviceRkpError::Rejected(-20).into()),
            _ => Err(DeviceRkpError::Timeout.into()),
        }
    }
}

#[tokio::test]
async fn native_compatibility_tries_both_orders_and_buffers_before_one_server_submission() {
    for success in [Some(0), Some(1), Some(2), Some(3), None] {
        let (_dir, ctx) = working_dir("rkp-native-compatible");
        let server = seeded_server();
        let ta = CompatibilityTa {
            success,
            calls: RefCell::new(vec![]),
            valid: NativeTa {
                calls: RefCell::new(0),
                outcome: Outcome::Valid,
            },
        };
        let result = provision(
            &ctx,
            true,
            Options {
                protocol: Protocol::V1Native,
                ..Options::default()
            },
            &FixedKeys,
            &ta,
            &server,
            &NativeEnvironment,
        )
        .await;
        let calls = ta.calls.borrow();
        let count = success.map_or(4, |index| index + 1);
        assert_eq!(
            calls.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..count).collect::<Vec<_>>()
        );
        assert!(
            calls.iter().all(|(_, fields)| *fields == calls[0].1),
            "all variants must retain the same challenge, MAC key/tag and EEK"
        );
        if success.is_some() {
            let data = result.unwrap();
            assert_eq!(data.csr_backend, Backend::Native);
            assert_eq!(data.attempts.len(), 1);
            assert_eq!(server.submitted.lock().unwrap().len(), 1);
        } else {
            let error = result.unwrap_err();
            assert_eq!(crate::error::code_of(&error), "invalid_ta_response");
            for label in [
                "vendor-order/send_cmd",
                "vendor-order/init/sendCmd",
                "canonical-order/send_cmd",
                "canonical-order/init/sendCmd",
            ] {
                assert!(format!("{error:#}").contains(label));
            }
            assert!(server.submitted.lock().unwrap().is_empty());
            assert_eq!(fs::read_dir(&ctx.paths.outputs_dir).unwrap().count(), 0);
        }
    }
}

struct V2SharedTa {
    calls: RefCell<Vec<crate::native_compat::BufferMode>>,
    valid: FakeTa,
}

impl Exchange for V2SharedTa {
    fn csr(&self, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("explicit buffer expected")
    }
    fn csr_with_buffer(
        &self,
        request: &[u8],
        buffer: crate::native_compat::BufferMode,
    ) -> anyhow::Result<Vec<u8>> {
        self.calls.borrow_mut().push(buffer);
        match buffer {
            crate::native_compat::BufferMode::Raw => {
                Err(DeviceRkpError::UnsupportedProtocol("raw command rejected".into()).into())
            }
            crate::native_compat::BufferMode::Shared => Exchange::csr(&self.valid, request),
        }
    }
}

#[tokio::test]
async fn v2_can_fall_back_to_shared_buffers_and_still_requires_signature_verification() {
    let (_dir, ctx) = working_dir("rkp-v2-shared");
    let server = seeded_server();
    let ta = V2SharedTa {
        calls: RefCell::new(vec![]),
        valid: FakeTa::new(),
    };
    let data = provision(
        &ctx,
        true,
        Options {
            protocol: Protocol::V2,
            ..Options::default()
        },
        &FixedKeys,
        &ta,
        &server,
        &FakeEnvironment,
    )
    .await
    .unwrap();
    assert_eq!(
        *ta.calls.borrow(),
        [
            crate::native_compat::BufferMode::Raw,
            crate::native_compat::BufferMode::Shared
        ]
    );
    assert_eq!(data.csr_protocol, Protocol::V2);
    assert!(data.local_verify.unwrap().signature_valid);
    assert_eq!(server.submitted.lock().unwrap().len(), 1);
}
