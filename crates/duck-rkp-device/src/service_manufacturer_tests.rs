use super::*;
use crate::artifacts;
use base64ct::{Base64, Encoding};
use duck_rkp::cbor::{as_array, as_map, as_text, decode, map_get_text, text};
use rcgen::{BasicConstraints, CustomExtension, IsCa, KeyUsagePurpose};

#[derive(Clone, Copy)]
enum Reply {
    Echo,
    Reversed,
    Missing,
    Mismatch,
    Malformed,
    RootOnly,
}

fn extension(manufacturer: &str) -> CustomExtension {
    CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30],
        encode(&Value::Map(vec![
            (int(1), int(1)),
            (int(3), text(manufacturer)),
            (int(4), text("TEE")),
        ]))
        .unwrap(),
    )
}

fn certified_chain(manufacturer: Option<&str>, reply: Reply) -> Vec<u8> {
    let mut root_params = named_params("manufacturer-test-root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    if matches!(reply, Reply::RootOnly) {
        root_params
            .custom_extensions
            .push(extension(manufacturer.unwrap()));
    }
    let root = rcgen::CertifiedIssuer::self_signed(root_params, RcgenKeyPair::generate().unwrap())
        .unwrap();
    let mut params = named_params("manufacturer-test-key");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    match reply {
        Reply::Echo | Reply::Reversed => {
            if let Some(manufacturer) = manufacturer {
                params.custom_extensions.push(extension(manufacturer));
            }
        }
        Reply::Mismatch => params.custom_extensions.push(extension("Other")),
        Reply::Malformed => params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30],
                vec![0xa1, 3, 1],
            )),
        _ => {}
    }
    let signer = TestSigner {
        key: p256::ecdsa::SigningKey::from(test_key()),
        subject: requested_point(&cose_public_of(&test_key())),
    };
    let leaf = params.signed_by(&signer, &root).unwrap();
    if matches!(reply, Reply::Reversed) {
        [root.der().as_ref(), leaf.der().as_ref()].concat()
    } else {
        [leaf.der().as_ref(), root.der().as_ref()].concat()
    }
}

struct MetadataServer {
    inner: FakeServer,
    manufacturer: Option<String>,
    replies: Vec<Reply>,
    exchanges: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl MetadataServer {
    fn new(manufacturer: Option<&str>, replies: Vec<Reply>) -> Self {
        let google = crate::service::Google::new(None, manufacturer.map(str::to_owned)).unwrap();
        Self {
            inner: FakeServer::new(),
            manufacturer: google.requested_manufacturer().map(str::to_owned),
            replies,
            exchanges: Mutex::new(vec![]),
        }
    }
}

impl Server for MetadataServer {
    fn requested_manufacturer(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }
    fn challenge<'a>(&'a self, fingerprint: &'a str) -> BoxFuture<'a, anyhow::Result<EekResponse>> {
        self.inner.challenge(fingerprint)
    }
    fn certificates<'a>(
        &'a self,
        csr: &'a [u8],
        challenge: &'a [u8],
    ) -> BoxFuture<'a, anyhow::Result<Vec<Vec<u8>>>> {
        Box::pin(async move {
            assert_eq!(challenge, CHALLENGE);
            assert_eq!(csr_keys_to_sign(csr), cose_public_of(&test_key()));
            let value = decode(csr).unwrap();
            let fields = as_array(&value, "CSR").unwrap();
            let metadata = if matches!(fields[0], Value::Integer(_)) {
                assert!(duck_rkp::verify::verify_csr(csr).unwrap().signature_valid);
                fields.get(4)
            } else {
                as_array(&fields[0], "DeviceInfo").unwrap().get(1)
            };
            let manufacturer = metadata.and_then(|info| {
                let info = as_map(info, "UnverifiedDeviceInfo").unwrap();
                map_get_text(info, "manufacturer")
                    .map(|value| as_text(value, "manufacturer").unwrap())
            });
            assert_eq!(manufacturer, self.requested_manufacturer());
            if manufacturer.is_some() {
                assert_eq!(
                    map_get_text(
                        as_map(metadata.unwrap(), "metadata").unwrap(),
                        "fingerprint"
                    ),
                    Some(&text(FINGERPRINT)),
                );
            }
            // The test server derives the certificate extension from the actual CSR.
            let mut exchanges = self.exchanges.lock().unwrap();
            let reply = self.replies[exchanges.len().min(self.replies.len() - 1)];
            let chain = certified_chain(manufacturer, reply);
            exchanges.push((csr.to_vec(), chain.clone()));
            Ok(vec![chain])
        })
    }
}

struct AllMethods(FakeTa);

impl Exchange for AllMethods {
    fn csr(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        if request[..4] == protocol::CSR_COMMAND.to_le_bytes() {
            return Exchange::csr(&self.0, request);
        }
        assert_eq!(request[..4], crate::v1::native::COMMAND.to_le_bytes());
        let response = crate::v1::tests::response();
        encode(&Value::Map(vec![
            (int(59), bytes(response.device_info)),
            (int(60), bytes(response.protected_data)),
        ]))
    }
    fn csr_v1(&self, _: &crate::v1::Request) -> anyhow::Result<crate::v1::Response> {
        Ok(crate::v1::tests::response())
    }
}

const PROTOCOLS: [super::super::Protocol; 4] = [
    super::super::Protocol::Auto,
    super::super::Protocol::V1,
    super::super::Protocol::V2,
    super::super::Protocol::V1Native,
];

fn leaf_from_xml(xml: &str) -> Vec<u8> {
    let body = xml
        .split_once("-----BEGIN CERTIFICATE-----")
        .unwrap()
        .1
        .split_once("-----END CERTIFICATE-----")
        .unwrap()
        .0;
    Base64::decode_vec(
        &body
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>(),
    )
    .unwrap()
}

#[tokio::test]
async fn manufacturer_reaches_the_csr_and_the_signed_certificate_in_every_export() {
    for protocol in PROTOCOLS {
        for (input, reply) in [(" Google ", Reply::Echo), ("A&B <\"'厂商", Reply::Reversed)] {
            let (dir, ctx) = working_dir("rkp-cert-manufacturer");
            let server = MetadataServer::new(Some(input), vec![reply]);
            let output = dir.path().join("custom.xml");
            let data = provision(
                &ctx,
                true,
                Options {
                    protocol,
                    output: Some(output.clone()),
                    ..Options::default()
                },
                &FixedKeys,
                &AllMethods(FakeTa::new()),
                &server,
                &FakeEnvironment,
            )
            .await
            .unwrap();
            assert!(data.device_id.starts_with("QTI-"));
            let records = server.exchanges.lock().unwrap();
            let (csr, chain) = &records[0];
            assert_eq!(fs::read(&data.artifacts.csr_path).unwrap(), *csr);
            assert_eq!(fs::read(&data.artifacts.cert_chain_path).unwrap(), *chain);
            let expected =
                artifacts::keybox_order(&artifacts::parse_der_cert_chain(chain).unwrap()).unwrap();
            let leaf = leaf_from_xml(&data.keybox_xml);
            assert_eq!(leaf, expected[0].der);
            crate::provisioning_info::require_manufacturer(&leaf, input.trim()).unwrap();
            // Verify the real issuer signature and CA constraints after XML export.
            duck_rkp::certificates::select_chain_for_p256(
                std::slice::from_ref(chain),
                &test_key().public_key().to_sec1_bytes(),
            )
            .unwrap();
            assert_eq!(fs::read_to_string(output).unwrap(), data.keybox_xml);
            let run_copy = PathBuf::from(&data.artifacts.run_dir).join("keybox.xml");
            assert_eq!(fs::read_to_string(run_copy).unwrap(), data.keybox_xml);
            let cleaned = duck_tricky_store::keybox::validate::clean(&data.keybox_xml).unwrap();
            assert_eq!(leaf_from_xml(&cleaned), leaf);
            duck_tricky_store::keybox::validate::validate(&cleaned).unwrap();
        }
    }
}

#[tokio::test]
async fn missing_mismatched_or_malformed_metadata_never_publishes_a_keybox() {
    for protocol in PROTOCOLS {
        for (reply, code) in [
            (Reply::Missing, "certificate_manufacturer_missing"),
            (Reply::RootOnly, "certificate_manufacturer_missing"),
            (Reply::Mismatch, "certificate_manufacturer_mismatch"),
            (Reply::Malformed, "invalid_provisioning_info"),
        ] {
            let (dir, ctx) = working_dir("rkp-cert-manufacturer-rejected");
            let server = MetadataServer::new(Some("Google"), vec![reply]);
            let output = dir.path().join("existing.xml");
            fs::write(&output, "existing keybox").unwrap();
            let error = provision(
                &ctx,
                true,
                Options {
                    protocol,
                    output: Some(output.clone()),
                    ..Options::default()
                },
                &FixedKeys,
                &AllMethods(FakeTa::new()),
                &server,
                &FakeEnvironment,
            )
            .await
            .unwrap_err();
            if protocol == super::super::Protocol::Auto {
                assert_eq!(crate::error::code_of(&error), "all_methods_failed");
                assert_eq!(error.to_string().matches(code).count(), 3);
            } else {
                assert_eq!(crate::error::code_of(&error), code);
            }
            assert_eq!(fs::read_dir(&ctx.paths.outputs_dir).unwrap().count(), 0);
            assert_eq!(fs::read_to_string(output).unwrap(), "existing keybox");
        }
    }
}

#[tokio::test]
async fn automatic_mode_retries_metadata_failures_and_keeps_the_successful_csr() {
    let (_dir, ctx) = working_dir("rkp-cert-manufacturer-retry");
    let server = MetadataServer::new(
        Some("Google"),
        vec![Reply::Missing, Reply::Mismatch, Reply::Echo],
    );
    let data = provision(
        &ctx,
        true,
        Options::default(),
        &FixedKeys,
        &AllMethods(FakeTa::new()),
        &server,
        &FakeEnvironment,
    )
    .await
    .unwrap();
    assert_eq!(data.attempts.len(), 3);
    assert_eq!(
        data.attempts[0].error.as_ref().unwrap().code,
        "certificate_manufacturer_missing"
    );
    assert_eq!(
        data.attempts[1].error.as_ref().unwrap().code,
        "certificate_manufacturer_mismatch"
    );
    let records = server.exchanges.lock().unwrap();
    assert_eq!(fs::read(&data.artifacts.csr_path).unwrap(), records[2].0);
    crate::provisioning_info::require_manufacturer(&leaf_from_xml(&data.keybox_xml), "Google")
        .unwrap();
}

#[tokio::test]
async fn omitted_or_blank_manufacturer_keeps_certificate_metadata_optional() {
    for manufacturer in [None, Some(""), Some(" \t\n")] {
        let (_dir, ctx) = working_dir("rkp-no-cert-manufacturer");
        let server = MetadataServer::new(manufacturer, vec![Reply::Missing]);
        provision(
            &ctx,
            true,
            Options::default(),
            &FixedKeys,
            &AllMethods(FakeTa::new()),
            &server,
            &FakeEnvironment,
        )
        .await
        .unwrap();
    }
}
