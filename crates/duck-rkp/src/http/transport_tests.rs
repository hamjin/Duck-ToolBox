use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ciborium::value::Value;

use super::{
    fetch_challenge, fetch_eek, fetch_eek_with_manufacturer, rkp_client, submit_csr,
    submit_csr_with_manufacturer, validate_endpoint,
};
use crate::cbor::{bytes, decode, encode, int, text};

struct Request {
    line: String,
    body: Vec<u8>,
}

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(status: u16, body: Vec<u8>) -> Self {
        let length = body.len();
        Self::start_with_length(status, body, length)
    }

    fn start_with_length(status: u16, body: Vec<u8>, length: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (recorded, stopping) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                let path = read_request(&mut socket);
                recorded.lock().unwrap().push(path);
                write!(
                    socket,
                    "HTTP/1.1 {status} Test\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                if let Err(error) = socket.write_all(&body) {
                    assert!(matches!(
                        error.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                    ));
                }
            }
        });
        Self {
            origin,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.line.clone())
            .collect()
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.body.clone())
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn read_request(socket: &mut TcpStream) -> Request {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let (end, header) = loop {
        let mut buffer = [0; 4096];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
        if let Some(end) = data.windows(4).position(|part| part == b"\r\n\r\n") {
            break (end + 4, String::from_utf8(data[..end].to_vec()).unwrap());
        }
    };
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while data.len() < end + length {
        let mut buffer = [0; 4096];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
    }
    Request {
        line: header.lines().next().unwrap().to_string(),
        body: data[end..end + length].to_vec(),
    }
}

fn eek_response() -> Vec<u8> {
    let public_key = encode(&Value::Map(vec![
        (int(1), int(1)),
        (int(3), int(-25)),
        (int(-1), int(4)),
        (int(-2), bytes(vec![0x33; 32])),
    ]))
    .unwrap();
    encode(&Value::Array(vec![
        Value::Array(vec![Value::Array(vec![
            int(2),
            Value::Array(vec![Value::Array(vec![
                Value::Null,
                Value::Null,
                bytes(public_key),
            ])]),
        ])]),
        bytes(vec![7; 32]),
    ]))
    .unwrap()
}

const ENDPOINT_PATHS: [(&str, &str); 5] = [
    ("/v1/", "/v1"),
    ("", "/v1"),
    ("/", "/v1"),
    ("/v1", "/v1"),
    ("/custom/version/", "/custom/version"),
];

#[tokio::test]
async fn optional_manufacturer_is_encoded_in_both_requests_without_changing_payloads() {
    for (manufacturer, query) in [
        (None, ""),
        (Some(""), ""),
        (Some(" \t\n"), ""),
        (Some(" Google "), "manufacturer=Google"),
        (
            Some("A&B /+=?#厂商"),
            "manufacturer=A%26B+%2F%2B%3D%3F%23%E5%8E%82%E5%95%86",
        ),
    ] {
        let client = rkp_client().unwrap();
        let server = Server::start(200, eek_response());
        let eek = fetch_eek_with_manufacturer(&client, "synthetic", &server.origin, manufacturer)
            .await
            .unwrap();
        assert_eq!(eek.challenge, [7; 32]);
        let suffix = if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        };
        assert_eq!(
            server.requests(),
            [format!("POST /v1:fetchEekChain{suffix} HTTP/1.1")]
        );
        assert_eq!(
            decode(&server.bodies()[0]).unwrap(),
            Value::Map(vec![
                (text("id"), int(42)),
                (text("fingerprint"), text("synthetic")),
            ])
        );

        let body = encode(&Value::Array(vec![
            bytes(vec![1]),
            Value::Array(vec![bytes(vec![2])]),
        ]))
        .unwrap();
        let server = Server::start(200, body);
        let chains = submit_csr_with_manufacturer(
            &client,
            b"synthetic CSR",
            &[1, 2, 3],
            &server.origin,
            manufacturer,
        )
        .await
        .unwrap();
        assert_eq!(chains, [vec![1, 2]]);
        let prefix = if query.is_empty() {
            String::new()
        } else {
            format!("{query}&")
        };
        assert_eq!(
            server.requests(),
            [format!(
                "POST /v1:signCertificates?{prefix}challenge=AQID HTTP/1.1"
            )]
        );
        assert_eq!(server.bodies(), [b"synthetic CSR".to_vec()]);
    }
}

#[tokio::test]
async fn challenge_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let server = Server::start(200, eek_response());
        let endpoint = format!("{}{input}", server.origin);
        validate_endpoint(&endpoint).unwrap();
        let challenge = fetch_challenge(&rkp_client().unwrap(), "synthetic", &endpoint)
            .await
            .unwrap();
        assert_eq!(challenge, [7; 32]);
        assert_eq!(
            server.requests(),
            [format!("POST {expected}:fetchEekChain HTTP/1.1")]
        );
    }
}

#[tokio::test]
async fn eek_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let server = Server::start(200, eek_response());
        let response = fetch_eek(
            &rkp_client().unwrap(),
            "synthetic",
            &format!("{}{input}", server.origin),
        )
        .await
        .unwrap();
        assert_eq!(response.challenge, [7; 32]);
        assert_eq!(response.eek_public, [0x33; 32]);
        assert_eq!(
            server.requests(),
            [format!("POST {expected}:fetchEekChain HTTP/1.1")]
        );
    }
}

#[tokio::test]
async fn submission_requests_normalize_endpoint_paths() {
    for (input, expected) in ENDPOINT_PATHS {
        let body = encode(&Value::Array(vec![
            bytes(vec![1]),
            Value::Array(vec![bytes(vec![2])]),
        ]))
        .unwrap();
        let server = Server::start(200, body);
        let chains = submit_csr(
            &rkp_client().unwrap(),
            b"synthetic CSR",
            &[1, 2, 3],
            &format!("{}{input}", server.origin),
        )
        .await
        .unwrap();
        assert_eq!(chains, [vec![1, 2]]);
        assert_eq!(
            server.requests(),
            [format!(
                "POST {expected}:signCertificates?challenge=AQID HTTP/1.1"
            )]
        );
    }
}

#[tokio::test]
async fn every_rpc_rejects_unsafe_endpoints_before_sending() {
    for invalid in [
        "http://example.com/v1",
        "https://user@example.com/v1",
        "https://example.com/v1?secret=synthetic",
        "https://example.com/v1#synthetic",
    ] {
        assert_eq!(
            crate::error::code_of(&validate_endpoint(invalid).unwrap_err()),
            "invalid_endpoint"
        );
    }
    for action in 0..3 {
        for suffix in ["?secret=synthetic", "#synthetic"] {
            let server = Server::start(200, eek_response());
            let endpoint = format!("{}/v1{suffix}", server.origin);
            let client = rkp_client().unwrap();
            let error = match action {
                0 => fetch_challenge(&client, "synthetic", &endpoint)
                    .await
                    .map(|_| ()),
                1 => fetch_eek(&client, "synthetic", &endpoint).await.map(|_| ()),
                _ => submit_csr(&client, b"synthetic CSR", &[1], &endpoint)
                    .await
                    .map(|_| ()),
            }
            .unwrap_err();
            assert_eq!(crate::error::code_of(&error), "invalid_endpoint");
            assert!(server.requests().is_empty());
        }
    }
}

async fn submission_error(body: Vec<u8>, expected_reason: &str) {
    let server = Server::start(200, body);
    assert_submission_error(&server, expected_reason).await;
}

async fn assert_submission_error(server: &Server, expected_reason: &str) -> anyhow::Error {
    let error = submit_csr(
        &rkp_client().unwrap(),
        b"synthetic CSR",
        &[1, 2, 3],
        &format!("{}/v1", server.origin),
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::code_of(&error), "submission_unknown");
    assert!(error.to_string().contains("do not retry automatically"));
    let diagnostics = format!("{error:#} {error:?}");
    assert!(diagnostics.contains(expected_reason), "{diagnostics}");
    assert!(!diagnostics.contains("synthetic-response-secret"));
    assert_eq!(
        server.requests(),
        ["POST /v1:signCertificates?challenge=AQID HTTP/1.1"]
    );
    error
}

#[tokio::test]
async fn truncated_transport_body_after_successful_submission_has_unknown_outcome() {
    let body = b"synthetic-response-secret".to_vec();
    let length = body.len() + 1;
    let server = Server::start_with_length(200, body, length);
    let error = assert_submission_error(&server, "certificate submission result is unknown").await;
    assert!(!error.chain().any(|cause| matches!(
        cause.downcast_ref::<crate::error::RkpError>(),
        Some(crate::error::RkpError::InvalidRkpResponse(_))
    )));
}

#[tokio::test]
async fn oversized_transport_body_after_successful_submission_has_unknown_outcome() {
    let marker = b"synthetic-response-secret";
    let mut body = vec![b'x'; 1024 * 1024 + 1];
    body[..marker.len()].copy_from_slice(marker);
    let server = Server::start(200, body);
    assert_submission_error(&server, "response exceeds size limit").await;
}

#[tokio::test]
async fn truncated_cbor_after_successful_submission_has_unknown_outcome() {
    submission_error(vec![0x81], "truncated CBOR").await;
}

#[tokio::test]
async fn malformed_shapes_after_successful_submission_have_unknown_outcome() {
    for (value, expected_reason) in [
        (
            Value::Text("synthetic-response-secret".into()),
            "signCertificates response is not a CBOR array",
        ),
        (Value::Array(vec![]), "signCertificates response is empty"),
        (
            Value::Array(vec![bytes(vec![1])]),
            "missing certificate chain data",
        ),
        (
            Value::Array(vec![bytes(vec![1]), Value::Array(vec![])]),
            "no certificate chains",
        ),
    ] {
        submission_error(encode(&value).unwrap(), expected_reason).await;
    }
}

#[tokio::test]
async fn submission_parse_diagnostics_do_not_reflect_duplicate_cbor_text_keys() {
    let body = encode(&Value::Map(vec![
        (Value::Text("synthetic-response-secret".into()), int(1)),
        (Value::Text("synthetic-response-secret".into()), int(2)),
    ]))
    .unwrap();
    submission_error(body, "malformed CBOR").await;
}

#[tokio::test]
async fn explicit_http_rejection_retains_server_codes_without_body_or_retry() {
    for (status, expected) in [
        (403, "rkp_client_error"),
        (444, "device_not_registered"),
        (503, "rkp_server_error"),
    ] {
        let server = Server::start(status, b"synthetic-response-secret".to_vec());
        let error = submit_csr(
            &rkp_client().unwrap(),
            b"synthetic CSR",
            &[1],
            &format!("{}/v1", server.origin),
        )
        .await
        .unwrap_err();
        assert_eq!(crate::error::code_of(&error), expected);
        assert!(!format!("{error:#} {error:?}").contains("synthetic-response-secret"));
        assert_eq!(server.requests().len(), 1);
    }
}
