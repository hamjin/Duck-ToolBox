//! Owns every file a device-backed run produces, and the checks that bind the issued
//! certificate chain to the key pair this feature generated.
//!
//! The artifacts deliberately match the offline workbench: the same Tricky Store
//! `keybox.xml`, the same CSR, and the device's certificate chain in DER.

use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use duck_core::{AppPaths, fs::write_bytes_atomic};
use p256::SecretKey as P256SecretKey;
use serde::Serialize;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

use crate::{
    error::DeviceRkpError, protocol::MAX_CERT_CHAIN_LEN, provisioning_info::ManufacturerReport,
};

/// Upper bound on the certificates in one issued chain. The server returns four (leaf,
/// Droid CA3, Droid CA2, Key Attestation CA1); the bound only stops a malformed response
/// from being walked indefinitely.
pub(crate) const MAX_CHAIN_CERTIFICATES: usize = 8;

const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_CURVE_OID: &str = "1.2.840.10045.3.1.7";

/// One certificate of the issued chain, in the order the server returned it.
#[derive(Debug, Clone)]
pub(crate) struct ParsedCertificate {
    pub der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    /// The subject as X.509 text, e.g. `CN=Droid CA3`, for the JSON summary.
    pub subject_label: String,
    /// The issuer as X.509 text, in the same form.
    pub issuer_label: String,
    /// SEC1 uncompressed point of a P-256 subject public key, when the subject key is an
    /// EC P-256 key. `None` for any other algorithm or curve.
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChainSummary {
    pub certificates: usize,
    pub subjects: Vec<String>,
}

impl ChainSummary {
    pub(crate) fn of(chain: &[ParsedCertificate]) -> Self {
        Self {
            certificates: chain.len(),
            subjects: chain
                .iter()
                .map(|cert| cert.subject_label.clone())
                .collect(),
        }
    }
}

/// Where a finished run wrote its files, so the WebUI can offer them.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ArtifactPaths {
    pub run_dir: String,
    pub keybox_path: String,
    pub csr_path: String,
    pub cert_chain_path: String,
    pub private_key_path: String,
}

/// Everything a completed run produced.
#[derive(Debug)]
pub(crate) struct Artifacts {
    pub keybox_xml: String,
    pub device_id: String,
    pub chain: Vec<ParsedCertificate>,
    pub paths: ArtifactPaths,
    pub manufacturer: ManufacturerReport,
}

#[cfg(test)]
pub(crate) struct Inputs<'a> {
    pub secret_key: &'a P256SecretKey,
    pub csr: &'a [u8],
    pub cert_chain_der: &'a [u8],
    pub manufacturer: &'a str,
}

/// Validates the issued chain against the generated key, then writes every artifact.
///
/// The chain is put in keybox order once, so the file and the JSON summary describe the
/// same chain.
#[cfg(test)]
pub(crate) fn write(paths: &AppPaths, inputs: Inputs<'_>) -> Result<Artifacts> {
    prepare(
        inputs.secret_key,
        inputs.cert_chain_der.to_vec(),
        inputs.manufacturer,
        None,
    )?
    .write(paths, inputs.csr)
}

/// All certificate checks and encoding finish before any output directory is created.
pub(crate) struct Prepared {
    chain: Vec<ParsedCertificate>,
    device_id: String,
    keybox_xml: String,
    private_key_pem: String,
    cert_chain_der: Vec<u8>,
    manufacturer: ManufacturerReport,
}

pub(crate) fn prepare(
    secret_key: &P256SecretKey,
    cert_chain_der: Vec<u8>,
    manufacturer: &str,
    requested_manufacturer: Option<&str>,
) -> Result<Prepared> {
    let chain = parse_der_cert_chain(&cert_chain_der)
        .map_err(|error| DeviceRkpError::InvalidCsr(format!("{error:#}")))?;
    ensure_chain_matches_key(&chain, secret_key)?;
    ensure_chain_is_linked(&chain)?;
    let chain = keybox_order(&chain)?;
    let manufacturer_report =
        crate::provisioning_info::check_manufacturer(&chain[0].der, requested_manufacturer)?;

    let device_id = device_id(manufacturer)?;
    let keybox_xml =
        duck_rkp::keybox_xml::build_keybox_xml(secret_key, &keybox_chain(&chain), &device_id)?;
    let private_key_pem = private_key_pem(secret_key)?;
    Ok(Prepared {
        chain,
        device_id,
        keybox_xml,
        private_key_pem,
        cert_chain_der,
        manufacturer: manufacturer_report,
    })
}

impl Prepared {
    pub(crate) fn write(self, paths: &AppPaths, csr: &[u8]) -> Result<Artifacts> {
        let Self {
            chain,
            device_id,
            keybox_xml,
            private_key_pem,
            cert_chain_der,
            manufacturer,
        } = self;
        // TempDir reserves a private directory atomically and removes partial output on
        // failure. It is retained only once every artifact has been written successfully.
        let run_dir = unique_run_dir(paths)?;
        let run_path = run_dir.path();

        let artifact_paths = ArtifactPaths {
            keybox_path: run_path.join("keybox.xml").display().to_string(),
            csr_path: run_path.join("csr.cbor").display().to_string(),
            cert_chain_path: run_path.join("cert_chain.der").display().to_string(),
            private_key_path: run_path.join("private_key.pem").display().to_string(),
            run_dir: run_path.display().to_string(),
        };

        write_secret(
            Path::new(&artifact_paths.private_key_path),
            private_key_pem.as_bytes(),
        )?;
        write_keybox(Path::new(&artifact_paths.keybox_path), &keybox_xml)?;
        write_bytes_atomic(Path::new(&artifact_paths.csr_path), csr)?;
        write_bytes_atomic(Path::new(&artifact_paths.cert_chain_path), &cert_chain_der)?;
        let _ = run_dir.keep();

        Ok(Artifacts {
            keybox_xml,
            device_id,
            chain,
            paths: artifact_paths,
            manufacturer,
        })
    }
}

/// Splits a concatenated DER certificate stream, as returned by `signCertificates`.
pub(crate) fn parse_der_cert_chain(data: &[u8]) -> Result<Vec<ParsedCertificate>> {
    if data.is_empty() {
        bail!("certificate chain is empty");
    }
    if data.len() > MAX_CERT_CHAIN_LEN {
        bail!("certificate chain is too large");
    }

    let mut certificates = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let slice = &data[offset..];
        let (header_len, body_len) = parse_der_len(slice)?;
        let total = header_len
            .checked_add(body_len)
            .ok_or_else(|| anyhow!("DER length overflow"))?;
        let end = offset
            .checked_add(total)
            .ok_or_else(|| anyhow!("DER length overflow"))?;
        if end > data.len() {
            bail!("DER certificate is truncated");
        }

        let der = &data[offset..end];
        let certificate = Certificate::from_der(der).context("parse X.509 certificate")?;
        let tbs = certificate.tbs_certificate();
        certificates.push(ParsedCertificate {
            der: der.to_vec(),
            subject_der: tbs.subject().to_der().context("encode subject name")?,
            issuer_der: tbs.issuer().to_der().context("encode issuer name")?,
            subject_label: tbs.subject().to_string(),
            issuer_label: tbs.issuer().to_string(),
            public_key: p256_subject_public_key(tbs),
        });

        if certificates.len() > MAX_CHAIN_CERTIFICATES {
            bail!("certificate chain contains more than {MAX_CHAIN_CERTIFICATES} certificates");
        }
        offset = end;
    }

    Ok(certificates)
}

/// The leaf must carry exactly the public key whose private half we keep, otherwise the
/// keybox would be rejected by every keystore that loads it.
pub(crate) fn ensure_chain_matches_key(
    chain: &[ParsedCertificate],
    secret_key: &P256SecretKey,
) -> Result<()> {
    let leaf = leaf_certificate(chain).ok_or(DeviceRkpError::CertificateMismatch)?;
    let issued = leaf
        .public_key
        .as_deref()
        .ok_or(DeviceRkpError::CertificateMismatch)?;
    if issued != secret_key.public_key().to_sec1_bytes().as_ref() {
        return Err(DeviceRkpError::CertificateMismatch.into());
    }
    Ok(())
}

/// The chain entry no other certificate in the set issued, i.e. the leaf.
fn leaf_certificate(chain: &[ParsedCertificate]) -> Option<&ParsedCertificate> {
    chain.iter().find(|candidate| {
        !chain.iter().any(|other| {
            other.subject_der != other.issuer_der && other.issuer_der == candidate.subject_der
        })
    })
}

/// The chain in keybox order, leaf first, each following entry the issuer of the one
/// before it. Fails when a certificate has no issuer in the set (which also catches a
/// cycle: the walk never reaches a self-issued certificate).
pub(crate) fn keybox_order(chain: &[ParsedCertificate]) -> Result<Vec<ParsedCertificate>> {
    let leaf = chain
        .iter()
        .position(|candidate| {
            !chain.iter().any(|other| {
                other.subject_der != other.issuer_der && other.issuer_der == candidate.subject_der
            })
        })
        .ok_or(DeviceRkpError::CertificateMismatch)?;

    let mut current = leaf;
    let mut ordered = vec![chain[leaf].clone()];
    let mut visited = vec![leaf];
    while chain[current].issuer_der != chain[current].subject_der {
        let issuer = chain
            .iter()
            .position(|candidate| candidate.subject_der == chain[current].issuer_der)
            .ok_or_else(|| {
                DeviceRkpError::InvalidCsr("certificate chain is missing an issuer".into())
            })?;
        if visited.contains(&issuer) {
            return Err(
                DeviceRkpError::InvalidCsr("certificate chain contains a cycle".into()).into(),
            );
        }
        visited.push(issuer);
        ordered.push(chain[issuer].clone());
        current = issuer;
    }
    Ok(ordered)
}

/// The response must be exactly one leaf-to-root path: a certificate the walk does not
/// reach would be dropped when the keybox is built, leaving a chain the device cannot
/// verify.
pub(crate) fn ensure_chain_is_linked(chain: &[ParsedCertificate]) -> Result<()> {
    let ordered = keybox_order(chain)?;
    if ordered.len() == chain.len() {
        return Ok(());
    }
    Err(DeviceRkpError::InvalidCsr(
        "certificate chain contains a certificate outside the leaf-to-root path".into(),
    )
    .into())
}

fn keybox_chain(chain: &[ParsedCertificate]) -> Vec<duck_rkp::keybox_xml::ParsedCertificate> {
    chain
        .iter()
        .map(|cert| duck_rkp::keybox_xml::ParsedCertificate {
            der: cert.der.clone(),
            subject_der: cert.subject_der.clone(),
            issuer_der: cert.issuer_der.clone(),
            subject_summary: cert.subject_label.clone(),
            issuer_summary: cert.issuer_label.clone(),
        })
        .collect()
}

/// SEC1 uncompressed point of a P-256 subject public key, or `None` for other keys.
fn p256_subject_public_key(tbs: &x509_cert::TbsCertificate) -> Option<Vec<u8>> {
    let spki = tbs.subject_public_key_info();
    if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY_OID {
        return None;
    }
    let parameters = spki.algorithm.parameters.as_ref()?;
    let curve = parameters
        .decode_as::<x509_cert::der::asn1::ObjectIdentifier>()
        .ok()?;
    if curve.to_string() != P256_CURVE_OID {
        return None;
    }
    let point = spki.subject_public_key.raw_bytes();
    // Normalize compressed and uncompressed encodings before comparing with the key.
    let public_key = p256::PublicKey::from_sec1_bytes(point).ok()?;
    Some(public_key.to_sec1_bytes().to_vec())
}

fn private_key_pem(secret_key: &P256SecretKey) -> Result<String> {
    let der = secret_key
        .to_sec1_der()
        .map_err(|error| anyhow!("encode EC private key as SEC1 DER: {error}"))?;
    Ok(pem_wrap("EC PRIVATE KEY", der.as_slice()))
}

/// Reserves a private output directory with a timestamp and a random suffix.
fn unique_run_dir(paths: &AppPaths) -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::create_dir_all(&paths.outputs_dir)
        .with_context(|| format!("create {}", paths.outputs_dir.display()))?;
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_millis();

    tempfile::Builder::new()
        .prefix(&format!("rkp-device-{millis}-"))
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&paths.outputs_dir)
        .with_context(|| {
            format!(
                "create a run directory under {}",
                paths.outputs_dir.display()
            )
        })
}

fn device_id(manufacturer: &str) -> Result<String> {
    let manufacturer = manufacturer.trim();
    let manufacturer = if manufacturer.is_empty() {
        "generic"
    } else {
        manufacturer
    };
    let mut random = [0_u8; 6];
    getrandom::fill(&mut random).map_err(|error| anyhow!("fill random bytes: {error}"))?;
    Ok(format!("{manufacturer}-{}", hex::encode(random)))
}

/// A keybox embeds the private key, so both the saved artifact and an explicit output
/// copy must have the same restrictive permissions as the standalone private key.
pub(crate) fn write_keybox(path: &Path, xml: &str) -> Result<()> {
    write_secret(path, xml.as_bytes())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .context("secret output has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // NamedTempFile creates a fresh 0600 file, even with a permissive caller umask or
    // an existing destination whose permissions are too broad. Persist replaces the
    // destination atomically without following a destination symlink.
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create a temporary file under {}", parent.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.as_file()
        .sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    file.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    use std::fmt::Write as _;

    let encoded = Base64::encode_string(der);
    let mut pem = String::new();
    writeln!(pem, "-----BEGIN {label}-----").unwrap();
    for chunk in encoded.as_bytes().chunks(64) {
        writeln!(pem, "{}", String::from_utf8_lossy(chunk)).unwrap();
    }
    write!(pem, "-----END {label}-----").unwrap();
    pem
}

fn parse_der_len(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.len() < 2 {
        bail!("DER sequence is truncated");
    }
    if bytes[0] != 0x30 {
        bail!("DER certificate must start with SEQUENCE");
    }
    if bytes[1] & 0x80 == 0 {
        return Ok((2, usize::from(bytes[1])));
    }
    if bytes[1] == 0x80 {
        bail!("DER indefinite lengths are not supported");
    }
    let count = usize::from(bytes[1] & 0x7F);
    if count == 0 || count > std::mem::size_of::<usize>() {
        bail!("DER length uses an invalid long-form encoding");
    }
    let length_bytes = bytes
        .get(2..2 + count)
        .context("DER length bytes are truncated")?;
    let mut length = 0usize;
    for byte in length_bytes {
        length = (length << 8) | usize::from(*byte);
    }
    Ok((2 + count, length))
}

#[cfg(test)]
#[path = "artifacts_tests.rs"]
mod tests;
