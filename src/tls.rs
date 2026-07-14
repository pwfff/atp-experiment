//! TLS 1.3 for key exchange only — the whole point of atp-experiment.
//!
//! The control connection gets a real rustls handshake: ECDHE, certificate
//! identity, forward secrecy. The *data* plane stays kernel UDP; both peers
//! derive the 32-byte symbol key from the established session via the
//! RFC 8446 §7.5 keying-material exporter, and every datagram is sealed
//! with per-datagram AEAD (see [`crate::sealed`]). No userspace QUIC
//! transport anywhere — that's the gap the original atp documented and
//! this design closes.
//!
//! Trust model (demo-grade, SSH-style): the receiver generates an rcgen
//! self-signed cert and prints its SHA-256 fingerprint; the sender pins it
//! with `--pin`. The pin verifier still checks the TLS 1.3 handshake
//! signature against the pinned cert's public key, so presenting a stolen
//! certificate without its private key fails.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// RFC 8446 §7.5 exporter label for the UDP symbol-plane AEAD key.
/// Both ends export 32 bytes under this label (empty context) once the
/// handshake completes.
pub const SEAL_EXPORTER_LABEL: &[u8] = b"EXPORTER-atp-rq-sealed-v1-symbol-key";

/// Symbol-plane AEAD key length in bytes.
pub const SEAL_KEY_LEN: usize = 32;

/// SNI name; carries no trust (identity is the pinned fingerprint).
pub const SNI: &str = "atp-experiment";

/// Receiver-side self-signed identity for one `atp-experiment recv` invocation.
pub struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![SNI.to_string()])
            .map_err(|e| Error::Transfer(format!("certificate generation failed: {e}")))?;
        let cert = ck.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        Ok(Identity { cert, key })
    }

    /// Hex SHA-256 of the certificate DER — what the sender pins.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.cert.as_ref()))
    }

    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| Error::Transfer(format!("TLS server config: {e}")))?;
        Ok(Arc::new(cfg))
    }
}

/// Parse a `--pin` value: hex SHA-256, colons and whitespace tolerated.
pub fn parse_pin(s: &str) -> Result<[u8; 32]> {
    let cleaned: String = s.chars().filter(|c| !matches!(c, ':' | ' ')).collect();
    let bytes = hex::decode(cleaned.to_ascii_lowercase())
        .map_err(|_| Error::Transfer(format!("--pin is not valid hex: {s:?}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Transfer("--pin must be a 32-byte (64 hex char) SHA-256".into()))
}

/// Client config that authenticates the server *only* by certificate
/// fingerprint (plus a genuine handshake-signature check).
pub fn client_config(pin: [u8; 32]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Derive the symbol-plane key from an established connection.
pub fn export_symbol_key<Data>(
    conn: &rustls::ConnectionCommon<Data>,
) -> Result<[u8; SEAL_KEY_LEN]> {
    conn.export_keying_material([0u8; SEAL_KEY_LEN], SEAL_EXPORTER_LABEL, None)
        .map_err(|e| Error::Transfer(format!("TLS keying-material export failed: {e}")))
}

#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = Sha256::digest(end_entity.as_ref());
        if fp.as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is compiled out (no `tls12` feature); never accept it.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_parsing() {
        let id = Identity::generate().unwrap();
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(parse_pin(&fp).is_ok());
        let colons: String = fp
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_pin(&colons).unwrap(), parse_pin(&fp).unwrap());
        assert!(parse_pin("beef").is_err(), "too short");
        assert!(parse_pin("zz").is_err(), "not hex");
    }

    #[test]
    fn fingerprints_are_unique_per_identity() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
