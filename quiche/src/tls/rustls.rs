// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use ::rustls::crypto::CipherSuite;
use ::rustls::crypto::Credentials;
use ::rustls::crypto::Identity;
use ::rustls::crypto::SingleCredential;
use ::rustls::pki_types::pem::PemObject;
use ::rustls::pki_types::CertificateDer;
use ::rustls::pki_types::PrivateKeyDer;
use ::rustls::RootCertStore;
use ::rustls::SupportedCipherSuite;

use crate::crypto;
use crate::packet;
use crate::ConnectionError;
use crate::Error;
use crate::Result;

pub struct Context {
    provider: Arc<::rustls::crypto::CryptoProvider>,
    certificate_identity: Option<Arc<Identity<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    root_store: RootCertStore,
    verify: bool,
    keylog_enabled: bool,
    early_data_enabled: bool,
    alpn_protocols: Vec<Vec<u8>>,
}

impl Context {
    pub fn new() -> Result<Context> {
        keep_crypto_symbols_live();

        Ok(Context {
            provider: Arc::new(rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER),
            certificate_identity: None,
            private_key: None,
            root_store: RootCertStore::empty(),
            verify: true,
            keylog_enabled: false,
            early_data_enabled: false,
            alpn_protocols: Vec::new(),
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        let key_log = self.keylog_enabled.then(|| Arc::new(QuicheKeyLog::new()));

        Ok(Handshake {
            provider: Arc::clone(&self.provider),
            certificate_identity: self.certificate_identity.clone(),
            private_key: self.private_key.as_ref().map(PrivateKeyDer::clone_key),
            root_store: self.root_store.clone(),
            verify: self.verify,
            key_log,
            early_data_enabled: self.early_data_enabled,
            alpn_protocols: self.alpn_protocols.clone(),
            is_server: None,
            server_name: None,
            local_transport_params: Vec::new(),
            conn: None,
            write_level: crypto::Level::Initial,
        })
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        self.load_root_certs_from_file(file)
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let mut valid = 0;

        for entry in fs::read_dir(path).map_err(|_| Error::TlsFail)? {
            let entry = entry.map_err(|_| Error::TlsFail)?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if self.load_root_certs_from_file(&path).is_ok() {
                valid += 1;
            }
        }

        match valid {
            0 => Err(Error::TlsFail),
            _ => Ok(()),
        }
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let certs = CertificateDer::pem_file_iter(file)
            .map_err(|_| Error::TlsFail)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::TlsFail)?;
        let identity =
            Identity::from_cert_chain(certs).map_err(|_| Error::TlsFail)?;

        self.certificate_identity = Some(Arc::new(identity));

        Ok(())
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        self.private_key =
            Some(PrivateKeyDer::from_pem_file(file).map_err(|_| Error::TlsFail)?);

        Ok(())
    }

    pub fn set_verify(&mut self, verify: bool) {
        self.verify = verify;
    }

    pub fn enable_keylog(&mut self) {
        self.keylog_enabled = true;
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        self.alpn_protocols = v.iter().map(|proto| proto.to_vec()).collect();

        Ok(())
    }

    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        self.early_data_enabled = enabled;
    }

    fn load_root_certs_from_file(
        &mut self, file: impl AsRef<Path>,
    ) -> Result<()> {
        let certs = CertificateDer::pem_file_iter(file)
            .map_err(|_| Error::TlsFail)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::TlsFail)?;
        let (valid, _invalid) = self.root_store.add_parsable_certificates(certs);

        match valid {
            0 => Err(Error::TlsFail),
            _ => Ok(()),
        }
    }
}

pub struct Handshake {
    provider: Arc<::rustls::crypto::CryptoProvider>,
    certificate_identity: Option<Arc<Identity<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    root_store: RootCertStore,
    verify: bool,
    key_log: Option<Arc<QuicheKeyLog>>,
    early_data_enabled: bool,
    alpn_protocols: Vec<Vec<u8>>,
    is_server: Option<bool>,
    server_name: Option<String>,
    local_transport_params: Vec<u8>,
    conn: Option<::rustls::quic::Connection>,
    write_level: crypto::Level,
}

impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.is_server = Some(is_server);

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, _use_legacy: bool) {}

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        self.server_name = Some(name.to_string());

        Ok(())
    }

    pub fn set_quic_transport_params(
        &mut self, params: &crate::TransportParams, is_server: bool,
    ) -> Result<()> {
        let mut raw_params = [0; 128];

        let raw_params =
            crate::TransportParams::encode(params, is_server, &mut raw_params)?;

        self.local_transport_params.clear();
        self.local_transport_params.extend_from_slice(raw_params);

        Ok(())
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        self.conn
            .as_ref()
            .and_then(|conn| conn.quic_transport_parameters())
            .unwrap_or(&[])
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        self.conn
            .as_ref()
            .and_then(|conn| conn.alpn_protocol())
            .map(|proto| proto.as_ref())
            .unwrap_or(&[])
    }

    pub fn server_name(&self) -> Option<&str> {
        match &self.conn {
            Some(::rustls::quic::Connection::Server(conn)) =>
                conn.server_name().map(|name| name.as_ref()),

            _ => self.server_name.as_deref(),
        }
    }

    pub fn provide_data(
        &mut self, _level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        self.connection()?.read_hs(buf).map_err(|_| Error::TlsFail)
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        observe_ex_data(ex_data);
        self.sync_ex_data(ex_data);
        self.flush_handshake_data(ex_data)?;
        self.flush_keylog(ex_data);

        match self.is_completed() {
            true => Ok(()),
            false => Err(Error::Done),
        }
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        self.flush_keylog(ex_data);

        Ok(())
    }

    pub fn write_level(&self) -> crypto::Level {
        self.write_level
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let cipher = self.conn.as_ref()?.negotiated_cipher_suite()?;

        match cipher {
            SupportedCipherSuite::Tls13(suite) =>
                rustls_cipher_to_algorithm(suite.common.suite),

            SupportedCipherSuite::Tls12(_) => None,

            _ => None,
        }
    }

    #[cfg(test)]
    pub fn set_options(&mut self, _opts: u32) {}

    pub fn is_completed(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|conn| !conn.is_handshaking())
    }

    pub fn is_resumed(&self) -> bool {
        matches!(
            self.conn.as_ref().and_then(|conn| conn.handshake_kind()),
            Some(::rustls::HandshakeKind::Resumed) |
                Some(::rustls::HandshakeKind::ResumedWithHelloRetryRequest)
        )
    }

    pub fn clear(&mut self) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_session(&mut self, _session: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn curve(&self) -> Option<String> {
        self.conn
            .as_ref()?
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name()))
    }

    pub fn sigalg(&self) -> Option<String> {
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        peer_cert_chain(self.conn.as_ref()?.peer_identity()?)
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        peer_cert(self.conn.as_ref()?.peer_identity()?)
    }

    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {}

    pub fn is_in_early_data(&self) -> bool {
        false
    }

    pub fn early_data_reason(&self) -> u32 {
        0
    }

    fn connection(&mut self) -> Result<&mut ::rustls::quic::Connection> {
        if self.conn.is_none() {
            self.conn = Some(self.build_connection()?);
        }

        Ok(self.conn.as_mut().expect("connection was just initialized"))
    }

    fn build_connection(&self) -> Result<::rustls::quic::Connection> {
        match self.is_server.ok_or(Error::TlsFail)? {
            true => self.build_server_connection(),
            false => self.build_client_connection(),
        }
    }

    fn build_client_connection(&self) -> Result<::rustls::quic::Connection> {
        let server_name = self.server_name.as_deref().ok_or(Error::TlsFail)?;
        let server_name = ::rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|_| Error::TlsFail)?
            .to_owned();

        let mut config = match self.verify {
            true => {
                if self.root_store.is_empty() {
                    return Err(Error::TlsFail);
                }

                ::rustls::ClientConfig::builder(Arc::clone(&self.provider))
                    .with_root_certificates(Arc::new(self.root_store.clone()))
                    .with_no_client_auth()
                    .map_err(|_| Error::TlsFail)?
            },

            false => ::rustls::ClientConfig::builder(Arc::clone(&self.provider))
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    NoCertificateVerification::new(&self.provider),
                ))
                .with_no_client_auth()
                .map_err(|_| Error::TlsFail)?,
        };

        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .cloned()
            .map(::rustls::enums::ApplicationProtocol::from)
            .collect();
        config.enable_early_data = self.early_data_enabled;
        self.set_keylog(&mut config.key_log);

        let conn = ::rustls::quic::ClientConnection::new(
            Arc::new(config),
            ::rustls::quic::Version::V1,
            server_name,
            self.local_transport_params.clone(),
        )
        .map_err(|_| Error::TlsFail)?;

        Ok(conn.into())
    }

    fn build_server_connection(&self) -> Result<::rustls::quic::Connection> {
        let certificate_identity = self
            .certificate_identity
            .as_ref()
            .ok_or(Error::TlsFail)?
            .clone();
        let private_key =
            self.private_key.as_ref().ok_or(Error::TlsFail)?.clone_key();

        let signing_key = self
            .provider
            .key_provider
            .load_private_key(private_key)
            .map_err(|_| Error::TlsFail)?;
        let credentials =
            Credentials::new_unchecked(certificate_identity, signing_key);
        let mut config =
            ::rustls::ServerConfig::builder(Arc::clone(&self.provider))
                .with_no_client_auth()
                .with_server_credential_resolver(Arc::new(
                    SingleCredential::from(credentials),
                ))
                .map_err(|_| Error::TlsFail)?;

        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .cloned()
            .map(::rustls::enums::ApplicationProtocol::from)
            .collect();
        config.max_early_data_size = match self.early_data_enabled {
            true => u32::MAX,
            false => 0,
        };
        self.set_keylog(&mut config.key_log);

        let conn = ::rustls::quic::ServerConnection::new(
            Arc::new(config),
            ::rustls::quic::Version::V1,
            self.local_transport_params.clone(),
        )
        .map_err(|_| Error::TlsFail)?;

        Ok(conn.into())
    }

    fn set_keylog(&self, key_log: &mut Arc<dyn ::rustls::KeyLog>) {
        if let Some(log) = &self.key_log {
            *key_log = log.clone();
        }
    }

    fn flush_keylog(&self, ex_data: &mut ExData) {
        if let Some(key_log) = &self.key_log {
            key_log.drain(&mut ex_data.keylog);
        }
    }

    fn sync_ex_data(&mut self, ex_data: &ExData) {
        if self.alpn_protocols != *ex_data.application_protos {
            self.alpn_protocols = ex_data.application_protos.clone();
        }
    }

    fn flush_handshake_data(&mut self, ex_data: &mut ExData) -> Result<()> {
        loop {
            let mut buf = Vec::new();
            let key_change = self.connection()?.write_hs(&mut buf);

            if !buf.is_empty() {
                let space = match self.write_level {
                    crypto::Level::Initial =>
                        &mut ex_data.crypto_ctx[packet::Epoch::Initial],

                    crypto::Level::ZeroRTT => unreachable!(),

                    crypto::Level::Handshake =>
                        &mut ex_data.crypto_ctx[packet::Epoch::Handshake],

                    crypto::Level::OneRTT =>
                        &mut ex_data.crypto_ctx[packet::Epoch::Application],
                };

                space
                    .crypto_stream
                    .send
                    .write(&buf, false)
                    .map_err(|_| Error::TlsFail)?;
            }

            match key_change {
                Some(::rustls::quic::KeyChange::Handshake { keys }) => {
                    ex_data.crypto_ctx[packet::Epoch::Handshake].crypto_open =
                        Some(crypto::Open::from_rustls(keys.remote, None));
                    ex_data.crypto_ctx[packet::Epoch::Handshake].crypto_seal =
                        Some(crypto::Seal::from_rustls(keys.local, None));

                    self.write_level = crypto::Level::Handshake;
                },

                Some(::rustls::quic::KeyChange::OneRtt { keys, next }) => {
                    ex_data.crypto_ctx[packet::Epoch::Application].crypto_open =
                        Some(crypto::Open::from_rustls(
                            keys.remote,
                            Some(next.clone()),
                        ));
                    ex_data.crypto_ctx[packet::Epoch::Application].crypto_seal =
                        Some(crypto::Seal::from_rustls(keys.local, Some(next)));

                    self.write_level = crypto::Level::OneRTT;
                },

                None => break,
            }
        }

        Ok(())
    }
}

fn rustls_cipher_to_algorithm(cipher: CipherSuite) -> Option<crypto::Algorithm> {
    match cipher {
        CipherSuite::TLS13_AES_128_GCM_SHA256 =>
            Some(crypto::Algorithm::AES128_GCM),

        CipherSuite::TLS13_AES_256_GCM_SHA384 =>
            Some(crypto::Algorithm::AES256_GCM),

        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 =>
            Some(crypto::Algorithm::ChaCha20_Poly1305),

        _ => None,
    }
}

fn peer_cert_chain<'a>(identity: &'a Identity<'static>) -> Option<Vec<&'a [u8]>> {
    match identity {
        Identity::X509(certificates) => {
            let leaf = certificates.end_entity.as_ref();
            if leaf.is_empty() {
                return None;
            }

            let mut chain = vec![leaf];

            for cert in &certificates.intermediates {
                let cert = cert.as_ref();
                if cert.is_empty() {
                    return None;
                }

                chain.push(cert);
            }

            Some(chain)
        },

        Identity::RawPublicKey(spki) => {
            let spki = spki.as_ref();
            (!spki.is_empty()).then_some(vec![spki])
        },

        _ => None,
    }
}

fn peer_cert<'a>(identity: &'a Identity<'static>) -> Option<&'a [u8]> {
    match identity {
        Identity::X509(certificates) => {
            let cert = certificates.end_entity.as_ref();
            (!cert.is_empty()).then_some(cert)
        },

        Identity::RawPublicKey(spki) => {
            let spki = spki.as_ref();
            (!spki.is_empty()).then_some(spki)
        },

        _ => None,
    }
}

struct QuicheKeyLog {
    lines: Mutex<Vec<u8>>,
}

impl QuicheKeyLog {
    fn new() -> QuicheKeyLog {
        QuicheKeyLog {
            lines: Mutex::new(Vec::new()),
        }
    }

    fn drain(&self, keylog: &mut Option<&mut Box<dyn Write + Send + Sync>>) {
        let data = match self.lines.lock() {
            Ok(mut lines) => std::mem::take(&mut *lines),

            Err(_) => return,
        };

        if data.is_empty() {
            return;
        }

        if let Some(keylog) = keylog {
            keylog.write_all(&data).ok();
            keylog.flush().ok();
        }
    }
}

impl fmt::Debug for QuicheKeyLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicheKeyLog").finish_non_exhaustive()
    }
}

impl ::rustls::KeyLog for QuicheKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let Ok(mut lines) = self.lines.lock() else {
            return;
        };

        write!(lines, "{label} ").ok();

        for b in client_random {
            write!(lines, "{b:02x}").ok();
        }

        write!(lines, " ").ok();

        for b in secret {
            write!(lines, "{b:02x}").ok();
        }

        writeln!(lines).ok();
    }
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported_schemes: Vec<::rustls::crypto::SignatureScheme>,
}

impl NoCertificateVerification {
    fn new(provider: &::rustls::crypto::CryptoProvider) -> Self {
        Self {
            supported_schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl ::rustls::client::danger::ServerVerifier for NoCertificateVerification {
    fn verify_identity(
        &self, _identity: &::rustls::client::danger::ServerIdentity,
    ) -> std::result::Result<
        ::rustls::client::danger::PeerVerified,
        ::rustls::Error,
    > {
        Ok(::rustls::client::danger::PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        Ok(::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        Ok(::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<::rustls::crypto::SignatureScheme> {
        self.supported_schemes.clone()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, h: &mut dyn std::hash::Hasher) {
        h.write(b"quiche-rustls-no-certificate-verification");
    }
}

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub local_transport_params: crate::TransportParams,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    /// PMTUD configuration: (enable, max_probes)
    pub pmtud: Option<(bool, u8)>,

    pub is_server: bool,
}

fn keep_crypto_symbols_live() {
    let _ = crypto::Level::ZeroRTT;
    let _ = crypto::Algorithm::AES256_GCM;
    let _ = crypto::Algorithm::ChaCha20_Poly1305;
}

fn observe_ex_data(ex_data: &mut ExData) {
    let _ = ex_data.session.is_some();
    let _ = ex_data.local_error.is_some();
    let _ = ex_data.keylog.is_some();
    let _ = ex_data.trace_id.len();
    let _ = ex_data.is_server;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(is_server: bool) -> (Handshake, [packet::CryptoContext; 3]) {
        handshake_with_keylog(is_server, false)
    }

    fn handshake_with_keylog(
        is_server: bool, keylog_enabled: bool,
    ) -> (Handshake, [packet::CryptoContext; 3]) {
        let mut ctx = Context::new().unwrap();
        ctx.set_verify(false);
        ctx.set_alpn(&[b"h3"]).unwrap();

        if keylog_enabled {
            ctx.enable_keylog();
        }

        if is_server {
            ctx.use_certificate_chain_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/cert.crt"
            ))
            .unwrap();
            ctx.use_privkey_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/cert.key"
            ))
            .unwrap();
        }

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(is_server).unwrap();

        if !is_server {
            handshake.set_host_name("example.com").unwrap();
        }

        handshake
            .set_quic_transport_params(
                &crate::TransportParams::default(),
                is_server,
            )
            .unwrap();

        (handshake, [
            packet::CryptoContext::new(),
            packet::CryptoContext::new(),
            packet::CryptoContext::new(),
        ])
    }

    fn ex_data<'a>(
        crypto_ctx: &'a mut [packet::CryptoContext; 3], is_server: bool,
        application_protos: &'a Vec<Vec<u8>>, session: &'a mut Option<Vec<u8>>,
        local_error: &'a mut Option<ConnectionError>,
        recovery_config: crate::recovery::RecoveryConfig, tx_cap_factor: f64,
    ) -> ExData<'a> {
        ex_data_with_keylog(
            crypto_ctx,
            is_server,
            application_protos,
            session,
            local_error,
            recovery_config,
            tx_cap_factor,
            None,
        )
    }

    fn ex_data_with_keylog<'a>(
        crypto_ctx: &'a mut [packet::CryptoContext; 3], is_server: bool,
        application_protos: &'a Vec<Vec<u8>>, session: &'a mut Option<Vec<u8>>,
        local_error: &'a mut Option<ConnectionError>,
        recovery_config: crate::recovery::RecoveryConfig, tx_cap_factor: f64,
        keylog: Option<&'a mut Box<dyn Write + Send + Sync>>,
    ) -> ExData<'a> {
        ExData {
            application_protos,
            crypto_ctx,
            session,
            local_error,
            keylog,
            trace_id: "",
            local_transport_params: crate::TransportParams::default(),
            recovery_config,
            tx_cap_factor,
            pmtud: None,
            is_server,
        }
    }

    #[derive(Clone)]
    struct SharedKeyLog {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedKeyLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.lock().unwrap().extend_from_slice(buf);

            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn keylog_writer() -> (Arc<Mutex<Vec<u8>>>, Box<dyn Write + Send + Sync>) {
        let data = Arc::new(Mutex::new(Vec::new()));

        (data.clone(), Box::new(SharedKeyLog { data }))
    }

    fn drain_crypto(
        crypto_ctx: &mut [packet::CryptoContext; 3], epoch: packet::Epoch,
    ) -> Vec<u8> {
        let mut data = vec![0; 8192];
        let len = crypto_ctx[epoch]
            .crypto_stream
            .send
            .emit(&mut data)
            .unwrap()
            .0;

        data.truncate(len);

        data
    }

    fn example_cert_chain() -> Vec<Vec<u8>> {
        CertificateDer::pem_file_iter(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/cert.crt"
        ))
        .unwrap()
        .map(|cert| cert.unwrap().as_ref().to_vec())
        .collect()
    }

    #[test]
    fn client_handshake_emits_initial_crypto() {
        let mut ctx = Context::new().unwrap();
        ctx.set_verify(false);
        ctx.set_alpn(&[b"h3"]).unwrap();

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(false).unwrap();
        handshake.set_host_name("example.com").unwrap();
        handshake
            .set_quic_transport_params(&crate::TransportParams::default(), false)
            .unwrap();

        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let mut crypto_ctx = [
            packet::CryptoContext::new(),
            packet::CryptoContext::new(),
            packet::CryptoContext::new(),
        ];
        let mut session = None;
        let mut local_error = None;
        let application_protos = vec![b"h3".to_vec()];
        let mut ex_data = ExData {
            application_protos: &application_protos,
            crypto_ctx: &mut crypto_ctx,
            session: &mut session,
            local_error: &mut local_error,
            keylog: None,
            trace_id: "",
            local_transport_params: crate::TransportParams::default(),
            recovery_config,
            tx_cap_factor: config.tx_cap_factor,
            pmtud: None,
            is_server: false,
        };

        assert_eq!(handshake.do_handshake(&mut ex_data), Err(Error::Done));
        assert!(ex_data.crypto_ctx[packet::Epoch::Initial].data_available());
    }

    #[test]
    fn handshake_installs_packet_keys() {
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let application_protos = vec![b"h3".to_vec()];
        let mut client_session = None;
        let mut server_session = None;
        let mut client_error = None;
        let mut server_error = None;

        let (mut client, mut client_crypto_ctx) = handshake(false);
        let (mut server, mut server_crypto_ctx) = handshake(true);

        {
            let mut client_ex_data = ex_data(
                &mut client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert!(matches!(
                client.do_handshake(&mut client_ex_data),
                Ok(()) | Err(Error::Done)
            ));
        }

        let client_initial =
            drain_crypto(&mut client_crypto_ctx, packet::Epoch::Initial);
        assert!(!client_initial.is_empty());

        server
            .provide_data(crypto::Level::Initial, &client_initial)
            .unwrap();

        {
            let mut server_ex_data = ex_data(
                &mut server_crypto_ctx,
                true,
                &application_protos,
                &mut server_session,
                &mut server_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert_eq!(
                server.do_handshake(&mut server_ex_data),
                Err(Error::Done)
            );
        }

        assert!(server_crypto_ctx[packet::Epoch::Handshake].has_keys());
        assert_eq!(server.cipher(), Some(crypto::Algorithm::AES128_GCM));

        let server_initial =
            drain_crypto(&mut server_crypto_ctx, packet::Epoch::Initial);
        let server_handshake =
            drain_crypto(&mut server_crypto_ctx, packet::Epoch::Handshake);
        assert!(!server_initial.is_empty());
        assert!(!server_handshake.is_empty());

        client
            .provide_data(crypto::Level::Initial, &server_initial)
            .unwrap();
        client
            .provide_data(crypto::Level::Handshake, &server_handshake)
            .unwrap();

        {
            let mut client_ex_data = ex_data(
                &mut client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert!(matches!(
                client.do_handshake(&mut client_ex_data),
                Ok(()) | Err(Error::Done)
            ));
        }

        assert!(client_crypto_ctx[packet::Epoch::Handshake].has_keys());
        assert!(client_crypto_ctx[packet::Epoch::Application].has_keys());
        assert_eq!(client.cipher(), Some(crypto::Algorithm::AES128_GCM));
        assert!(client.curve().is_some());
        assert!(!client.is_resumed());

        let expected_chain = example_cert_chain();
        assert_eq!(client.peer_cert(), Some(expected_chain[0].as_slice()));
        assert_eq!(
            client.peer_cert_chain(),
            Some(expected_chain.iter().map(Vec::as_slice).collect::<Vec<_>>())
        );
        assert!(server.peer_cert().is_none());
        assert!(server.peer_cert_chain().is_none());
    }

    #[test]
    fn handshake_writes_keylog() {
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let application_protos = vec![b"h3".to_vec()];
        let mut client_session = None;
        let mut server_session = None;
        let mut client_error = None;
        let mut server_error = None;
        let (client_log, mut client_keylog) = keylog_writer();
        let (server_log, mut server_keylog) = keylog_writer();

        let (mut client, mut client_crypto_ctx) =
            handshake_with_keylog(false, true);
        let (mut server, mut server_crypto_ctx) =
            handshake_with_keylog(true, true);

        {
            let mut client_ex_data = ex_data_with_keylog(
                &mut client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config.clone(),
                config.tx_cap_factor,
                Some(&mut client_keylog),
            );
            assert!(matches!(
                client.do_handshake(&mut client_ex_data),
                Ok(()) | Err(Error::Done)
            ));
        }

        let client_initial =
            drain_crypto(&mut client_crypto_ctx, packet::Epoch::Initial);
        server
            .provide_data(crypto::Level::Initial, &client_initial)
            .unwrap();

        {
            let mut server_ex_data = ex_data_with_keylog(
                &mut server_crypto_ctx,
                true,
                &application_protos,
                &mut server_session,
                &mut server_error,
                recovery_config.clone(),
                config.tx_cap_factor,
                Some(&mut server_keylog),
            );
            assert_eq!(
                server.do_handshake(&mut server_ex_data),
                Err(Error::Done)
            );
        }

        let server_initial =
            drain_crypto(&mut server_crypto_ctx, packet::Epoch::Initial);
        let server_handshake =
            drain_crypto(&mut server_crypto_ctx, packet::Epoch::Handshake);

        client
            .provide_data(crypto::Level::Initial, &server_initial)
            .unwrap();
        client
            .provide_data(crypto::Level::Handshake, &server_handshake)
            .unwrap();

        {
            let mut client_ex_data = ex_data_with_keylog(
                &mut client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config,
                config.tx_cap_factor,
                Some(&mut client_keylog),
            );
            assert!(matches!(
                client.do_handshake(&mut client_ex_data),
                Ok(()) | Err(Error::Done)
            ));
        }

        let client_log =
            String::from_utf8(client_log.lock().unwrap().clone()).unwrap();
        let server_log =
            String::from_utf8(server_log.lock().unwrap().clone()).unwrap();

        assert!(client_log.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET "));
        assert!(client_log.contains("SERVER_HANDSHAKE_TRAFFIC_SECRET "));
        assert!(client_log.contains("CLIENT_TRAFFIC_SECRET_0 "));
        assert!(client_log.contains("SERVER_TRAFFIC_SECRET_0 "));
        assert!(server_log.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET "));
        assert!(server_log.contains("SERVER_HANDSHAKE_TRAFFIC_SECRET "));
    }

    #[test]
    fn client_verification_requires_loaded_roots() {
        let mut ctx = Context::new().unwrap();

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(false).unwrap();
        handshake.set_host_name("example.com").unwrap();
        handshake
            .set_quic_transport_params(&crate::TransportParams::default(), false)
            .unwrap();

        assert!(matches!(
            handshake.build_client_connection(),
            Err(Error::TlsFail)
        ));
    }

    #[test]
    fn client_context_loads_verify_roots() {
        let mut ctx = Context::new().unwrap();
        ctx.load_verify_locations_from_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/rootca.crt"
        ))
        .unwrap();

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(false).unwrap();
        handshake.set_host_name("example.com").unwrap();
        handshake
            .set_quic_transport_params(&crate::TransportParams::default(), false)
            .unwrap();

        assert!(handshake.build_client_connection().is_ok());
    }

    #[test]
    fn client_context_loads_verify_roots_from_directory() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("quiche-rustls-roots-{pid}-{now}"));
        let root_path = dir.join("rootca.crt");

        fs::create_dir(&dir).unwrap();
        fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/rootca.crt"),
            &root_path,
        )
        .unwrap();

        let mut ctx = Context::new().unwrap();
        let result =
            ctx.load_verify_locations_from_directory(dir.to_str().unwrap());

        fs::remove_dir_all(&dir).unwrap();

        result.unwrap();

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(false).unwrap();
        handshake.set_host_name("example.com").unwrap();
        handshake
            .set_quic_transport_params(&crate::TransportParams::default(), false)
            .unwrap();

        assert!(handshake.build_client_connection().is_ok());
    }

    #[test]
    fn context_copies_early_data_setting_to_handshake() {
        let mut ctx = Context::new().unwrap();
        let handshake = ctx.new_handshake().unwrap();
        assert!(!handshake.early_data_enabled);

        ctx.set_early_data_enabled(true);
        let handshake = ctx.new_handshake().unwrap();
        assert!(handshake.early_data_enabled);
    }

    #[test]
    fn early_data_enabled_connections_build() {
        let mut client_ctx = Context::new().unwrap();
        client_ctx.set_verify(false);
        client_ctx.set_alpn(&[b"h3"]).unwrap();
        client_ctx.set_early_data_enabled(true);

        let mut client = client_ctx.new_handshake().unwrap();
        client.init(false).unwrap();
        client.set_host_name("example.com").unwrap();
        client
            .set_quic_transport_params(&crate::TransportParams::default(), false)
            .unwrap();
        assert!(client.build_client_connection().is_ok());

        let mut server_ctx = Context::new().unwrap();
        server_ctx.set_alpn(&[b"h3"]).unwrap();
        server_ctx.set_early_data_enabled(true);
        server_ctx
            .use_certificate_chain_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/cert.crt"
            ))
            .unwrap();
        server_ctx
            .use_privkey_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/cert.key"
            ))
            .unwrap();

        let mut server = server_ctx.new_handshake().unwrap();
        server.init(true).unwrap();
        server
            .set_quic_transport_params(&crate::TransportParams::default(), true)
            .unwrap();
        assert!(server.build_server_connection().is_ok());
    }

    #[test]
    fn server_context_loads_certificate_and_private_key() {
        let mut ctx = Context::new().unwrap();
        ctx.use_certificate_chain_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/cert.crt"
        ))
        .unwrap();
        ctx.use_privkey_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/cert.key"
        ))
        .unwrap();

        let mut handshake = ctx.new_handshake().unwrap();
        handshake.init(true).unwrap();
        handshake
            .set_quic_transport_params(&crate::TransportParams::default(), true)
            .unwrap();

        assert!(handshake.build_server_connection().is_ok());
    }
}
