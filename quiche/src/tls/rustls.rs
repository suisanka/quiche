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

use std::io::Write;
use std::sync::Arc;

use ::rustls::crypto::Credentials;
use ::rustls::crypto::Identity;
use ::rustls::crypto::SingleCredential;
use ::rustls::pki_types::pem::PemObject;
use ::rustls::pki_types::CertificateDer;
use ::rustls::pki_types::PrivateKeyDer;
use ::rustls::RootCertStore;

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
            alpn_protocols: Vec::new(),
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        Ok(Handshake {
            provider: Arc::clone(&self.provider),
            certificate_identity: self.certificate_identity.clone(),
            private_key: self.private_key.as_ref().map(PrivateKeyDer::clone_key),
            root_store: self.root_store.clone(),
            verify: self.verify,
            alpn_protocols: self.alpn_protocols.clone(),
            is_server: None,
            server_name: None,
            local_transport_params: Vec::new(),
            conn: None,
            write_level: crypto::Level::Initial,
        })
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
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

    pub fn load_verify_locations_from_directory(
        &mut self, _path: &str,
    ) -> Result<()> {
        Err(Error::TlsFail)
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

    pub fn enable_keylog(&mut self) {}

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        self.alpn_protocols = v.iter().map(|proto| proto.to_vec()).collect();

        Ok(())
    }

    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_early_data_enabled(&mut self, _enabled: bool) {}
}

pub struct Handshake {
    provider: Arc<::rustls::crypto::CryptoProvider>,
    certificate_identity: Option<Arc<Identity<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    root_store: RootCertStore,
    verify: bool,
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

        match self.is_completed() {
            true => Ok(()),
            false => Err(Error::Done),
        }
    }

    pub fn process_post_handshake(
        &mut self, _ex_data: &mut ExData,
    ) -> Result<()> {
        Ok(())
    }

    pub fn write_level(&self) -> crypto::Level {
        self.write_level
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        None
    }

    #[cfg(test)]
    pub fn set_options(&mut self, _opts: u32) {}

    pub fn is_completed(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|conn| !conn.is_handshaking())
    }

    pub fn is_resumed(&self) -> bool {
        false
    }

    pub fn clear(&mut self) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_session(&mut self, _session: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn curve(&self) -> Option<String> {
        None
    }

    pub fn sigalg(&self) -> Option<String> {
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        None
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        None
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

        let conn = ::rustls::quic::ServerConnection::new(
            Arc::new(config),
            ::rustls::quic::Version::V1,
            self.local_transport_params.clone(),
        )
        .map_err(|_| Error::TlsFail)?;

        Ok(conn.into())
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
        let mut ctx = Context::new().unwrap();
        ctx.set_verify(false);
        ctx.set_alpn(&[b"h3"]).unwrap();

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
        ExData {
            application_protos,
            crypto_ctx,
            session,
            local_error,
            keylog: None,
            trace_id: "",
            local_transport_params: crate::TransportParams::default(),
            recovery_config,
            tx_cap_factor,
            pmtud: None,
            is_server,
        }
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
