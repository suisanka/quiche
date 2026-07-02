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

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

use ::rustls::client::ClientSessionKey;
use ::rustls::client::ClientSessionStore;
use ::rustls::client::Tls12ClientSessionValue;
use ::rustls::client::Tls13ClientSessionValue;
use ::rustls::crypto::kx::NamedGroup;
use ::rustls::crypto::CipherSuite;
use ::rustls::crypto::Credentials;
use ::rustls::crypto::Identity;
use ::rustls::crypto::SignatureScheme;
use ::rustls::crypto::SingleCredential;
use ::rustls::crypto::TicketProducer;
use ::rustls::error::CertificateError;
use ::rustls::pki_types::pem::PemObject;
use ::rustls::pki_types::CertificateDer;
use ::rustls::pki_types::PrivateKeyDer;
use ::rustls::server::StoresServerSessions;
use ::rustls::DistinguishedName;
use ::rustls::RootCertStore;
use ::rustls::SupportedCipherSuite;
use aws_lc_rs::cipher::DecryptionContext;
use aws_lc_rs::cipher::PaddedBlockDecryptingKey;
use aws_lc_rs::cipher::PaddedBlockEncryptingKey;
use aws_lc_rs::cipher::UnboundCipherKey;
use aws_lc_rs::cipher::AES_128;
use aws_lc_rs::cipher::AES_CBC_IV_LEN;
use aws_lc_rs::hmac;
use aws_lc_rs::iv;
use aws_lc_rs::rand;
use aws_lc_rs::signature;

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
    server_session_storage: Arc<dyn StoresServerSessions>,
    ticket_producer: Option<Arc<dyn TicketProducer>>,
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
            verify: false,
            keylog_enabled: false,
            early_data_enabled: false,
            server_session_storage: Arc::new(QuicheServerSessionStore::new(256)),
            ticket_producer: None,
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
            server_session_storage: self.server_session_storage.clone(),
            ticket_producer: self.ticket_producer.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            is_server: None,
            server_name: None,
            local_transport_params: Vec::new(),
            conn: None,
            write_level: crypto::Level::Initial,
            early_data_active: false,
            signature_scheme: Arc::new(Mutex::new(None)),
            peer_identity_recorder: Arc::new(Mutex::new(None)),
            recorded_peer_identity: None,
            session_store: Arc::new(QuicheClientSessionStore::new()),
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

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.ticket_producer = Some(Arc::new(QuicheTicketProducer::new(key)?));

        Ok(())
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
    server_session_storage: Arc<dyn StoresServerSessions>,
    ticket_producer: Option<Arc<dyn TicketProducer>>,
    alpn_protocols: Vec<Vec<u8>>,
    is_server: Option<bool>,
    server_name: Option<String>,
    local_transport_params: Vec<u8>,
    conn: Option<::rustls::quic::Connection>,
    write_level: crypto::Level,
    early_data_active: bool,
    signature_scheme: Arc<Mutex<Option<SignatureScheme>>>,
    peer_identity_recorder: RecordedPeerIdentity,
    recorded_peer_identity: Option<Identity<'static>>,
    session_store: Arc<QuicheClientSessionStore>,
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
        let result = self.connection()?.read_hs(buf).map_err(|_| Error::TlsFail);
        self.flush_recorded_peer_identity();

        result
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        observe_ex_data(ex_data);
        self.sync_ex_data(ex_data);
        self.flush_handshake_data(ex_data)?;
        self.flush_recorded_peer_identity();
        self.flush_keylog(ex_data);
        self.flush_session(ex_data);

        match self.is_completed() {
            true => Ok(()),
            false => Err(Error::Done),
        }
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        self.flush_keylog(ex_data);
        self.flush_session(ex_data);

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
        self.conn = None;
        self.write_level = crypto::Level::Initial;
        self.early_data_active = false;
        if let Ok(mut scheme) = self.signature_scheme.lock() {
            *scheme = None;
        }
        if let Ok(mut identity) = self.peer_identity_recorder.lock() {
            *identity = None;
        }
        self.recorded_peer_identity = None;

        Ok(())
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        self.session_store.import_session(session)
    }

    pub fn curve(&self) -> Option<String> {
        self.conn
            .as_ref()?
            .negotiated_key_exchange_group()
            .map(|group| format!("{:?}", group.name()))
    }

    pub fn sigalg(&self) -> Option<String> {
        let scheme = self.signature_scheme.lock().ok()?.as_ref().copied()?;

        Some(format!("{scheme:?}"))
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        self.conn
            .as_ref()
            .and_then(|conn| conn.peer_identity())
            .or(self.recorded_peer_identity.as_ref())
            .and_then(peer_cert_chain)
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.conn
            .as_ref()
            .and_then(|conn| conn.peer_identity())
            .or(self.recorded_peer_identity.as_ref())
            .and_then(peer_cert)
    }

    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {}

    pub fn is_in_early_data(&self) -> bool {
        self.early_data_active
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

        let config_builder = match self.verify {
            true => {
                if self.root_store.is_empty() {
                    return Err(Error::TlsFail);
                }

                let root_store = Arc::new(self.root_store.clone());
                let verifier = ::rustls::client::WebPkiServerVerifier::builder(
                    root_store.clone(),
                    &self.provider,
                )
                .build()
                .map_err(|_| Error::TlsFail)?;

                ::rustls::ClientConfig::builder(Arc::clone(&self.provider))
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        RecordingServerVerifier::new(
                            Arc::new(verifier),
                            self.signature_scheme.clone(),
                            root_store,
                        ),
                    ))
            },

            false => ::rustls::ClientConfig::builder(Arc::clone(&self.provider))
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    NoCertificateVerification::new(
                        &self.provider,
                        self.signature_scheme.clone(),
                    ),
                )),
        };
        let mut config = self.finish_client_config(config_builder)?;

        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .cloned()
            .map(::rustls::enums::ApplicationProtocol::from)
            .collect();
        config.resumption =
            ::rustls::client::Resumption::store(self.session_store.clone());
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
        let config = self.build_server_config()?;

        let conn = ::rustls::quic::ServerConnection::new(
            Arc::new(config),
            ::rustls::quic::Version::V1,
            self.local_transport_params.clone(),
        )
        .map_err(|_| Error::TlsFail)?;

        Ok(conn.into())
    }

    fn build_server_config(&self) -> Result<::rustls::ServerConfig> {
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
        let config_builder =
            ::rustls::ServerConfig::builder(Arc::clone(&self.provider));
        let config_builder = match self.verify {
            true => {
                let verifier = if self.root_store.is_empty() {
                    RecordingClientVerifier::without_roots(
                        &self.provider,
                        self.signature_scheme.clone(),
                        self.peer_identity_recorder.clone(),
                    )
                } else {
                    let verifier =
                        ::rustls::server::WebPkiClientVerifier::builder(
                            Arc::new(self.root_store.clone()),
                            &self.provider,
                        )
                        .allow_unauthenticated()
                        .build()
                        .map_err(|_| Error::TlsFail)?;

                    RecordingClientVerifier::new(
                        Arc::new(verifier),
                        self.signature_scheme.clone(),
                        self.peer_identity_recorder.clone(),
                    )
                };

                config_builder.with_client_cert_verifier(Arc::new(verifier))
            },

            false => config_builder.with_no_client_auth(),
        };
        let mut config = config_builder
            .with_server_credential_resolver(Arc::new(SingleCredential::from(
                credentials,
            )))
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
        config.ticketer = match &self.ticket_producer {
            Some(ticket_producer) => Some(ticket_producer.clone()),

            None if self.early_data_enabled => None,

            None => Some(
                self.provider
                    .ticketer_factory
                    .ticketer()
                    .map_err(|_| Error::TlsFail)?,
            ),
        };
        config.session_storage = self.server_session_storage.clone();
        self.set_keylog(&mut config.key_log);

        Ok(config)
    }

    fn set_keylog(&self, key_log: &mut Arc<dyn ::rustls::KeyLog>) {
        if let Some(log) = &self.key_log {
            *key_log = log.clone();
        }
    }

    fn finish_client_config(
        &self,
        builder: ::rustls::ConfigBuilder<
            ::rustls::ClientConfig,
            ::rustls::client::WantsClientCert,
        >,
    ) -> Result<::rustls::ClientConfig> {
        match (&self.certificate_identity, &self.private_key) {
            (Some(identity), Some(private_key)) => {
                let signing_key = self
                    .provider
                    .key_provider
                    .load_private_key(private_key.clone_key())
                    .map_err(|_| Error::TlsFail)?;
                let credentials =
                    Credentials::new_unchecked(identity.clone(), signing_key);

                builder
                    .with_client_credential_resolver(Arc::new(
                        SingleCredential::from(credentials),
                    ))
                    .map_err(|_| Error::TlsFail)
            },

            (None, None) =>
                builder.with_no_client_auth().map_err(|_| Error::TlsFail),

            _ => Err(Error::TlsFail),
        }
    }

    fn flush_keylog(&self, ex_data: &mut ExData) {
        if let Some(key_log) = &self.key_log {
            key_log.drain(&mut ex_data.keylog);
        }
    }

    fn flush_session(&self, ex_data: &mut ExData) {
        if let Some(session) = self.session_store.take_exported_session() {
            *ex_data.session = Some(session);
        }
    }

    fn flush_recorded_peer_identity(&mut self) {
        if self.recorded_peer_identity.is_some() {
            return;
        }

        if let Ok(mut identity) = self.peer_identity_recorder.lock() {
            self.recorded_peer_identity = identity.take();
        }
    }

    fn sync_ex_data(&mut self, ex_data: &ExData) {
        if self.alpn_protocols != *ex_data.application_protos {
            self.alpn_protocols = ex_data.application_protos.clone();
        }
    }

    fn flush_handshake_data(&mut self, ex_data: &mut ExData) -> Result<()> {
        self.connection()?;
        self.install_zero_rtt_keys(ex_data);

        loop {
            let mut buf = Vec::new();
            let mut key_change = self.connection()?.write_hs(&mut buf);
            let mut consumed_key_change = false;
            self.install_zero_rtt_keys(ex_data);

            if matches!(
                key_change,
                Some(::rustls::quic::KeyChange::Handshake { .. })
            ) && self.write_level == crypto::Level::Initial &&
                !ex_data.is_server
            {
                let Some(::rustls::quic::KeyChange::Handshake { keys }) =
                    key_change.take()
                else {
                    unreachable!();
                };

                ex_data.crypto_ctx[packet::Epoch::Handshake].crypto_open =
                    Some(crypto::Open::from_rustls(keys.remote, None));
                ex_data.crypto_ctx[packet::Epoch::Handshake].crypto_seal =
                    Some(crypto::Seal::from_rustls(keys.local, None));

                self.write_level = crypto::Level::Handshake;
                consumed_key_change = true;
            }

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
                    if !ex_data.is_server {
                        self.early_data_active = false;
                    }
                },

                None if consumed_key_change => continue,

                None => break,
            }
        }

        Ok(())
    }

    fn install_zero_rtt_keys(&mut self, ex_data: &mut ExData) {
        let Some(keys) = self.conn.as_ref().and_then(|conn| conn.zero_rtt_keys())
        else {
            return;
        };

        let app_crypto = &mut ex_data.crypto_ctx[packet::Epoch::Application];

        if ex_data.is_server {
            if app_crypto.crypto_0rtt_open.is_none() {
                app_crypto.crypto_0rtt_open =
                    Some(crypto::Open::from_rustls(keys, None));
            }
            self.early_data_active = true;

            return;
        }

        if app_crypto.crypto_seal.is_none() {
            app_crypto.crypto_seal = Some(crypto::Seal::from_rustls(keys, None));
            self.early_data_active = true;
        }
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

fn certificate_name_error(error: &::rustls::Error) -> bool {
    matches!(
        error,
        ::rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName |
                CertificateError::NotValidForNameContext { .. }
        )
    )
}

fn unsupported_cert_version_error(error: &::rustls::Error) -> bool {
    matches!(
        error,
        ::rustls::Error::InvalidCertificate(CertificateError::Other(e))
            if format!("{e:?}").contains("UnsupportedCertVersion")
    )
}

fn common_name_matches_server_name(
    cert: &[u8], server_name: &::rustls::pki_types::ServerName<'_>,
) -> bool {
    let server_name = server_name.to_str();

    common_names(cert).any(|name| name.eq_ignore_ascii_case(&server_name))
}

fn common_names(cert: &[u8]) -> impl Iterator<Item = &str> {
    let subject = certificate_subject(cert).unwrap_or(&[]);

    DerReader::new(subject).flat_map(|set| {
        let Some((0x31, set)) = set else {
            return None;
        };

        let Some((0x30, attribute)) = DerReader::new(set).next().flatten() else {
            return None;
        };

        let mut attribute = DerReader::new(attribute);
        let Some((0x06, oid)) = attribute.next().flatten() else {
            return None;
        };

        let common_name_oid = [0x55, 0x04, 0x03];
        if oid != common_name_oid {
            return None;
        }

        let (tag, value) = attribute.next().flatten()?;
        match tag {
            0x0c | 0x13 | 0x16 => std::str::from_utf8(value).ok(),

            _ => None,
        }
    })
}

fn certificate_subject(cert: &[u8]) -> Option<&[u8]> {
    let mut cert = DerReader::new(cert);
    let Some((0x30, cert, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut cert = DerReader::new(cert);
    let Some((0x30, tbs, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut tbs = DerReader::new(tbs);

    if matches!(tbs.peek_tag(), Some(0xa0)) {
        tbs.next().flatten()?;
    }

    tbs.next().flatten()?;
    tbs.next().flatten()?;
    tbs.next().flatten()?;
    tbs.next().flatten()?;

    let Some((0x30, subject)) = tbs.next().flatten() else {
        return None;
    };

    Some(subject)
}

fn certificate_subject_public_key_info(cert: &[u8]) -> Option<&[u8]> {
    let mut cert = DerReader::new(cert);
    let Some((0x30, cert, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut cert = DerReader::new(cert);
    let Some((0x30, tbs, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut tbs = DerReader::new(tbs);

    if matches!(tbs.peek_tag(), Some(0xa0)) {
        tbs.next().flatten()?;
    }

    tbs.next().flatten()?;
    tbs.next().flatten()?;
    tbs.next().flatten()?;
    tbs.next().flatten()?;
    tbs.next().flatten()?;

    let Some((0x30, _, spki_raw)) = tbs.next_raw().flatten() else {
        return None;
    };

    Some(spki_raw)
}

struct LegacyCertificate<'a> {
    tbs: &'a [u8],
    signature_algorithm: &'a [u8],
    not_before: u64,
    not_after: u64,
    signature: &'a [u8],
}

fn legacy_v1_certificate(cert: &[u8]) -> Option<LegacyCertificate<'_>> {
    let mut cert = DerReader::new(cert);
    let Some((0x30, cert, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut cert = DerReader::new(cert);
    let Some((0x30, tbs, tbs_raw)) = cert.next_raw().flatten() else {
        return None;
    };
    let Some((0x30, signature_algorithm, _)) = cert.next_raw().flatten() else {
        return None;
    };
    let Some((0x03, signature, _)) = cert.next_raw().flatten() else {
        return None;
    };

    let mut tbs = DerReader::new(tbs);
    if matches!(tbs.peek_tag(), Some(0xa0)) {
        return None;
    }

    tbs.next().flatten()?;
    let Some((0x30, tbs_signature_algorithm)) = tbs.next().flatten() else {
        return None;
    };
    if tbs_signature_algorithm != signature_algorithm {
        return None;
    }

    let Some((0x30, _)) = tbs.next().flatten() else {
        return None;
    };
    let Some((0x30, validity)) = tbs.next().flatten() else {
        return None;
    };
    let mut validity = DerReader::new(validity);
    let (not_before_tag, not_before) = validity.next().flatten()?;
    let (not_after_tag, not_after) = validity.next().flatten()?;
    let not_before = der_time(not_before_tag, not_before)?;
    let not_after = der_time(not_after_tag, not_after)?;

    tbs.next().flatten()?;
    let Some((0x30, ..)) = tbs.next_raw().flatten() else {
        return None;
    };

    let signature = match signature {
        [0, signature @ ..] => signature,

        _ => return None,
    };

    Some(LegacyCertificate {
        tbs: tbs_raw,
        signature_algorithm,
        not_before,
        not_after,
        signature,
    })
}

fn valid_at(
    cert: &LegacyCertificate<'_>, now: ::rustls::pki_types::UnixTime,
) -> bool {
    cert.not_before <= now.as_secs() && now.as_secs() <= cert.not_after
}

fn legacy_v1_server_identity_valid(
    root_store: &RootCertStore, identity: &Identity<'_>,
    server_name: &::rustls::pki_types::ServerName<'_>,
    now: ::rustls::pki_types::UnixTime,
) -> bool {
    let Identity::X509(certificates) = identity else {
        return false;
    };

    if !certificates.intermediates.is_empty() ||
        !common_name_matches_server_name(
            certificates.end_entity.as_ref(),
            server_name,
        )
    {
        return false;
    }

    let Some(cert) = legacy_v1_certificate(certificates.end_entity.as_ref())
    else {
        return false;
    };

    if !valid_at(&cert, now) ||
        !legacy_sha256_rsa_signature_algorithm(cert.signature_algorithm)
    {
        return false;
    }

    root_store.roots.iter().any(|root| {
        if root.name_constraints.is_some() {
            return false;
        }

        let public_key = der_sequence(root.subject_public_key_info.as_ref());
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            public_key,
        )
        .verify(cert.tbs, cert.signature)
        .is_ok()
    })
}

fn legacy_sha256_rsa_signature_algorithm(algorithm: &[u8]) -> bool {
    let mut algorithm = DerReader::new(algorithm);
    let Some((0x06, oid)) = algorithm.next().flatten() else {
        return false;
    };

    oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
}

fn legacy_handshake_signature_algorithm(
    scheme: SignatureScheme,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    Some(match scheme {
        SignatureScheme::RSA_PKCS1_SHA1 =>
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,

        SignatureScheme::RSA_PKCS1_SHA256 =>
            &signature::RSA_PKCS1_2048_8192_SHA256,

        SignatureScheme::RSA_PKCS1_SHA384 =>
            &signature::RSA_PKCS1_2048_8192_SHA384,

        SignatureScheme::RSA_PKCS1_SHA512 =>
            &signature::RSA_PKCS1_2048_8192_SHA512,

        SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_2048_8192_SHA256,

        SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_2048_8192_SHA384,

        SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_2048_8192_SHA512,

        SignatureScheme::ECDSA_NISTP256_SHA256 =>
            &signature::ECDSA_P256_SHA256_ASN1,

        SignatureScheme::ECDSA_NISTP384_SHA384 =>
            &signature::ECDSA_P384_SHA384_ASN1,

        SignatureScheme::ECDSA_NISTP521_SHA512 =>
            &signature::ECDSA_P521_SHA512_ASN1,

        SignatureScheme::ED25519 => &signature::ED25519,

        _ => return None,
    })
}

fn legacy_handshake_signature_valid(
    input: &::rustls::client::danger::SignatureVerificationInput,
) -> bool {
    let Some(algorithm) =
        legacy_handshake_signature_algorithm(input.signature.scheme)
    else {
        return false;
    };

    let Some(public_key) = (match input.signer {
        ::rustls::SignerPublicKey::X509(cert) => {
            if legacy_v1_certificate(cert.as_ref()).is_none() {
                return false;
            }

            certificate_subject_public_key_info(cert.as_ref())
        },

        ::rustls::SignerPublicKey::RawPublicKey(spki) => Some(spki.as_ref()),

        _ => None,
    }) else {
        return false;
    };

    signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(input.message, input.signature.signature())
        .is_ok()
}

fn der_time(tag: u8, value: &[u8]) -> Option<u64> {
    let (year, value) = match (tag, value.len()) {
        (0x17, 13) => {
            let year = decimal(&value[..2])?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };

            (year, &value[2..])
        },

        (0x18, 15) => (decimal(&value[..4])?, &value[4..]),

        _ => return None,
    };

    if value.last().copied() != Some(b'Z') {
        return None;
    }

    let month = decimal(&value[0..2])?;
    let day = decimal(&value[2..4])?;
    let hour = decimal(&value[4..6])?;
    let minute = decimal(&value[6..8])?;
    let second = decimal(&value[8..10])?;

    unix_time(year as i64, month, day, hour, minute, second)
}

fn decimal(input: &[u8]) -> Option<u32> {
    input.iter().try_fold(0u32, |value, b| {
        b.is_ascii_digit()
            .then_some(value * 10 + u32::from(b - b'0'))
    })
}

fn unix_time(
    year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32,
) -> Option<u64> {
    if !(1..=12).contains(&month) ||
        day == 0 ||
        day > days_in_month(year, month)? ||
        hour > 23 ||
        minute > 59 ||
        second > 59
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;

    u64::try_from(seconds).ok()
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,

        4 | 6 | 9 | 11 => 30,

        2 if leap_year(year) => 29,

        2 => 28,

        _ => return None,
    })
}

fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(mut year: i64, month: u32, day: u32) -> Option<i64> {
    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year =
        (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn der_sequence(value: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(value.len() + 5);
    der.push(0x30);
    encode_der_len(value.len(), &mut der);
    der.extend_from_slice(value);

    der
}

fn encode_der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }

    let len_bytes = len.to_be_bytes();
    let first = len_bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(len_bytes.len() - 1);
    out.push(0x80 | u8::try_from(len_bytes.len() - first).unwrap_or(0));
    out.extend_from_slice(&len_bytes[first..]);
}

struct DerReader<'a> {
    input: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.first().copied()
    }

    fn next_raw(&mut self) -> Option<Option<(u8, &'a [u8], &'a [u8])>> {
        let original = self.input;
        let tag = *self.input.first()?;
        let len_start = 1;
        let first_len = *self.input.get(len_start)?;
        let (len, len_size) = if first_len & 0x80 == 0 {
            (first_len as usize, 1)
        } else {
            let len_len = (first_len & 0x7f) as usize;
            if len_len == 0 || self.input.len() < len_start + 1 + len_len {
                self.input = &[];
                return Some(None);
            }

            let mut len = 0usize;
            for b in &self.input[len_start + 1..len_start + 1 + len_len] {
                len = len.checked_mul(256)?.checked_add(*b as usize)?;
            }

            (len, 1 + len_len)
        };

        let value_start = len_start + len_size;
        let value_end = value_start.checked_add(len)?;
        if self.input.len() < value_end {
            self.input = &[];
            return Some(None);
        }

        let value = &self.input[value_start..value_end];
        self.input = &self.input[value_end..];

        Some(Some((tag, value, &original[..value_end])))
    }
}

impl<'a> Iterator for DerReader<'a> {
    type Item = Option<(u8, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_raw()
            .map(|item| item.map(|(tag, value, _)| (tag, value)))
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

struct QuicheServerSessionStore {
    sessions: Mutex<VecDeque<(Vec<u8>, Vec<u8>)>>,
    capacity: usize,
}

impl QuicheServerSessionStore {
    fn new(capacity: usize) -> Self {
        Self {
            sessions: Mutex::new(VecDeque::new()),
            capacity,
        }
    }
}

impl fmt::Debug for QuicheServerSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicheServerSessionStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl StoresServerSessions for QuicheServerSessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let Ok(mut sessions) = self.sessions.lock() else {
            return false;
        };

        if let Some(index) =
            sessions.iter().position(|(existing, _)| *existing == key)
        {
            sessions.remove(index);
        }

        if sessions.len() == self.capacity {
            sessions.pop_front();
        }

        sessions.push_back((key, value));

        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.sessions
            .lock()
            .ok()?
            .iter()
            .find(|(existing, _)| existing.as_slice() == key)
            .map(|(_, value)| value.clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().ok()?;
        let index = sessions
            .iter()
            .position(|(existing, _)| existing.as_slice() == key)?;

        sessions.remove(index).map(|(_, value)| value)
    }

    fn can_cache(&self) -> bool {
        self.capacity > 0
    }
}

const RUSTLS_SESSION_TOKEN_LEN: usize = 16;
const MAX_RUSTLS_SESSIONS: usize = 1024;
const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

type RustlsSessionToken = [u8; RUSTLS_SESSION_TOKEN_LEN];

struct RegisteredRustlsSession {
    key: ClientSessionKey<'static>,
    value: Tls13ClientSessionValue,
}

static RUSTLS_SESSION_REGISTRY: OnceLock<
    Mutex<HashMap<RustlsSessionToken, RegisteredRustlsSession>>,
> = OnceLock::new();

fn rustls_session_registry(
) -> &'static Mutex<HashMap<RustlsSessionToken, RegisteredRustlsSession>> {
    RUSTLS_SESSION_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Default)]
struct ClientSessionData {
    kx_hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tls13: VecDeque<Tls13ClientSessionValue>,
}

#[derive(Default)]
struct QuicheClientSessionStore {
    sessions: Mutex<HashMap<ClientSessionKey<'static>, ClientSessionData>>,
    exported_session: Mutex<Option<Vec<u8>>>,
}

impl QuicheClientSessionStore {
    fn new() -> Self {
        Self::default()
    }

    fn import_session(&self, session: &[u8]) -> Result<()> {
        if session.len() != RUSTLS_SESSION_TOKEN_LEN {
            return Err(Error::TlsFail);
        }

        let mut token = [0; RUSTLS_SESSION_TOKEN_LEN];
        token.copy_from_slice(session);

        let registered = rustls_session_registry()
            .lock()
            .map_err(|_| Error::TlsFail)?
            .remove(&token)
            .ok_or(Error::TlsFail)?;

        self.insert_imported_tls13_ticket(registered.key, registered.value);

        Ok(())
    }

    fn take_exported_session(&self) -> Option<Vec<u8>> {
        self.exported_session.lock().ok()?.take()
    }

    fn export_tls13_ticket(
        &self, key: ClientSessionKey<'static>, value: Tls13ClientSessionValue,
    ) {
        let peer_params = value.quic_params();
        let Some(token) = register_rustls_session(key, value) else {
            return;
        };

        if let Ok(mut session) = self.exported_session.lock() {
            *session = Some(encode_quiche_session(&token, &peer_params));
        }
    }

    fn insert_imported_tls13_ticket(
        &self, key: ClientSessionKey<'static>, value: Tls13ClientSessionValue,
    ) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let session = sessions.entry(key).or_default();
            if session.tls13.len() == MAX_TLS13_TICKETS_PER_SERVER {
                session.tls13.pop_front();
            }

            session.tls13.push_back(value);
        }
    }
}

impl fmt::Debug for QuicheClientSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicheClientSessionStore")
            .finish_non_exhaustive()
    }
}

impl ClientSessionStore for QuicheClientSessionStore {
    fn set_kx_hint(&self, key: ClientSessionKey<'static>, group: NamedGroup) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.entry(key).or_default().kx_hint = Some(group);
        }
    }

    fn kx_hint(&self, key: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        self.sessions
            .lock()
            .ok()?
            .get(key)
            .and_then(|session| session.kx_hint)
    }

    fn set_tls12_session(
        &self, key: ClientSessionKey<'static>, value: Tls12ClientSessionValue,
    ) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.entry(key).or_default().tls12 = Some(value);
        }
    }

    fn tls12_session(
        &self, key: &ClientSessionKey<'_>,
    ) -> Option<Tls12ClientSessionValue> {
        self.sessions
            .lock()
            .ok()?
            .get(key)
            .and_then(|session| session.tls12.as_ref().cloned())
    }

    fn remove_tls12_session(&self, key: &ClientSessionKey<'static>) {
        if let Ok(mut sessions) = self.sessions.lock() {
            if let Some(session) = sessions.get_mut(key) {
                session.tls12 = None;
            }
        }
    }

    fn insert_tls13_ticket(
        &self, key: ClientSessionKey<'static>, value: Tls13ClientSessionValue,
    ) {
        self.export_tls13_ticket(key, value);
    }

    fn take_tls13_ticket(
        &self, key: &ClientSessionKey<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.sessions
            .lock()
            .ok()?
            .get_mut(key)
            .and_then(|session| session.tls13.pop_back())
    }
}

fn register_rustls_session(
    key: ClientSessionKey<'static>, value: Tls13ClientSessionValue,
) -> Option<RustlsSessionToken> {
    let mut token = [0; RUSTLS_SESSION_TOKEN_LEN];
    rand::fill(&mut token).ok()?;

    let mut registry = rustls_session_registry().lock().ok()?;
    if registry.len() >= MAX_RUSTLS_SESSIONS {
        let first_key = *registry.keys().next()?;
        registry.remove(&first_key);
    }

    registry.insert(token, RegisteredRustlsSession { key, value });

    Some(token)
}

fn encode_quiche_session(session: &[u8], peer_params: &[u8]) -> Vec<u8> {
    let mut buffer =
        Vec::with_capacity(8 + session.len() + 8 + peer_params.len());

    buffer.extend_from_slice(&(session.len() as u64).to_be_bytes());
    buffer.extend_from_slice(session);
    buffer.extend_from_slice(&(peer_params.len() as u64).to_be_bytes());
    buffer.extend_from_slice(peer_params);

    buffer
}

const TICKET_KEY_LEN: usize = 48;
const TICKET_KEY_NAME_LEN: usize = 16;
const TICKET_HMAC_KEY_LEN: usize = 16;
const TICKET_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TICKET_CIPHERTEXT_LEN: usize = u16::MAX as usize;

struct QuicheTicketProducer {
    key_name: [u8; TICKET_KEY_NAME_LEN],
    hmac_key: hmac::Key,
    aes_encrypt_key: PaddedBlockEncryptingKey,
    aes_decrypt_key: PaddedBlockDecryptingKey,
}

impl QuicheTicketProducer {
    fn new(key: &[u8]) -> Result<Self> {
        if key.len() != TICKET_KEY_LEN {
            return Err(Error::TlsFail);
        }

        let mut key_name = [0; TICKET_KEY_NAME_LEN];
        key_name.copy_from_slice(&key[..TICKET_KEY_NAME_LEN]);
        let hmac_key = hmac::Key::new(
            hmac::HMAC_SHA256,
            &key[TICKET_KEY_NAME_LEN..TICKET_KEY_NAME_LEN + TICKET_HMAC_KEY_LEN],
        );
        let aes_key = &key[TICKET_KEY_NAME_LEN + TICKET_HMAC_KEY_LEN..];

        let aes_encrypt_key = UnboundCipherKey::new(&AES_128, aes_key)
            .map_err(|_| Error::TlsFail)?;
        let aes_encrypt_key =
            PaddedBlockEncryptingKey::cbc_pkcs7(aes_encrypt_key)
                .map_err(|_| Error::TlsFail)?;
        let aes_decrypt_key = UnboundCipherKey::new(&AES_128, aes_key)
            .map_err(|_| Error::TlsFail)?;
        let aes_decrypt_key =
            PaddedBlockDecryptingKey::cbc_pkcs7(aes_decrypt_key)
                .map_err(|_| Error::TlsFail)?;

        Ok(Self {
            key_name,
            hmac_key,
            aes_encrypt_key,
            aes_decrypt_key,
        })
    }
}

impl TicketProducer for QuicheTicketProducer {
    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        let mut encrypted_state = Vec::from(message);
        let dec_ctx = self.aes_encrypt_key.encrypt(&mut encrypted_state).ok()?;
        let iv: &[u8] = (&dec_ctx).try_into().ok()?;

        let mut hmac_data = Vec::with_capacity(
            self.key_name.len() + iv.len() + 2 + encrypted_state.len(),
        );
        hmac_data.extend_from_slice(&self.key_name);
        hmac_data.extend_from_slice(iv);
        hmac_data.extend_from_slice(
            &u16::try_from(encrypted_state.len()).ok()?.to_be_bytes(),
        );
        hmac_data.extend_from_slice(&encrypted_state);
        let tag = hmac::sign(&self.hmac_key, &hmac_data);

        let mut ciphertext = Vec::with_capacity(
            self.key_name.len() +
                iv.len() +
                encrypted_state.len() +
                tag.as_ref().len(),
        );
        ciphertext.extend_from_slice(&self.key_name);
        ciphertext.extend_from_slice(iv);
        ciphertext.extend_from_slice(&encrypted_state);
        ciphertext.extend_from_slice(tag.as_ref());

        Some(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() > MAX_TICKET_CIPHERTEXT_LEN {
            return None;
        }

        let (key_name, ciphertext) =
            ciphertext.split_at_checked(TICKET_KEY_NAME_LEN)?;
        if key_name != self.key_name {
            return None;
        }

        let (iv, ciphertext) = ciphertext.split_at_checked(AES_CBC_IV_LEN)?;
        let tag_len = self.hmac_key.algorithm().digest_algorithm().output_len();
        let encrypted_len = ciphertext.len().checked_sub(tag_len)?;
        let (encrypted_state, tag) =
            ciphertext.split_at_checked(encrypted_len)?;

        let mut hmac_data = Vec::with_capacity(
            key_name.len() + iv.len() + 2 + encrypted_state.len(),
        );
        hmac_data.extend_from_slice(key_name);
        hmac_data.extend_from_slice(iv);
        hmac_data.extend_from_slice(
            &u16::try_from(encrypted_state.len()).ok()?.to_be_bytes(),
        );
        hmac_data.extend_from_slice(encrypted_state);
        hmac::verify(&self.hmac_key, &hmac_data, tag).ok()?;

        let iv = iv::FixedLength::try_from(iv).ok()?;
        let mut out = Vec::from(encrypted_state);
        let plaintext = self
            .aes_decrypt_key
            .decrypt(&mut out, DecryptionContext::Iv128(iv))
            .ok()?;

        Some(plaintext.into())
    }

    fn lifetime(&self) -> Duration {
        TICKET_LIFETIME
    }
}

impl fmt::Debug for QuicheTicketProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicheTicketProducer")
            .finish_non_exhaustive()
    }
}

type RecordedSignatureScheme = Arc<Mutex<Option<SignatureScheme>>>;
type RecordedPeerIdentity = Arc<Mutex<Option<Identity<'static>>>>;

fn record_signature_scheme(
    signature_scheme: &RecordedSignatureScheme,
    input: &::rustls::client::danger::SignatureVerificationInput,
) {
    if let Ok(mut scheme) = signature_scheme.lock() {
        *scheme = Some(input.signature.scheme);
    }
}

#[derive(Debug)]
struct RecordingServerVerifier {
    inner: Arc<dyn ::rustls::client::danger::ServerVerifier>,
    signature_scheme: RecordedSignatureScheme,
    root_store: Arc<RootCertStore>,
}

impl RecordingServerVerifier {
    fn new(
        inner: Arc<dyn ::rustls::client::danger::ServerVerifier>,
        signature_scheme: RecordedSignatureScheme,
        root_store: Arc<RootCertStore>,
    ) -> Self {
        Self {
            inner,
            signature_scheme,
            root_store,
        }
    }

    fn verify_identity_with_cn_fallback(
        &self, identity: &::rustls::client::danger::ServerIdentity,
        error: ::rustls::Error,
    ) -> std::result::Result<
        ::rustls::client::danger::PeerVerified,
        ::rustls::Error,
    > {
        if !certificate_name_error(&error) {
            return Err(error);
        }

        let Identity::X509(certificates) = identity.identity else {
            return Err(error);
        };

        if common_name_matches_server_name(
            certificates.end_entity.as_ref(),
            identity.server_name,
        ) {
            return Ok(::rustls::client::danger::PeerVerified::assertion());
        }

        Err(error)
    }

    fn verify_legacy_v1_identity(
        &self, identity: &::rustls::client::danger::ServerIdentity,
    ) -> bool {
        legacy_v1_server_identity_valid(
            &self.root_store,
            identity.identity,
            identity.server_name,
            identity.now,
        )
    }

    fn verify_legacy_v1_signature(
        &self, input: &::rustls::client::danger::SignatureVerificationInput,
        error: ::rustls::Error,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        if unsupported_cert_version_error(&error) &&
            legacy_handshake_signature_valid(input)
        {
            record_signature_scheme(&self.signature_scheme, input);

            return Ok(
                ::rustls::client::danger::HandshakeSignatureValid::assertion(),
            );
        }

        Err(error)
    }
}

impl ::rustls::client::danger::ServerVerifier for RecordingServerVerifier {
    fn verify_identity(
        &self, identity: &::rustls::client::danger::ServerIdentity,
    ) -> std::result::Result<
        ::rustls::client::danger::PeerVerified,
        ::rustls::Error,
    > {
        match self.inner.verify_identity(identity) {
            Ok(verified) => Ok(verified),

            Err(e) => {
                if unsupported_cert_version_error(&e) &&
                    self.verify_legacy_v1_identity(identity)
                {
                    return Ok(
                        ::rustls::client::danger::PeerVerified::assertion(),
                    );
                }

                self.verify_identity_with_cn_fallback(identity, e)
            },
        }
    }

    fn verify_tls12_signature(
        &self, input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        match self.inner.verify_tls12_signature(input) {
            Ok(verified) => {
                record_signature_scheme(&self.signature_scheme, input);

                Ok(verified)
            },

            Err(e) => self.verify_legacy_v1_signature(input, e),
        }
    }

    fn verify_tls13_signature(
        &self, input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        match self.inner.verify_tls13_signature(input) {
            Ok(verified) => {
                record_signature_scheme(&self.signature_scheme, input);

                Ok(verified)
            },

            Err(e) => self.verify_legacy_v1_signature(input, e),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        self.inner.request_ocsp_response()
    }

    fn supported_certificate_types(
        &self,
    ) -> &'static [::rustls::enums::CertificateType] {
        self.inner.supported_certificate_types()
    }

    fn root_hint_subjects(&self) -> Option<Arc<[DistinguishedName]>> {
        self.inner.root_hint_subjects()
    }

    fn hash_config(&self, h: &mut dyn std::hash::Hasher) {
        self.inner.hash_config(h);
    }
}

#[derive(Debug)]
struct RecordingClientVerifier {
    inner: Option<Arc<dyn ::rustls::server::danger::ClientVerifier>>,
    signature_scheme: RecordedSignatureScheme,
    peer_identity: RecordedPeerIdentity,
    supported_schemes: Vec<SignatureScheme>,
}

impl RecordingClientVerifier {
    fn new(
        inner: Arc<dyn ::rustls::server::danger::ClientVerifier>,
        signature_scheme: RecordedSignatureScheme,
        peer_identity: RecordedPeerIdentity,
    ) -> Self {
        let supported_schemes = inner.supported_verify_schemes();

        Self {
            inner: Some(inner),
            signature_scheme,
            peer_identity,
            supported_schemes,
        }
    }

    fn without_roots(
        provider: &::rustls::crypto::CryptoProvider,
        signature_scheme: RecordedSignatureScheme,
        peer_identity: RecordedPeerIdentity,
    ) -> Self {
        Self {
            inner: None,
            signature_scheme,
            peer_identity,
            supported_schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }

    fn record_peer_identity(
        &self, identity: &::rustls::server::danger::ClientIdentity,
    ) {
        if let Ok(mut peer_identity) = self.peer_identity.lock() {
            *peer_identity = Some(identity.identity.clone().into_owned());
        }
    }
}

impl ::rustls::server::danger::ClientVerifier for RecordingClientVerifier {
    fn verify_identity(
        &self, identity: &::rustls::server::danger::ClientIdentity,
    ) -> std::result::Result<
        ::rustls::server::danger::PeerVerified,
        ::rustls::Error,
    > {
        self.record_peer_identity(identity);

        match &self.inner {
            Some(inner) => inner.verify_identity(identity),

            None => Err(CertificateError::UnknownIssuer.into()),
        }
    }

    fn verify_tls12_signature(
        &self, input: &::rustls::server::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        let result = match &self.inner {
            Some(inner) => inner.verify_tls12_signature(input),

            None => Err(CertificateError::UnknownIssuer.into()),
        };
        if result.is_ok() {
            record_signature_scheme(&self.signature_scheme, input);
        }

        result
    }

    fn verify_tls13_signature(
        &self, input: &::rustls::server::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        let result = match &self.inner {
            Some(inner) => inner.verify_tls13_signature(input),

            None => Err(CertificateError::UnknownIssuer.into()),
        };
        if result.is_ok() {
            record_signature_scheme(&self.signature_scheme, input);
        }

        result
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        match &self.inner {
            Some(inner) => inner.root_hint_subjects(),

            None => Arc::from([]),
        }
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.client_auth_mandatory())
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes.clone()
    }

    fn supported_certificate_types(
        &self,
    ) -> &'static [::rustls::enums::CertificateType] {
        match &self.inner {
            Some(inner) => inner.supported_certificate_types(),

            None => &[::rustls::enums::CertificateType::X509],
        }
    }
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported_schemes: Vec<::rustls::crypto::SignatureScheme>,
    signature_scheme: RecordedSignatureScheme,
}

impl NoCertificateVerification {
    fn new(
        provider: &::rustls::crypto::CryptoProvider,
        signature_scheme: RecordedSignatureScheme,
    ) -> Self {
        Self {
            supported_schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
            signature_scheme,
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
        &self, input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        record_signature_scheme(&self.signature_scheme, input);

        Ok(::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, input: &::rustls::client::danger::SignatureVerificationInput,
    ) -> std::result::Result<
        ::rustls::client::danger::HandshakeSignatureValid,
        ::rustls::Error,
    > {
        record_signature_scheme(&self.signature_scheme, input);

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
    use ::rustls::server::danger::ClientVerifier as _;

    use super::*;

    const EXAMPLE_CERT: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/cert.crt");
    const EXAMPLE_KEY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/cert.key");
    const EXAMPLE_ROOT: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/rootca.crt");

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
            ctx.use_certificate_chain_file(EXAMPLE_CERT).unwrap();
            ctx.use_privkey_file(EXAMPLE_KEY).unwrap();
        }

        handshake_from_context(ctx, is_server)
    }

    fn handshake_from_context(
        mut ctx: Context, is_server: bool,
    ) -> (Handshake, [packet::CryptoContext; 3]) {
        handshake_from_context_mut(&mut ctx, is_server)
    }

    fn handshake_from_context_mut(
        ctx: &mut Context, is_server: bool,
    ) -> (Handshake, [packet::CryptoContext; 3]) {
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

    fn drain_crypto_if_available(
        crypto_ctx: &mut [packet::CryptoContext; 3], epoch: packet::Epoch,
    ) -> Vec<u8> {
        match crypto_ctx[epoch].data_available() {
            true => drain_crypto(crypto_ctx, epoch),
            false => Vec::new(),
        }
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
    fn certificate_common_name_matches_dns_name() {
        let cert = example_cert_chain().remove(0);
        let server_name =
            ::rustls::pki_types::ServerName::try_from("quic.tech").unwrap();

        assert!(common_name_matches_server_name(&cert, &server_name));
    }

    #[test]
    fn legacy_v1_example_cert_verifies_against_root() {
        let mut ctx = Context::new().unwrap();
        ctx.load_verify_locations_from_file(EXAMPLE_ROOT).unwrap();

        let cert = example_cert_chain().remove(0);
        let legacy = legacy_v1_certificate(&cert).unwrap();
        let now = ::rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1_800_000_000),
        );

        assert!(valid_at(&legacy, now));
        assert!(legacy_sha256_rsa_signature_algorithm(
            legacy.signature_algorithm
        ));
        assert!(ctx.root_store.roots.iter().any(|root| {
            let public_key = der_sequence(root.subject_public_key_info.as_ref());
            signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                public_key,
            )
            .verify(legacy.tbs, legacy.signature)
            .is_ok()
        }));

        let identity =
            Identity::from_cert_chain(vec![CertificateDer::from(cert)]).unwrap();
        let server_name =
            ::rustls::pki_types::ServerName::try_from("quic.tech").unwrap();

        assert!(legacy_v1_server_identity_valid(
            &ctx.root_store,
            &identity,
            &server_name,
            now
        ));
    }

    #[test]
    fn empty_root_client_verifier_requests_optional_auth() {
        let verifier = RecordingClientVerifier::without_roots(
            &rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER,
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
        );

        assert!(verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
        assert!(verifier.root_hint_subjects().is_empty());
    }

    fn server_context_with_ticket_key() -> Context {
        let mut server_ctx = Context::new().unwrap();
        server_ctx.set_verify(false);
        server_ctx.set_alpn(&[b"h3"]).unwrap();
        server_ctx.use_certificate_chain_file(EXAMPLE_CERT).unwrap();
        server_ctx.use_privkey_file(EXAMPLE_KEY).unwrap();
        server_ctx.set_ticket_key(&[0x0a; TICKET_KEY_LEN]).unwrap();

        server_ctx
    }

    fn drive_full_handshake(
        client: &mut Handshake,
        client_crypto_ctx: &mut [packet::CryptoContext; 3],
        server: &mut Handshake,
        server_crypto_ctx: &mut [packet::CryptoContext; 3],
    ) -> Option<Vec<u8>> {
        drive_full_handshake_with_protos(
            client,
            client_crypto_ctx,
            server,
            server_crypto_ctx,
            vec![b"h3".to_vec()],
        )
    }

    fn drive_full_handshake_with_protos(
        client: &mut Handshake,
        client_crypto_ctx: &mut [packet::CryptoContext; 3],
        server: &mut Handshake,
        server_crypto_ctx: &mut [packet::CryptoContext; 3],
        application_protos: Vec<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let mut client_session = None;
        let mut server_session = None;
        let mut client_error = None;
        let mut server_error = None;

        {
            let mut client_ex_data = ex_data(
                client_crypto_ctx,
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
            drain_crypto(client_crypto_ctx, packet::Epoch::Initial);
        server
            .provide_data(crypto::Level::Initial, &client_initial)
            .unwrap();

        let mut server_application = Vec::new();

        {
            let mut server_ex_data = ex_data(
                server_crypto_ctx,
                true,
                &application_protos,
                &mut server_session,
                &mut server_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert!(matches!(
                server.do_handshake(&mut server_ex_data),
                Ok(()) | Err(Error::Done)
            ));
        }

        let server_initial =
            drain_crypto(server_crypto_ctx, packet::Epoch::Initial);
        let server_handshake =
            drain_crypto(server_crypto_ctx, packet::Epoch::Handshake);
        server_application.extend_from_slice(&drain_crypto_if_available(
            server_crypto_ctx,
            packet::Epoch::Application,
        ));

        client
            .provide_data(crypto::Level::Initial, &server_initial)
            .unwrap();
        client
            .provide_data(crypto::Level::Handshake, &server_handshake)
            .unwrap();

        {
            let mut client_ex_data = ex_data(
                client_crypto_ctx,
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

        let client_handshake = drain_crypto_if_available(
            client_crypto_ctx,
            packet::Epoch::Handshake,
        );
        if !client_handshake.is_empty() {
            server
                .provide_data(crypto::Level::Handshake, &client_handshake)
                .unwrap();

            let mut server_ex_data = ex_data(
                server_crypto_ctx,
                true,
                &application_protos,
                &mut server_session,
                &mut server_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert!(matches!(
                server.do_handshake(&mut server_ex_data),
                Ok(()) | Err(Error::Done)
            ));
            server_application.extend_from_slice(&drain_crypto_if_available(
                server_crypto_ctx,
                packet::Epoch::Application,
            ));
        }

        if !server_application.is_empty() {
            client
                .provide_data(crypto::Level::OneRTT, &server_application)
                .unwrap();

            let mut client_ex_data = ex_data(
                client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config,
                config.tx_cap_factor,
            );
            assert!(matches!(
                client.do_handshake(&mut client_ex_data),
                Ok(()) | Err(Error::Done)
            ));
            client.process_post_handshake(&mut client_ex_data).unwrap();
        }

        client_session
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
    fn handshake_clear_restarts_client_initial() {
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let application_protos = vec![b"h3".to_vec()];
        let mut session = None;
        let mut local_error = None;
        let (mut handshake, mut crypto_ctx) = handshake(false);

        {
            let mut ex_data = ex_data(
                &mut crypto_ctx,
                false,
                &application_protos,
                &mut session,
                &mut local_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert_eq!(handshake.do_handshake(&mut ex_data), Err(Error::Done));
        }

        assert_eq!(handshake.write_level(), crypto::Level::Initial);
        assert!(!drain_crypto(&mut crypto_ctx, packet::Epoch::Initial).is_empty());

        handshake.clear().unwrap();

        {
            let mut ex_data = ex_data(
                &mut crypto_ctx,
                false,
                &application_protos,
                &mut session,
                &mut local_error,
                recovery_config,
                config.tx_cap_factor,
            );
            assert_eq!(handshake.do_handshake(&mut ex_data), Err(Error::Done));
        }

        assert_eq!(handshake.write_level(), crypto::Level::Initial);
        assert!(!drain_crypto(&mut crypto_ctx, packet::Epoch::Initial).is_empty());
    }

    #[test]
    fn handshake_clear_resets_early_data_state() {
        let (mut handshake, _crypto_ctx) = handshake(false);
        handshake.early_data_active = true;
        *handshake.signature_scheme.lock().unwrap() =
            Some(SignatureScheme::ECDSA_NISTP256_SHA256);

        assert!(handshake.is_in_early_data());
        assert!(handshake.sigalg().is_some());

        handshake.clear().unwrap();

        assert!(!handshake.is_in_early_data());
        assert!(handshake.sigalg().is_none());
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
        assert!(client.sigalg().is_some());
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
    fn server_context_builds_with_optional_client_auth() {
        let mut server_ctx = Context::new().unwrap();
        server_ctx.set_verify(true);
        server_ctx.set_alpn(&[b"h3"]).unwrap();
        server_ctx
            .load_verify_locations_from_file(EXAMPLE_ROOT)
            .unwrap();
        server_ctx.use_certificate_chain_file(EXAMPLE_CERT).unwrap();
        server_ctx.use_privkey_file(EXAMPLE_KEY).unwrap();

        let (server, _server_crypto_ctx) =
            handshake_from_context(server_ctx, true);

        assert!(server.build_server_connection().is_ok());
    }

    #[test]
    fn server_config_enables_stateless_tickets() {
        let (server, _server_crypto_ctx) = handshake(true);
        let config = server.build_server_config().unwrap();

        assert!(config.ticketer.is_some());
    }

    #[test]
    fn set_ticket_key_rejects_invalid_lengths() {
        let mut ctx = Context::new().unwrap();

        assert_eq!(
            ctx.set_ticket_key(&[0; TICKET_KEY_LEN - 1]),
            Err(Error::TlsFail)
        );
        assert_eq!(
            ctx.set_ticket_key(&[0; TICKET_KEY_LEN + 1]),
            Err(Error::TlsFail)
        );
    }

    #[test]
    fn set_ticket_key_configures_fixed_ticket_producer() {
        let server_ctx = server_context_with_ticket_key();

        let (server, _server_crypto_ctx) =
            handshake_from_context(server_ctx, true);
        let config = server.build_server_config().unwrap();
        let ticketer = config.ticketer.as_ref().unwrap();
        let ticket_state = b"ticket state";

        let ciphertext = ticketer.encrypt(ticket_state).unwrap();
        assert_eq!(ticketer.decrypt(&ciphertext).unwrap(), ticket_state);

        let mut wrong_key_name = ciphertext;
        wrong_key_name[0] ^= 0x01;
        assert!(ticketer.decrypt(&wrong_key_name).is_none());
    }

    #[test]
    fn client_session_token_can_resume_handshake() {
        let (mut client, mut client_crypto_ctx) = handshake(false);
        let (mut server, mut server_crypto_ctx) =
            handshake_from_context(server_context_with_ticket_key(), true);

        let session = drive_full_handshake(
            &mut client,
            &mut client_crypto_ctx,
            &mut server,
            &mut server_crypto_ctx,
        )
        .unwrap();
        let mut session_buf = octets::Octets::with_slice(&session);
        let token_len = session_buf.get_u64().unwrap() as usize;
        let token = session_buf.get_bytes(token_len).unwrap();
        let params_len = session_buf.get_u64().unwrap() as usize;
        let params = session_buf.get_bytes(params_len).unwrap();

        assert_eq!(token_len, RUSTLS_SESSION_TOKEN_LEN);
        assert!(!params.is_empty());

        let (mut resumed_client, mut resumed_client_crypto_ctx) =
            handshake(false);
        resumed_client.set_session(token.as_ref()).unwrap();
        let (mut resumed_server, mut resumed_server_crypto_ctx) =
            handshake_from_context(server_context_with_ticket_key(), true);

        drive_full_handshake(
            &mut resumed_client,
            &mut resumed_client_crypto_ctx,
            &mut resumed_server,
            &mut resumed_server_crypto_ctx,
        );

        assert!(resumed_client.is_resumed());
    }

    #[test]
    fn early_data_session_installs_zero_rtt_open_key() {
        let mut ctx = Context::new().unwrap();
        ctx.set_verify(false);
        ctx.set_alpn(&[b"h3"]).unwrap();
        ctx.set_early_data_enabled(true);
        ctx.use_certificate_chain_file(EXAMPLE_CERT).unwrap();
        ctx.use_privkey_file(EXAMPLE_KEY).unwrap();

        let (mut client, mut client_crypto_ctx) =
            handshake_from_context_mut(&mut ctx, false);
        client.set_host_name("quic.tech").unwrap();
        let (mut server, mut server_crypto_ctx) =
            handshake_from_context_mut(&mut ctx, true);

        let session = drive_full_handshake(
            &mut client,
            &mut client_crypto_ctx,
            &mut server,
            &mut server_crypto_ctx,
        )
        .unwrap();
        let mut session_buf = octets::Octets::with_slice(&session);
        let token_len = session_buf.get_u64().unwrap() as usize;
        let token = session_buf.get_bytes(token_len).unwrap();

        let (mut resumed_client, mut resumed_client_crypto_ctx) =
            handshake_from_context_mut(&mut ctx, false);
        resumed_client.set_host_name("quic.tech").unwrap();
        resumed_client.set_session(token.as_ref()).unwrap();
        let (mut resumed_server, mut resumed_server_crypto_ctx) =
            handshake_from_context_mut(&mut ctx, true);

        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let application_protos = vec![b"h3".to_vec()];
        let mut client_session = None;
        let mut server_session = None;
        let mut client_error = None;
        let mut server_error = None;

        {
            let mut client_ex_data = ex_data(
                &mut resumed_client_crypto_ctx,
                false,
                &application_protos,
                &mut client_session,
                &mut client_error,
                recovery_config.clone(),
                config.tx_cap_factor,
            );
            assert_eq!(
                resumed_client.do_handshake(&mut client_ex_data),
                Err(Error::Done)
            );
        }

        assert!(resumed_client.is_in_early_data());
        assert!(resumed_client_crypto_ctx[packet::Epoch::Application]
            .crypto_seal
            .is_some());

        let client_initial =
            drain_crypto(&mut resumed_client_crypto_ctx, packet::Epoch::Initial);
        resumed_server
            .provide_data(crypto::Level::Initial, &client_initial)
            .unwrap();

        {
            let mut server_ex_data = ex_data(
                &mut resumed_server_crypto_ctx,
                true,
                &application_protos,
                &mut server_session,
                &mut server_error,
                recovery_config,
                config.tx_cap_factor,
            );
            assert_eq!(
                resumed_server.do_handshake(&mut server_ex_data),
                Err(Error::Done)
            );
        }

        assert!(resumed_server.is_resumed());
        assert!(resumed_server.is_in_early_data());
        assert!(resumed_server_crypto_ctx[packet::Epoch::Application]
            .crypto_0rtt_open
            .is_some());
    }

    #[test]
    fn client_context_loads_certificate_and_private_key() {
        let mut client_ctx = Context::new().unwrap();
        client_ctx.set_verify(false);
        client_ctx.set_alpn(&[b"h3"]).unwrap();
        client_ctx.use_certificate_chain_file(EXAMPLE_CERT).unwrap();
        client_ctx.use_privkey_file(EXAMPLE_KEY).unwrap();

        let (mut client, mut client_crypto_ctx) =
            handshake_from_context(client_ctx, false);
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config =
            crate::recovery::RecoveryConfig::from_config(&config);
        let application_protos = vec![b"h3".to_vec()];
        let mut session = None;
        let mut local_error = None;

        let mut ex_data = ex_data(
            &mut client_crypto_ctx,
            false,
            &application_protos,
            &mut session,
            &mut local_error,
            recovery_config,
            config.tx_cap_factor,
        );

        assert_eq!(client.do_handshake(&mut ex_data), Err(Error::Done));
        assert!(ex_data.crypto_ctx[packet::Epoch::Initial].data_available());
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
        ctx.set_verify(true);

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
        ctx.set_verify(true);
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
        ctx.set_verify(true);
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
