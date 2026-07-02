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

use std::sync::Arc;

use super::*;

use ::rustls::crypto::cipher::AeadKey;
use ::rustls::crypto::cipher::Iv;
use ::rustls::crypto::tls13::OkmBlock;
use ::rustls::crypto::CipherSuite;
use ::rustls::crypto::CryptoProvider;
use ::rustls::Tls13CipherSuite;

pub(crate) struct PacketKey {
    inner: Box<dyn ::rustls::quic::PacketKey>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        let suite = tls13_suite_for_algorithm(alg)?;
        let quic = suite.quic.ok_or(Error::CryptoFail)?;
        let key = aead_key_from_slice(&key)?;
        let iv = Iv::new(&iv).map_err(|_| Error::CryptoFail)?;

        Ok(Self {
            inner: quic.packet_key(key, iv),
        })
    }

    pub fn from_secret(alg: Algorithm, secret: &[u8], _enc: u32) -> Result<Self> {
        Ok(Self {
            inner: key_builder(alg, secret)?.packet_key(),
        })
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        self.inner
            .decrypt_in_place(counter, ad, buf, None)
            .map(|plaintext| plaintext.len())
            .map_err(|_| Error::CryptoFail)
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.inner.tag_len();
        let extra_len = extra_in.map_or(0, <[u8]>::len);
        let plaintext_len = in_len + extra_len;

        if plaintext_len + tag_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        if let Some(extra) = extra_in {
            buf[in_len..plaintext_len].copy_from_slice(extra);
        }

        let tag = self
            .inner
            .encrypt_in_place(counter, ad, &mut buf[..plaintext_len], None)
            .map_err(|_| Error::CryptoFail)?;

        buf[plaintext_len..plaintext_len + tag_len].copy_from_slice(tag.as_ref());

        Ok(plaintext_len + tag_len)
    }
}

#[cfg(test)]
pub(crate) struct HeaderProtectionKey {
    alg: Algorithm,
    key: Vec<u8>,
    inner: Arc<dyn ::rustls::quic::HeaderProtectionKey>,
}

#[cfg(test)]
impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        let suite = tls13_suite_for_algorithm(alg)?;
        let quic = suite.quic.ok_or(Error::CryptoFail)?;
        let key = aead_key_from_slice(&hp_key)?;

        Ok(Self {
            alg,
            key: hp_key,
            inner: quic.header_protection_key(key).into(),
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        new_mask(self.inner.as_ref(), sample)
    }
}

#[cfg(test)]
impl Clone for HeaderProtectionKey {
    fn clone(&self) -> Self {
        Self::new(self.alg, self.key.clone())
            .expect("stored header protection key must remain valid")
    }
}

#[cfg(test)]
pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    if secret.len() > OkmBlock::MAX_LEN {
        return Err(Error::CryptoFail);
    }

    let suite = tls13_suite_for_algorithm(alg)?;
    let secret = OkmBlock::new(secret);
    let expander = suite.hkdf_provider.expander_for_okm(&secret);

    expander
        .expand_slice(&[info], out)
        .map_err(|_| Error::CryptoFail)
}

pub(crate) fn backend_verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::CryptoFail);
    }

    let diff = a.iter().zip(b).fold(0, |acc, (&a, &b)| acc | (a ^ b));

    match diff {
        0 => Ok(()),
        _ => Err(Error::CryptoFail),
    }
}

pub(crate) fn default_provider() -> Result<Arc<CryptoProvider>> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Ok(Arc::clone(provider));
    }

    #[cfg(feature = "rustls-aws-lc-rs")]
    {
        return Ok(Arc::new(rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER));
    }

    #[cfg(not(feature = "rustls-aws-lc-rs"))]
    Err(Error::TlsFail)
}

pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    default_provider()?
        .secure_random
        .fill(buf)
        .map_err(|_| Error::CryptoFail)
}

#[cfg(test)]
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    if key.len() > OkmBlock::MAX_LEN {
        return Err(Error::CryptoFail);
    }

    let suite =
        tls13_suite_for_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)?;
    let key = OkmBlock::new(key);
    let tag = suite.hkdf_provider.hmac_sign(&key, data);
    let mut out = [0; 32];
    let tag = tag.as_ref();

    if tag.len() != out.len() {
        return Err(Error::CryptoFail);
    }

    out.copy_from_slice(tag);

    Ok(out)
}

pub(crate) fn initial_keys(
    cid: &[u8], version: u32, is_server: bool,
) -> Result<::rustls::quic::Keys> {
    let suite =
        tls13_suite_for_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)?;
    let suite = suite.quic_suite().ok_or(Error::CryptoFail)?;
    let side = match is_server {
        true => ::rustls::quic::Side::Server,
        false => ::rustls::quic::Side::Client,
    };

    Ok(suite.keys(cid, side, rustls_quic_version(version)))
}

fn key_builder(
    alg: Algorithm, secret: &[u8],
) -> Result<::rustls::quic::KeyBuilder<'static>> {
    if secret.len() > OkmBlock::MAX_LEN {
        return Err(Error::CryptoFail);
    }

    let suite = tls13_suite_for_algorithm(alg)?;
    let quic = suite.quic.ok_or(Error::CryptoFail)?;
    let secret = OkmBlock::new(secret);

    Ok(::rustls::quic::KeyBuilder::new(
        &secret,
        ::rustls::quic::Version::V1,
        quic,
        suite.hkdf_provider,
    ))
}

fn tls13_suite_for_algorithm(
    alg: Algorithm,
) -> Result<&'static Tls13CipherSuite> {
    tls13_suite_for_cipher_suite(match alg {
        Algorithm::AES128_GCM => CipherSuite::TLS13_AES_128_GCM_SHA256,
        Algorithm::AES256_GCM => CipherSuite::TLS13_AES_256_GCM_SHA384,
        Algorithm::ChaCha20_Poly1305 =>
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    })
}

fn tls13_suite_for_cipher_suite(
    cipher_suite: CipherSuite,
) -> Result<&'static Tls13CipherSuite> {
    default_provider()?
        .tls13_cipher_suites
        .iter()
        .copied()
        .find(|suite| suite.common.suite == cipher_suite && suite.quic.is_some())
        .ok_or(Error::CryptoFail)
}

fn aead_key_from_slice(key: &[u8]) -> Result<AeadKey> {
    match key.len() {
        16 => {
            let mut out = [0; 16];
            out.copy_from_slice(key);
            Ok(out.into())
        },

        32 => {
            let mut out = [0; 32];
            out.copy_from_slice(key);
            Ok(out.into())
        },

        _ => Err(Error::CryptoFail),
    }
}

fn rustls_quic_version(_version: u32) -> ::rustls::quic::Version {
    ::rustls::quic::Version::V1
}

#[cfg(test)]
fn new_mask(
    key: &dyn ::rustls::quic::HeaderProtectionKey, sample: &[u8],
) -> Result<HeaderProtectionMask> {
    let mut first = 0x03;
    let mut packet_number = [0; 4];

    key.encrypt_in_place(sample, &mut first, &mut packet_number)
        .map_err(|_| Error::CryptoFail)?;

    let mut mask = [0; HP_MASK_LEN];
    mask[0] = (first ^ 0x03) & 0x1f;
    mask[1..].copy_from_slice(&packet_number);

    Ok(mask)
}
