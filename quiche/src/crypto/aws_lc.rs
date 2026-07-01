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

use super::*;

use aws_lc_rs::aead;
use aws_lc_rs::constant_time;
use aws_lc_rs::hkdf;
use aws_lc_rs::hmac;

pub(crate) struct PacketKey {
    alg: Algorithm,

    key: aead::LessSafeKey,

    nonce: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        let key = aead::UnboundKey::new(alg.get_aead(), &key)
            .map_err(|_| Error::CryptoFail)?;

        Ok(Self {
            alg,
            key: aead::LessSafeKey::new(key),
            nonce: iv,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8], enc: u32) -> Result<Self> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];

        derive_pkt_key(aead, secret, &mut key)?;
        derive_pkt_iv(aead, secret, &mut iv)?;

        Self::new(aead, key, iv, enc)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let nonce =
            aead::Nonce::assume_unique_for_key(make_nonce(&self.nonce, counter));

        self.key
            .open_in_place(nonce, aead::Aad::from(ad), buf)
            .map(|plaintext| plaintext.len())
            .map_err(|_| Error::CryptoFail)
    }

    pub fn seal_with_u64_counter(
        &mut self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();
        let extra_len = extra_in.map_or(0, <[u8]>::len);

        if in_len + tag_len + extra_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        let nonce =
            aead::Nonce::assume_unique_for_key(make_nonce(&self.nonce, counter));
        let (in_out, extra_out_and_tag) = buf.split_at_mut(in_len);
        let extra_out_and_tag = &mut extra_out_and_tag[..tag_len + extra_len];

        match extra_in {
            Some(extra) => {
                self.key
                    .seal_in_place_scatter(
                        nonce,
                        aead::Aad::from(ad),
                        in_out,
                        extra,
                        extra_out_and_tag,
                    )
                    .map_err(|_| Error::CryptoFail)?;

                Ok(in_len + extra_out_and_tag.len())
            },

            None => {
                let tag = self
                    .key
                    .seal_in_place_separate_tag(
                        nonce,
                        aead::Aad::from(ad),
                        in_out,
                    )
                    .map_err(|_| Error::CryptoFail)?;

                extra_out_and_tag.copy_from_slice(tag.as_ref());

                Ok(in_len + tag_len)
            },
        }
    }
}

pub(crate) struct HeaderProtectionKey {
    alg: &'static aead::quic::Algorithm,

    key: Vec<u8>,

    inner: aead::quic::HeaderProtectionKey,
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        let alg = alg.get_hp();
        let inner = aead::quic::HeaderProtectionKey::new(alg, &hp_key)
            .map_err(|_| Error::CryptoFail)?;

        Ok(Self {
            alg,
            key: hp_key,
            inner,
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        self.inner.new_mask(sample).map_err(|_| Error::CryptoFail)
    }
}

impl Clone for HeaderProtectionKey {
    fn clone(&self) -> Self {
        Self {
            alg: self.alg,
            key: self.key.clone(),
            inner: aead::quic::HeaderProtectionKey::new(self.alg, &self.key)
                .expect("stored header protection key must remain valid"),
        }
    }
}

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    let tag = hmac::sign(&hmac::Key::new(alg.get_hmac(), salt), secret);

    if tag.as_ref().len() > out.len() {
        return Err(Error::CryptoFail);
    }

    out[..tag.as_ref().len()].copy_from_slice(tag.as_ref());

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    let out_len = HkdfOutputLen(out.len());
    let prk = hkdf::Prk::new_less_safe(alg.get_hkdf(), secret);
    let info = [info];
    let okm = prk.expand(&info, out_len).map_err(|_| Error::CryptoFail)?;

    okm.fill(out).map_err(|_| Error::CryptoFail)
}

pub(crate) fn backend_verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    constant_time::verify_slices_are_equal(a, b).map_err(|_| Error::CryptoFail)
}

struct HkdfOutputLen(usize);

impl hkdf::KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl Algorithm {
    fn get_aead(self) -> &'static aead::Algorithm {
        match self {
            Algorithm::AES128_GCM => &aead::AES_128_GCM,
            Algorithm::AES256_GCM => &aead::AES_256_GCM,
            Algorithm::ChaCha20_Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    fn get_hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Algorithm::AES128_GCM => &aead::quic::AES_128,
            Algorithm::AES256_GCM => &aead::quic::AES_256,
            Algorithm::ChaCha20_Poly1305 => &aead::quic::CHACHA20,
        }
    }

    fn get_hkdf(self) -> hkdf::Algorithm {
        match self {
            Algorithm::AES128_GCM => hkdf::HKDF_SHA256,
            Algorithm::AES256_GCM => hkdf::HKDF_SHA384,
            Algorithm::ChaCha20_Poly1305 => hkdf::HKDF_SHA256,
        }
    }

    fn get_hmac(self) -> hmac::Algorithm {
        match self {
            Algorithm::AES128_GCM => hmac::HMAC_SHA256,
            Algorithm::AES256_GCM => hmac::HMAC_SHA384,
            Algorithm::ChaCha20_Poly1305 => hmac::HMAC_SHA256,
        }
    }
}
