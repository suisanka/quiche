// Copyright (C) 2026, Cloudflare, Inc.
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

use rustls::crypto::tls13::OkmBlock;
use rustls::crypto::CipherSuite;
use rustls::crypto::CryptoProvider;

pub(crate) fn rand_bytes(buf: &mut [u8]) {
    default_provider()
        .secure_random
        .fill(buf)
        .expect("failed to generate secure random bytes");
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    assert!(key.len() <= OkmBlock::MAX_LEN);

    let provider = default_provider();
    let suite = provider
        .tls13_cipher_suites
        .iter()
        .copied()
        .find(|suite| suite.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .expect("rustls provider must support TLS_AES_128_GCM_SHA256");
    let key = OkmBlock::new(key);
    let tag = suite.hkdf_provider.hmac_sign(&key, data);
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub(crate) fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).fold(0, |acc, (&a, &b)| acc | (a ^ b)) == 0
}

fn default_provider() -> Arc<CryptoProvider> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Arc::clone(provider);
    }

    #[cfg(feature = "rustls-aws-lc-rs")]
    {
        return Arc::new(rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER);
    }

    #[cfg(not(feature = "rustls-aws-lc-rs"))]
    panic!("rustls crypto provider must be installed before using tokio-quiche")
}
