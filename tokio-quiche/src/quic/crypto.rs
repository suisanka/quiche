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

pub(crate) fn rand_bytes(buf: &mut [u8]) {
    fill_random(buf);
}

#[cfg(feature = "boringssl-boring-crate")]
fn fill_random(buf: &mut [u8]) {
    boring::rand::rand_bytes(buf).expect("BoringSSL RAND_bytes never fails");
}

#[cfg(all(
    not(feature = "boringssl-boring-crate"),
    feature = "rustls-aws-lc-rs"
))]
fn fill_random(buf: &mut [u8]) {
    use aws_lc_rs::rand::SecureRandom;

    let rng = aws_lc_rs::rand::SystemRandom::new();

    rng.fill(buf)
        .expect("failed to generate secure random bytes");
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    sign_hmac_sha256(key, data)
}

#[cfg(feature = "boringssl-boring-crate")]
fn sign_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = boring::hash::hmac_sha256(key, data).expect("HMAC-SHA256 failed");
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(all(
    not(feature = "boringssl-boring-crate"),
    feature = "rustls-aws-lc-rs"
))]
fn sign_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = aws_lc_rs::hmac::sign(&key, data);
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub(crate) fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}

#[cfg(feature = "boringssl-boring-crate")]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    boring::memcmp::eq(a, b)
}

#[cfg(all(
    not(feature = "boringssl-boring-crate"),
    feature = "rustls-aws-lc-rs"
))]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}
