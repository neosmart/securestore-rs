//! Internal crypto abstraction: one of OpenSSL or pure-Rust (rustls) backend.

#[cfg(not(feature = "rustls"))]
mod openssl_impl;
#[cfg(not(feature = "rustls"))]
use openssl_impl as backend;

#[cfg(feature = "rustls")]
mod rustls_impl;
#[cfg(feature = "rustls")]
use rustls_impl as backend;

pub use backend::{
    aes_128_cbc_decrypt, aes_128_cbc_encrypt, constant_time_eq, hmac_sha1, pbkdf2_hmac_sha1,
    rand_bytes,
};
