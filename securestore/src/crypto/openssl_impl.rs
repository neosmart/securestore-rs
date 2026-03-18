//! OpenSSL-backed implementation of the internal crypto API.

use crate::errors::Error;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::PKey;
use openssl::rand;
use openssl::sign::Signer;
use openssl::symm::{self, Cipher};

pub fn rand_bytes(buf: &mut [u8]) {
    rand::rand_bytes(buf).expect("CSPRNG failure");
}

pub fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    symm::encrypt(cipher, key, Some(iv), plaintext).expect("AES-128-CBC encrypt failed")
}

pub fn aes_128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Cipher::aes_128_cbc();
    symm::decrypt(cipher, key, Some(iv), ciphertext).map_err(Error::from)
}

pub fn hmac_sha1(key: &[u8; 16], chunks: &[&[u8]]) -> [u8; 20] {
    let pkey = PKey::hmac(key).expect("Failed to load HMAC key");
    let mut signer =
        Signer::new(MessageDigest::sha1(), &pkey).expect("Failed to create HMAC signer");
    for &chunk in chunks {
        signer.update(chunk).expect("HMAC update failed");
    }
    let mut out = [0u8; 20];
    let n = signer.sign(&mut out).expect("HMAC sign failed");
    assert_eq!(n, 20);
    out
}

pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    pbkdf2_hmac(password, salt, rounds as usize, MessageDigest::sha1(), out)
        .expect("PBKDF2-HMAC-SHA1 failed");
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    openssl::memcmp::eq(a, b)
}
