//! Pure-Rust (rustls-style) implementation of the internal crypto API.

use crate::errors::{Error, ErrorKind};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Mac;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use subtle::ConstantTimeEq;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn rand_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("CSPRNG failure");
}

pub fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let ct_len = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
        .expect("AES-128-CBC encrypt failed")
        .len();
    buf.truncate(ct_len);
    buf
}

pub fn aes_128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; ciphertext.len()];
    let pt = Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buf)
        .map_err(|_| ErrorKind::DecryptionFailure)?;
    let pt_len = pt.len();
    buf.truncate(pt_len);
    Ok(buf)
}

pub fn hmac_sha1(key: &[u8; 16], chunks: &[&[u8]]) -> [u8; 20] {
    let mut mac =
        hmac::Hmac::<Sha1>::new_from_slice(key).expect("Failed to init HMAC with provided key");
    for &chunk in chunks {
        mac.update(chunk);
    }
    let result = mac.finalize();
    result.into_bytes().into()
}

pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha1>(password, salt, rounds, out);
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
