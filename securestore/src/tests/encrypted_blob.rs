use crate::shared::*;
use openssl::rand;

#[cfg(test)]
impl Default for CryptoKeys {
    fn default() -> Self {
        let mut encryption_key = [0u8; KEY_LENGTH];
        let mut hmac_key = [0u8; KEY_LENGTH];

        rand::rand_bytes(&mut encryption_key).unwrap();
        rand::rand_bytes(&mut hmac_key).unwrap();

        CryptoKeys {
            encryption: encryption_key,
            hmac: hmac_key,
        }
    }
}

/// Tests basic encryption and decryption via [`EncryptedBlob`].
#[test]
fn basic_encryption_decryption() {
    let keys: CryptoKeys = Default::default();

    let foo = EncryptedBlob::encrypt(&keys, b"foo");
    assert_eq!(
        foo.decrypt(&keys).unwrap().as_slice(),
        b"foo",
        "failed to retrieve same value stored!"
    );
}

/// Verify that the same iv is not used twice in a row
#[test]
fn iv_uniqueness() {
    let keys: CryptoKeys = Default::default();

    let foo1 = EncryptedBlob::encrypt(&keys, b"foo");
    let foo2 = EncryptedBlob::encrypt(&keys, b"foo");

    assert_ne!(
        foo1.payload, foo2.payload,
        "Encrypting the same secret twice in a row yielded the same result!"
    );
    assert_ne!(
        foo1.iv, foo2.iv,
        "The iv was reused across two different secrets!"
    );
}

/// Verify that tampered ciphertext is caught
#[test]
fn blob_authentication() {
    let keys: CryptoKeys = Default::default();

    let mut foo = EncryptedBlob::encrypt(&keys, b"foo");
    assert!(
        foo.authenticate(&keys.hmac),
        "Authentication for known-good blob failed"
    );

    foo.payload[0] = !foo.payload[0];
    assert!(
        !foo.authenticate(&keys.hmac),
        "Authentication for known-bad blob succeeded"
    );
}
