use crate::shared::*;
use crate::*;
use openssl::rand;
use std::io::Read;
use tempfile::NamedTempFile;

/// Verifies that exporting keys derived from a password results in keys
/// dependent on the IV.
#[test]
fn key_derivation_iv() {
    let mut iv1 = [0u8; IV_SIZE];
    rand::rand_bytes(&mut iv1).unwrap();

    let mut iv2 = [0u8; IV_SIZE];
    rand::rand_bytes(&mut iv2).unwrap();

    let derived1 = KeySource::Password("foo").extract_keys(&iv1).unwrap();
    let derived2 = KeySource::Password("foo").extract_keys(&iv1).unwrap();

    assert_eq!(
        derived1, derived2,
        "Two keys derived from same password and same IV should not differ"
    );

    let derived3 = KeySource::Password("foo").extract_keys(&iv2).unwrap();
    assert_ne!(
        derived1, derived3,
        "Two keys derived from the same password but different IVs should differ"
    );
}

/// Validates that [`KeySource::Buffer`] can be used to read a secret out of a
/// file.
#[test]
fn buffer_key_source() {
    let vault = NamedTempFile::new().unwrap().into_temp_path();
    let keyfile = NamedTempFile::new().unwrap().into_temp_path();

    // Create a vault, write to it, and export it and its keys
    let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();
    sman.set("foo", "bar");
    sman.export_key(&keyfile).unwrap();
    sman.save_as(&vault).unwrap();

    let mut buffer = Vec::new();
    File::open(keyfile)
        .unwrap()
        .read_to_end(&mut buffer)
        .unwrap();
    let keysource = KeySource::Buffer(&buffer);
    let sman = SecretsManager::load(&vault, keysource).expect("Failed to load keys from buffer!");
    assert_eq!(&sman.get_as::<Vec<u8>>("foo").unwrap(), b"bar");
}
