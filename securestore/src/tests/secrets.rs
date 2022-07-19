//! Highest-level tests for the secure store

use crate::errors::ErrorKind;
use crate::{KeySource, SecretsManager};
use tempfile::NamedTempFile;

/// Verify that basic storage and retrieval of secrets functions correctly.
#[test]
fn basic_store_get() {
    // Create a new secrets manager with a known secret so we don't need to muck
    // around with keyfiles later.
    let secrets_path = NamedTempFile::new().unwrap();
    let mut sman = SecretsManager::new(&secrets_path, KeySource::Password("mysecret")).unwrap();

    // Make sure that we can set values in different &str/String types
    sman.set("foo", "bar");
    sman.set("foo", "bar".to_string());
    sman.save().unwrap();

    // Do we get the same value back on get?
    let getd: String = sman.get("foo").unwrap();
    assert_eq!("bar", getd);

    // Now open the store from the disk with the same settings and make sure the
    // data remains loadable.
    let sman2 = SecretsManager::load(&secrets_path, KeySource::Password("mysecret")).unwrap();
    let getd: String = sman2.get("foo").unwrap();
    assert_eq!("bar", getd);
}

#[test]
fn wrong_password() {
    let secrets_path = NamedTempFile::new().unwrap();
    let mut sman = SecretsManager::new(&secrets_path, KeySource::Password("mysecret")).unwrap();

    // Set something
    sman.set("foo", "foo");
    // And save the store to disk
    sman.save().unwrap();

    // Now try loading the store with wrong password
    match SecretsManager::load(&secrets_path, KeySource::Password("notmysecret")) {
        Ok(_) => panic!("Sentinel failed to detect wrong password on load"),
        Err(e) => {
            assert_eq!(ErrorKind::DecryptionFailure, e.kind());
        }
    }
}

#[test]
fn secret_not_found() {
    let secrets_path = NamedTempFile::new().unwrap();
    let sman = SecretsManager::new(&secrets_path, KeySource::Csprng).unwrap();

    assert_eq!(Err(ErrorKind::SecretNotFound.into()), sman.get("foo"));
}

#[test]
fn csprng_export() {
    let secrets_path = NamedTempFile::new().unwrap();

    let key_path = NamedTempFile::new().unwrap();
    {
        let mut sman = SecretsManager::new(&secrets_path, KeySource::Csprng).unwrap();
        sman.export_keyfile(&key_path).unwrap();

        sman.set("foo", "bar");
        sman.save().unwrap();
    }

    let sman = SecretsManager::load(secrets_path, KeySource::File(key_path.as_ref())).unwrap();
    assert_eq!(Ok("bar".to_owned()), sman.get("foo"));
}

#[test]
fn password_export() {
    let secrets_path = NamedTempFile::new().unwrap();

    let key_path = NamedTempFile::new().unwrap();
    {
        let mut sman =
            SecretsManager::new(&secrets_path, KeySource::Password("password123")).unwrap();
        sman.export_keyfile(&key_path).unwrap();

        sman.set("foo", "bar");
        sman.save().unwrap();
    }

    let sman = SecretsManager::load(secrets_path, KeySource::File(key_path.as_ref())).unwrap();
    assert_eq!(Ok("bar".to_owned()), sman.get("foo"));
}

#[test]
fn invalid_key_file() {
    let secrets_path = NamedTempFile::new().unwrap();
    let key_path = NamedTempFile::new().unwrap();
    match SecretsManager::new(&secrets_path, KeySource::File(key_path.as_ref())) {
        Ok(_) => panic!("SecretsManager loaded with invalid key file!"),
        Err(e) => assert_eq!(ErrorKind::InvalidKeyfile, e.kind()),
    }
}

#[test]
fn binary_secret() {
    let secrets_path = NamedTempFile::new().unwrap();
    let mut sman = SecretsManager::new(&secrets_path, KeySource::Csprng).unwrap();

    let (key, value) = ("secret", b"Hello, world!");
    sman.set(key, &value[..]);

    assert_eq!(&value[..], sman.get_as::<Vec<u8>>(key).unwrap().as_slice());
}
