//! Highest-level tests for the secure store

use crate::errors::ErrorKind;
use crate::{KeySource, SecretsManager};
use tempfile::NamedTempFile;

/// Verify that basic storage and retrieval of secrets functions correctly.
#[test]
fn basic_store_get() {
    // Create a new secrets manager with a known secret so we don't need to muck
    // around with keyfiles later.
    let secrets_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut sman = SecretsManager::new(KeySource::Password("mysecret")).unwrap();

    // Make sure that we can set values in different &str/String types
    sman.set("foo", "bar");
    sman.set("foo", "bar".to_string());
    sman.save_as(&secrets_path).unwrap();

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
    let secrets_path = NamedTempFile::new().unwrap().into_temp_path();
    let mut sman = SecretsManager::new(KeySource::Password("mysecret")).unwrap();

    // Set something
    sman.set("foo", "foo");
    // And save the store to disk
    sman.save_as(&secrets_path).unwrap();

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
    let sman = SecretsManager::new(KeySource::Csprng).unwrap();

    assert_eq!(Err(ErrorKind::SecretNotFound.into()), sman.get("foo"));
}

#[test]
fn csprng_export() {
    let secrets_path = NamedTempFile::new().unwrap().into_temp_path();
    let key_path = NamedTempFile::new().unwrap().into_temp_path();

    {
        let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();
        sman.export_key(&key_path).unwrap();

        sman.set("foo", "bar");
        sman.save_as(&secrets_path).unwrap();
    }

    let sman = SecretsManager::load(secrets_path, KeySource::File(key_path)).unwrap();
    assert_eq!(Ok("bar".to_owned()), sman.get("foo"));
}

#[test]
fn password_export() {
    let secrets_path = NamedTempFile::new().unwrap().into_temp_path();
    let key_path = NamedTempFile::new().unwrap().into_temp_path();

    {
        let mut sman = SecretsManager::new(KeySource::Password("password123")).unwrap();
        // Use legacy .export() alias .export_keyfile() to make sure it works
        sman.export_keyfile(&key_path).unwrap();

        sman.set("foo", "bar");
        sman.save_as(&secrets_path).unwrap();
    }

    let sman = SecretsManager::load(secrets_path, KeySource::File(key_path)).unwrap();
    assert_eq!(Ok("bar".to_owned()), sman.get("foo"));
}

#[test]
fn invalid_key_file() {
    let key_path = NamedTempFile::new().unwrap().into_temp_path();

    match SecretsManager::new(KeySource::File(key_path)) {
        Ok(_) => panic!("SecretsManager loaded with invalid key file!"),
        Err(e) => assert_eq!(ErrorKind::InvalidKeyfile, e.kind()),
    }
}

#[test]
fn binary_secret() {
    let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();

    let (key, value) = ("secret", b"Hello, world!");
    sman.set(key, &value[..]);

    assert_eq!(&value[..], sman.get_as::<Vec<u8>>(key).unwrap().as_slice());
}

#[test]
/// A release added generics to KeySource which were later removed because the
/// default generic fallback doesn't work on current rust versions. This had
/// let `KeySource::File(path: AsRef<Path>)` work, but broke `KeySource::Csprng`
/// and `KeySource::Password` because the `P: AsRef<Path>` wasn't defined for
/// those variants (unless it was explicitly provided, though not used).
///
/// `KeySource::File` was renamed to `KeySource::Path` and takes a `&Path` only,
/// but a function masquerading as a variant called `KeySource::File()` was
/// introduced that returns `impl GenericKeySource`, the trait which we now
/// accept in the `new()` and `load()` functions. This function is hidden from
/// the docs and is for backwards-compatibility only.
fn legacy_generic_keysource() {
    // We just want to verify that this compiles, we don't test the result here.
    let _ = SecretsManager::load("secrets.json", KeySource::File("secrets.key"));
}

#[test]
fn str_as_generic_keysource() {
    // We just want to verify that this compiles, we don't test the result here.
    let _ = SecretsManager::load("secrets.json", "secrets.key");
}
