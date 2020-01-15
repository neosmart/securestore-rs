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

    // Now try decrypting with wrong password
    let sman = SecretsManager::load(&secrets_path, KeySource::Password("notmysecret")).unwrap();
    assert_eq!(
        ErrorKind::DecryptionFailure,
        sman.get::<String>("foo").unwrap_err().kind()
    );
}
