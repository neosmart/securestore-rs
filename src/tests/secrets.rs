//! Highest-level tests for the secure store

use crate::{KeySource, SecretsManager};

/// Verify that basic storage and retrieval of secrets functions correctly.
#[test]
fn basic_store_retrieve() {
    // create a new secrets manager with a known secret so we don't need to muck around
    // with keyfiles later.
    let mut sman = SecretsManager::new("./secrets.json", KeySource::Password("mysecret"))
	.unwrap();

    // make sure that we can set values in different &str/String types
    sman.set("foo", "bar");
    sman.set("foo", "bar".to_string());
    sman.save();

    // do we get the same value back on retrieve?
    let retrieved: String = sman.retrieve("foo").unwrap();
    assert_eq!("bar", retrieved);
}
