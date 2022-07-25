//! This crate contains the rust implementation of [SecureStore](https://neosmart.net/blog/2020/securestore-open-secrets-format/),
//! an open standard for cross-language/cross-platform secrets storage and
//! retrieval. A SecureStore is represented on-disk as a plain-text,
//! human-readable (JSON) file, intended to be stored and versioned alongside
//! the code using it. Refer to [the accompanying article](https://neosmart.net/blog/2020/securestore-open-secrets-format/)
//! for more information on the SecureStore protocol.
//!
//! SecureStore vaults are created by or loaded from an existing vault and
//! represented in memory as instances of [`SecretsManager`], the primary type
//! exposed by this crate. Typically, one `SecretsManager` instance should be
//! created to service all retrieval and storage requests of secrets for an app.
//!
//! For maximum flexibility and per the SecureStore protocol, the private keys
//! used to encrypt or decrypt secrets in the vault can come from different
//! sources (that may possibly even be used interchangeably); this key source is
//! specified as a variant of the [`KeySource`] enum at the time of creating or
//! loading a `SecretsManager` instance.
//!
//! For best results, this crate should be used alongside the
//! [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient)
//! companion CLI app (available via `cargo install ssclient`). Typically, a new
//! SecureStore vault is created with `ssclient create ...` and loaded with
//! secrets at the command line with a series of `ssclient set ...`
//! commands; this crate is then used by your application's logic at runtime to
//! load the store created by `ssclient` (via [`SecretsManager::load()`]) and
//! retrieve the secrets (via [`SecretsManager::get()`]), although all the
//! functionality needed to create and initialize a new store and its secrets
//! directly yourself (without `ssclient`) is also available via the
//! `SecretsManager` API.
//!
//! # Example
//!
//! First, create a new store and set some secret value at the command line with
//! the companion `ssclient` crate:
//!
//! ```sh
//! $ cargo install ssclient
//! $ ssclient create secrets.json -k secrets.key
//! $ ssclient -k secrets.key set db_password pgsql123
//! ```
//!
//! Then in your code, load the store with the newly-created key file and
//! retrieve the secret:
//! ```rust
//! use securestore::{KeySource, SecretsManager};
//! use std::path::Path;
//! #
//! # let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();
//! # sman.set("db_password", "pgsql123");
//! # sman.export_keyfile("secrets.key");
//! # sman.save_as("secrets.json");
//! # drop (sman);
//!
//! let key_path = Path::new("secrets.key");
//! let sman = SecretsManager::load("secrets.json", KeySource::File(key_path))
//!     .expect("Failed to load secrets store!");
//! let db_password = sman.get("db_password")
//!     .expect("Couldn't get db_password from vault!");
//! # drop(sman);
//! # std::fs::remove_file("secrets.key").unwrap();
//! # std::fs::remove_file("secrets.json").unwrap();
//!
//! assert_eq!(db_password, String::from("pgsql123"));
//! ```
mod errors;
mod serial;
mod shared;
#[cfg(test)]
mod tests;

use self::shared::{CryptoKeys, EncryptedBlob, Vault};
pub use crate::errors::{Error, ErrorKind};
pub use crate::serial::{BinaryDeserializable, BinarySerializable};
use openssl::rand;
use std::fs::File;
use std::path::{Path, PathBuf};

/// A `KeySource` specifies the source of the encryption/decryption keys used by
/// a [`SecretsManager`] instance when loading or interacting with a SecureStore
/// vault.
///
/// Note that it is possible for different `KeySource` variants to be equivalent
/// and used interchangeably. For instance, you can derive the secret keys from
/// a password (via [`KeySource::Password`]) when reading/writing a SecureStore
/// vault from the command line (via the companion cli app/crate, `ssclient`)
/// but then export a copy of the keys derived from that password to a keyfile
/// and use that when accessing the vault from your code in production (as a
/// [`KeySource::File`] variant). See [`SecretsManager::export_keyfile()`] or
/// the `ssclient` documentation for more info.
///
/// Note that when creating a new vault with [`KeySource::Csprng`] the generated
/// private keys should be exported via [`SecretsManager::export_keyfile()`]
/// before dropping the `SecretsManager` instance; the exported keyfile should
/// then be used the next time the vault is loaded (via [`KeySource::File`]).
#[non_exhaustive]
#[derive(Clone)]
pub enum KeySource<'a> {
    /// Load the keys from a binary file on-disk
    File(&'a Path),
    /// Derive keys from the specified password
    Password(&'a str),
    /// Automatically generate a new key file from a secure RNG, for use with
    /// [`SecretsManager::new()`] only.
    ///
    /// [`SecretsManager::export_keyfile()`] should be used to export the
    /// keys before the instance is disposed. The store can then subsequently be
    /// loaded with a [`KeySource::File`] pointing to the file exported by
    /// [`SecretsManager::export_keyfile()`].
    Csprng,
}

/// `SecretsManager` is the primary interface used for interacting with this
/// crate, and is an in-memory representation of an encrypted SecureStore vault.
///
/// An existing plain-text SecureStore vault can be loaded with
/// [`SecretsManager::load()`] or a new vault can be created with
/// [`SecretsManager::new()`] and then saved to disk
/// with [`SecretsManager::save()`] or [`SecretsManager::save_as()`].
///
/// Individual secrets can be set, retrieved, and removed with
/// [`SecretsManager::set()`], [`SecretsManager::get()`], and
/// [`SecretsManager::remove()`] respectively. The names/keys of all secrets
/// stored in this vault can be enumerated via [`SecretsManager::keys()`].
pub struct SecretsManager {
    vault: Vault,
    path: Option<PathBuf>,
    cryptokeys: CryptoKeys,
}

impl SecretsManager {
    fn create_sentinel(keys: &CryptoKeys) -> EncryptedBlob {
        let mut random = [0u8; shared::IV_SIZE * 2];
        rand::rand_bytes(&mut random).expect("Failed to create sentinel");
        EncryptedBlob::encrypt(&keys, &random)
    }

    /// Creates a new instance of `SecretsManager`, encrypting its secrets with
    /// the specified [`KeySource`].
    ///
    /// Note that the usage of [`KeySource::File`] is taken to mean that there
    /// is an existing compatible private key already available at the
    /// specified path. To generate a new key file, use [`KeySource::Csprng`]
    /// then export the generated keys with
    /// [`SecretsManager::export_keyfile()`].
    pub fn new(key_source: KeySource) -> Result<Self, Error> {
        let mut vault = Vault::new();
        let keys = key_source.extract_keys(&vault.iv)?;
        vault.sentinel = Some(Self::create_sentinel(&keys));
        Ok(SecretsManager {
            cryptokeys: keys,
            path: None,
            vault,
        })
    }

    /// Load the contents of an on-disk SecureStore vault located at `path`
    /// into a new `SecretsManager` instance, decrypting its contents with
    /// the [`KeySource`] specified by the `key_source` parameter.
    ///
    /// Note that changes to the vault are not written to disk unless and until
    /// [`SecretsManager::save()`]/[`SecretsManager::save_as()`] is called.
    ///
    /// ## Panics:
    /// If an attempt is made to load an existing vault but `key_source` is set
    /// to [`KeySource::Csprng`] (which should only be used when
    /// initializing a new secrets vault). In release mode, this does not panic
    /// but the vault will invariably fail to decrypt.
    pub fn load<P1: AsRef<Path>>(path: P1, key_source: KeySource) -> Result<Self, Error> {
        // We intentionally only panic here in debug mode, only because we try to avoid
        // panicking in production if possible. This isn't a logic error (the code will
        // still run and everything will work without any incorrect behavior) but the
        // user will just never get the desired results (loading an existing store with
        // a newly generated key will just always fail to decrypt the store contents).
        // Tl;dr it's not unsafe or technically incorrect, just stupid.
        if matches!(key_source, KeySource::Csprng) {
            debug_assert!(false, "It is incorrect to call SecretsManager::load() except with an existing key source!");
        }

        let path = path.as_ref();

        let mut vault = Vault::from_file(path)?;
        let keys = key_source.extract_keys(&vault.iv)?;

        // The sentinel is an optional part of the spec that prevents inadvertently
        // adding two secrets with two different passwords. It is not intended to
        // have any effects on the security or entropy of the store.
        if let Some(ref sentinel) = vault.sentinel {
            sentinel.decrypt(&keys)?;
        } else {
            vault.sentinel = Some(Self::create_sentinel(&keys));
        }

        let sman = SecretsManager {
            cryptokeys: keys,
            path: Some(PathBuf::from(path)),
            vault,
        };
        Ok(sman)
    }

    /// Saves changes to the underlying vault specified by the path supplied
    /// during construction of this `SecretsManager` instance.
    ///
    /// Note that changes to a `SecretsManager` instance and its underlying
    /// vault are transient and will be lost unlesss they are flushed to
    /// disk via [`save()`](Self::save()) or [`save_as()`](Self::save_as()).
    ///
    /// ## Panics:
    /// If a call to `save()` is made on a `SecretsManager` initialized with
    /// `SecretsManager::new()` rather `SecretsManager::load()`. Use `save_as()`
    /// instead.
    pub fn save(&self) -> Result<(), Error> {
        match self.path.as_ref() {
            Some(path) => self.vault.save(path),
            None => panic!(concat!(
                "Cannot call save() on a newly-created store without a path. ",
                "Use SecretsManager::save_as(&path) instead!"
            )),
        }
    }

    /// Export the current vault plus any changes that have been made to it to
    /// the path specified by the `path` argument.
    ///
    /// Note that changes to a `SecretsManager` instance and its underlying
    /// vault are transient and will be lost unlesss they are flushed to
    /// disk via [`save()`](Self::save()) or [`save_as()`](Self::save_as()).
    pub fn save_as<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.vault.save(path.as_ref())
    }

    /// Exports the private key(s) resident in memory to a path on-disk. Note
    /// that in addition to being used for exporting existing keys previously
    /// loaded into the secrets store and keys newly generated by the secrets
    /// store, it can also be used to export keys derived from passwords to
    /// their equivalent keyfiles to facilitate subsequent passwordless access.
    pub fn export_keyfile<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.cryptokeys.export(path)
    }

    /// Decrypt and retrieve the single secret identified by `name` from the
    /// loaded store as a `String`. If the secret cannot be found, an
    /// [`Error`] with [`Error::kind()`] set to
    /// [`ErrorKind::SecretNotFound`] is returned.
    ///
    /// See [`get_as()`](Self::get_as) to retrieve secrets of arbitrary types
    /// implementing [`BinaryDeserializable`].
    /// Out-of-the-box, this crate supports retrieving `String` and `Vec<u8>`
    /// secrets. [`BinaryDeserializable`] may be implemented to support
    /// directly retrieving arbitrary types, but it is preferred to
    /// internally deserialize from one of the primitive supported types
    /// previously mentioned after calling [`get()`](Self::get()) to ensure
    /// maximum compatibility with other SecureStore clients.
    pub fn get(&self, name: &str) -> Result<String, Error> {
        self.get_as::<String>(name)
    }

    /// Decrypt and retrieve the single secret identified by `name` from the
    /// loaded store, deserializing it to the requested type.
    /// If the secret cannot be found, an [`Error`] with [`Error::kind()`] set
    /// to [`ErrorKind::SecretNotFound`] is returned.
    ///
    /// Out-of-the-box, this crate supports retrieving `String` and `Vec<u8>`
    /// secrets. [`BinaryDeserializable`] may be implemented to support
    /// directly retrieving arbitrary types, but it is preferred to
    /// internally deserialize from one of the primitive supported types
    /// previously mentioned after calling [`get()`](Self::get()) to ensure
    /// maximum compatibility with other SecureStore clients.
    pub fn get_as<T: BinaryDeserializable>(&self, name: &str) -> Result<T, Error> {
        match self.vault.secrets.get(name) {
            None => ErrorKind::SecretNotFound.into(),
            Some(blob) => {
                let decrypted = blob.decrypt(&self.cryptokeys)?;
                T::deserialize(decrypted)
                    .map_err(|e| Error::from_inner(ErrorKind::DeserializationError, Box::new(e)))
            }
        }
    }

    /// Add a new secret or replace the existing secret identified by `name`
    /// with the value `value` to the store.
    ///
    /// Out-of-the-box, this crate supports `String`, `&str`, `Vec<u8>`, and
    /// `&[u8]` secrets. [`BinarySerializable`] may be implemented to
    /// support directly setting arbitrary types, but it is preferred to
    /// internally serialize to one of the primitive supported types
    /// previously mentioned before calling [`set()`](Self::set()) to ensure
    /// maximum compatibility with other SecureStore clients.
    pub fn set<T: BinarySerializable>(&mut self, name: &str, value: T) {
        let encrypted = EncryptedBlob::encrypt(&self.cryptokeys, T::serialize(&value));
        self.vault.secrets.insert(name.to_string(), encrypted);
    }

    /// Remove the secret identified by `name` from the store. If there is no
    /// secret by that name, an [`Error`] with [`Error::kind()`] set to
    /// [`ErrorKind::SecretNotFound`] is returned.
    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        self.vault
            .secrets
            .remove(name)
            .ok_or_else(|| ErrorKind::SecretNotFound.into())
            .map(|_| ())
    }

    /// Retrieve a list of the names of secrets stored in the vault.
    pub fn keys<'a>(&'a self) -> impl Iterator<Item = &'a str> {
        self.vault.secrets.keys().map(|s| s.as_str())
    }
}

impl<'a> KeySource<'a> {
    fn extract_keys(&self, iv: &[u8; shared::IV_SIZE]) -> Result<CryptoKeys, Error> {
        match &self {
            KeySource::Csprng => {
                let mut buffer = [0u8; shared::KEY_COUNT * shared::KEY_LENGTH];
                rand::rand_bytes(&mut buffer).expect("Key generation failure!");

                CryptoKeys::import(&buffer[..])
            }
            KeySource::File(path) => {
                let attr = std::fs::metadata(path)?;
                if attr.len() as usize != shared::KEY_COUNT * shared::KEY_LENGTH {
                    return ErrorKind::InvalidKeyfile.into();
                }

                let file = File::open(path)?;
                CryptoKeys::import(&file)
            }
            KeySource::Password(password) => {
                use openssl::pkcs5::pbkdf2_hmac;

                let mut key_data = [0u8; shared::KEY_COUNT * shared::KEY_LENGTH];
                pbkdf2_hmac(
                    password.as_bytes(),
                    iv,
                    shared::PBKDF2_ROUNDS,
                    shared::PBKDF2_DIGEST(),
                    &mut key_data,
                )
                .expect("PBKDF2 key generation failed!");

                CryptoKeys::import(&key_data[..])
            }
        }
    }
}
