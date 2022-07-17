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

/// Used to specify where encryption/decryption keys should be loaded from
#[non_exhaustive]
#[derive(Clone)]
pub enum KeySource<'a> {
    /// Load the keys from a binary file on-disk
    File(&'a Path),
    /// Derive keys from the specified password
    Password(&'a str),
    /// Automatically generate a new key file from a secure RNG.
    ///
    /// [`SecretsManager::export_keyfile()`] should be used to export the
    /// keys before the instance is disposed. The store can then subsequently be
    /// loaded with a [`KeySource::File`] pointing to the file exported by
    /// [`SecretsManager::export_keyfile()`].
    Csprng,
}

/// The primary interface used for interacting with the SecureStore.
pub struct SecretsManager {
    vault: Vault,
    path: PathBuf,
    cryptokeys: CryptoKeys,
}

impl SecretsManager {
    fn create_sentinel(keys: &CryptoKeys) -> EncryptedBlob {
        let mut random = [0u8; shared::IV_SIZE * 2];
        rand::rand_bytes(&mut random).expect("Failed to create sentinel");
        EncryptedBlob::encrypt(&keys, &random)
    }

    /// Creates a new vault on-disk at path `path` and loads it in a new
    /// instance of `SecretsManager`.
    ///
    /// Note that the vault is not written to disk unless and until
    /// [`SecretsManager::save()`]/[`SecretsManager::save_as()`] is called.
    pub fn new<P1: AsRef<Path>>(path: P1, key_source: KeySource) -> Result<Self, Error> {
        let path = path.as_ref();

        let mut vault = Vault::new();
        let keys = key_source.extract_keys(&vault.iv)?;
        vault.sentinel = Some(Self::create_sentinel(&keys));
        Ok(SecretsManager {
            cryptokeys: keys,
            path: PathBuf::from(path),
            vault,
        })
    }

    /// Load the contents of an on-disk SecureStore vault located at `path`
    /// into a new `SecretsManager` instance, decrypting its contents with
    /// the [`KeySource`] specified by the `key_source` parameter.
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
            path: PathBuf::from(path),
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
    pub fn save(&self) -> Result<(), Error> {
        self.vault.save(&self.path)
    }

    /// Export the current vault plus any changes that have been made to it to
    /// the path specified by the `path` argument.
    ///
    /// Note that changes to a `SecretsManager` instance and its underlying
    /// vault are transient and will be lost unlesss they are flushed to
    /// disk via [`save()`](Self::save()) or [`save_as()`](Self::save_as()).
    pub fn save_as(&self, path: &Path) -> Result<(), Error> {
        self.vault.save(path)
    }

    /// Exports the private key(s) resident in memory to a path on-disk. Note
    /// that in addition to being used for exporting existing keys previously
    /// loaded into the secrets store and keys newly generated by the secrets
    /// store, it can also be used to export keys derived from passwords to
    /// their equivalent keyfiles to facilitate subsequent passwordless access.
    pub fn export_keyfile<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.cryptokeys.export(path)
    }

    /// Decrypts and retrieves a single secret from the loaded store. If the
    /// secret cannot be found, returns `Err(ErrorKind::SecretNotFound)`
    pub fn get<T: BinaryDeserializable>(&self, name: &str) -> Result<T, Error> {
        match self.vault.secrets.get(name) {
            None => ErrorKind::SecretNotFound.into(),
            Some(blob) => {
                let decrypted = blob.decrypt(&self.cryptokeys)?;
                T::deserialize(decrypted)
                    .map_err(|e| Error::from_inner(ErrorKind::DeserializationError, Box::new(e)))
            }
        }
    }

    /// Adds a new secret or replaces an existing secret identified by `name` to
    /// the store.
    pub fn set<T: BinarySerializable>(&mut self, name: &str, value: T) {
        let encrypted = EncryptedBlob::encrypt(&self.cryptokeys, T::serialize(&value));
        self.vault.secrets.insert(name.to_string(), encrypted);
    }

    /// Remove a secret identified by `name` from the store.
    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        self.vault
            .secrets
            .remove(name)
            .ok_or(ErrorKind::SecretNotFound.into())
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
