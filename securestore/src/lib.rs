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
//! A full and annotated example of using `ssclient` and this `securestore`
//! crate in tandem [may be found online](https://github.com/neosmart/securestore-rs/blob/master/README.md),
//! but an abbreviated version is shown below.
//!
//! # Example
//!
//! First, create a new store and set some secret value at the command line with
//! the companion `ssclient` crate:
//!
//! ```sh
//! $ cargo install ssclient
//! $ ssclient create secrets.json --export-key secrets.key
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
//! # sman.export_key("secrets.key");
//! # sman.save_as("secrets.json");
//! # drop (sman);
//!
//! let key_path = Path::new("secrets.key");
//! let sman = SecretsManager::load("secrets.json", KeySource::Path(key_path))
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
/// [`KeySource::Path`] variant). See [`SecretsManager::export_key()`] or
/// the `ssclient` documentation for more info.
///
/// Note that when creating a new vault with [`KeySource::Csprng`] the generated
/// private keys should be exported via [`SecretsManager::export_key()`]
/// before dropping the `SecretsManager` instance; the exported keyfile should
/// then be used the next time the vault is loaded (via [`KeySource::Path`]).
#[non_exhaustive]
#[derive(Clone)]
pub enum KeySource<'a> {
    /// Load the keys from a keyfile on-disk. Both binary and PEM keyfiles are
    /// supported.
    Path(&'a Path),

    /// Load the keys from the provided buffer. Both binary and PEM key formats
    /// are supported.
    Buffer(&'a [u8]),

    /// Derive keys from the specified password.
    ///
    /// You most likely do not want to use this `KeySource` variant directly;
    /// instead use [`ssclient`] with a password when managing the secrets
    /// in the SecureStore vault at the command line, and use `ssclient` to
    /// export a keyfile equivalent to that password to use to retrieve
    /// passwords at runtime (via [`KeySource::Path`] or
    /// [`KeySource::from_file()`).
    ///
    /// [`ssclient`]: https://neosmart.net/blog/2020/securestore-open-secrets-format/
    Password(&'a str),

    /// Automatically generate a new key file from a secure RNG, for use with
    /// [`SecretsManager::new()`] only.
    ///
    /// [`SecretsManager::export_key()`] should be used to export the
    /// keys before the `SecretsManager` instance is disposed or else the
    /// generated key will be lost and secrets will not be decryptable. The
    /// store should subsequently be loaded with [`KeySource::Path`] pointing to
    /// the exported key's path.
    Csprng,
}

/// This type is used internally for generic function overload purposes. See and
/// use [`KeySource`] instead.
pub trait GenericKeySource {
    fn key_source(&self) -> KeySource;
}

impl<'a> KeySource<'a> {
    // This is purposely named like an enum variant for backwards compatibility.
    #[doc(hidden)]
    #[allow(non_snake_case)]
    pub fn File<P: AsRef<Path>>(path: P) -> impl GenericKeySource {
        path
    }

    /// Use in lieu of `KeySource::Path` for cases where `path` implements
    /// `AsRef<Path>` but isn't specifically a `&Path` itself.
    pub fn from_file<P: AsRef<Path>>(path: P) -> impl GenericKeySource {
        path
    }
}

impl<P: AsRef<Path>> GenericKeySource for P {
    fn key_source(&self) -> KeySource {
        KeySource::Path(self.as_ref())
    }
}

impl<'a> GenericKeySource for KeySource<'_> {
    fn key_source(&self) -> KeySource {
        match self {
            Self::Csprng => KeySource::Csprng,
            Self::Path(p) => KeySource::Path(p),
            Self::Buffer(b) => KeySource::Buffer(*b),
            Self::Password(p) => KeySource::Password(p),
        }
    }
}

impl GenericKeySource for &KeySource<'_> {
    fn key_source(&self) -> KeySource {
        (*self).key_source()
    }
}

/// `SecretsManager` is the primary interface used for interacting with this
/// crate, and is an in-memory representation of an encrypted SecureStore vault.
///
/// An existing plain-text SecureStore vault can be loaded with
/// [`SecretsManager::load()`] or a new vault can be created with [`new()`] and
/// then saved to disk with [`save()`] or [`save_as()`].
///
/// Individual secrets can be set, retrieved, and removed with
/// [`SecretsManager::set()`], [`get()`], and [`remove()`] respectively. The
/// names/keys of all secrets stored in this vault can be enumerated via
/// [`SecretsManager::keys()`].
///
/// [`new()`]: Self::new()
/// [`save()`]: Self::save()
/// [`save_as()`]: Self::save_as()
/// [`get()`]: Self::get()
/// [`remove()`]: Self::remove()
pub struct SecretsManager {
    vault: Vault,
    path: Option<PathBuf>,
    cryptokeys: CryptoKeys,
}

/// This type is used for generic function overload purposes to allow
/// [`SecretsManager::load()`] to read from a `Read` instance or a path. You
/// shouldn't need to use it directly.
pub trait GenericVaultSource<'a> {
    type Source: std::io::Read;
    type Error: std::error::Error + Send + Sync + 'static;

    /// If the implementing type can also be reached via a `Path`, this trait
    /// method should return the equivalent path here so that
    /// [`SecretsManager::save()`] can work.
    fn path(&self) -> Option<PathBuf>;

    /// Creates and returns a `Read` source from the implementing type that is
    /// used by [`SecretsManager::load()`] to load the vault from an
    /// arbitrary type.
    fn as_read(&'a self) -> Result<Self::Source, Self::Error>;
}

/// An implementation of [`GenericVaultSource`] for paths and path-like values,
/// so that a path can be passed directly as the first parameter of a call to
/// [`SecretsManager::load()`].
impl<P: AsRef<Path>> GenericVaultSource<'_> for P {
    type Source = File;
    type Error = std::io::Error;

    fn path(&self) -> Option<PathBuf> {
        Some(PathBuf::from(self.as_ref()))
    }

    fn as_read(&self) -> Result<Self::Source, Self::Error> {
        let path = self.as_ref();
        File::open(path)
    }
}

// We aren't manually implementing Send/Sync for `SecretsManager`, but we need
// to make sure that it implements them all the same for ergonomic reasons.
const _: () = {
    // It is sufficient to declare the generic function pointers; calling them
    // too would require using `const fn` with Send/Sync constraints which wasn't
    // stabilized until rustc 1.61.0
    fn assert_send<T: Send>() {}
    let _ = assert_send::<SecretsManager>;
    fn assert_sync<T: Sync>() {}
    let _ = assert_sync::<SecretsManager>;
};

impl SecretsManager {
    fn create_sentinel(keys: &CryptoKeys) -> EncryptedBlob {
        let mut random = [0u8; shared::IV_SIZE * 2];
        rand::rand_bytes(&mut random).expect("Failed to create sentinel");
        EncryptedBlob::encrypt(&keys, &random)
    }

    /// Creates a new instance of `SecretsManager`, encrypting its secrets with
    /// the specified [`KeySource`].
    ///
    /// Note that the usage of [`KeySource::Path`] is taken to mean that there
    /// is an existing compatible private key already available at the
    /// specified path. To generate a new key file, use [`KeySource::Csprng`]
    /// then export the generated key to the desired path with
    /// [`export_key()`](Self::export_key).
    ///
    /// Most users will likely prefer to create a new SecureStore vault and
    /// manage its secrets by using the companion CLI utility [`ssclient`],
    /// then [`load()`](Self::load) the SecureStore at runtime to retrieve
    /// its secrets.
    ///
    /// [`ssclient`]: https://github.com/neosmart/securestore-rs/tree/master/ssclient
    pub fn new<K: GenericKeySource>(key_source: K) -> Result<SecretsManager, Error> {
        let key_source = key_source.key_source();
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
    /// [`save()`] or [`save_as()`] is called.
    ///
    /// ## Panics:
    /// In debug mode, if an attempt is made to load an existing vault but
    /// `key_source` is set to [`KeySource::Csprng`] (which should only be
    /// used when initializing a new secrets vault). In release mode, this does
    /// not panic but the vault will invariably fail to decrypt.
    ///
    /// [`save()`]: SecretsManager::save()
    /// [`save_as()`]: SecretsManager::save_as()
    ///
    /// ## Example:
    ///
    /// First, in the shell:
    /// ```sh
    /// ssclient create secrets.json --export-key secrets.key
    /// ssclient set password mYpassWORD123
    /// ```
    ///
    /// Then, in rust:
    /// ```no_run
    /// use securestore::SecretsManager;
    ///
    /// let secrets = SecretsManager::load("secrets.json", "secrets.key").unwrap();
    /// let password = secrets.get("password").unwrap();
    /// assert_eq!(password, String::from("mYpassWORD123"));
    /// ```
    pub fn load<V, K: GenericKeySource>(
        vault_source: V,
        key_source: K,
    ) -> Result<SecretsManager, Error>
    where
        for<'v> V: GenericVaultSource<'v>,
    {
        let key_source = key_source.key_source();
        // We intentionally only panic here in debug mode, only because we try to avoid
        // panicking in production if possible. This isn't a logic error (the code will
        // still run and everything will work without any incorrect behavior) but the
        // user will just never get the desired results (loading an existing store with
        // a newly generated key will just always fail to decrypt the store contents).
        // Tl;dr it's not unsafe or technically incorrect, just stupid.
        if matches!(key_source, KeySource::Csprng) {
            debug_assert!(
                false,
                concat!(
                    "It is incorrect to call SecretsManager::load() ",
                    "except with an existing key source!"
                )
            );
        }

        let mut vault = Vault::load(
            vault_source
                .as_read()
                .map_err(|e| Error::from_inner(ErrorKind::IoError, e))?,
        )?;
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
            path: vault_source.path(),
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
    /// `SecretsManager::new()` rather than opened with `load()`; use
    /// `save_as()` instead.
    ///
    /// [`load()`]: Self::load()
    pub fn save(&self) -> Result<(), Error> {
        match self.path.as_ref() {
            Some(path) => self.save_as(path),
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
        let path = path.as_ref();
        let file = File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        self.vault.save(file)
    }

    /// Exports the private key(s) resident in memory to a path on-disk. Note
    /// that in addition to being used for exporting existing keys previously
    /// loaded into the secrets store and keys newly generated by the secrets
    /// store, it can also be used to export keys derived from passwords to
    /// their equivalent keyfiles to facilitate subsequent passwordless access.
    ///
    /// As of securestore 0.100, the keyfile is written in a PEM-like format,
    /// with ASCII armor and a base64-encoded payload. Previous versions
    /// exported a binary version of the keyfile. Both are fully supported.
    ///
    /// ## Example:
    ///
    /// ```rust
    /// use securestore::{SecretsManager, KeySource};
    ///
    /// let vault_pass = KeySource::Password("myVaultPass123");
    /// let mut sman = SecretsManager::new(vault_pass).unwrap();
    /// sman.set("password", "password123");
    /// sman.save_as("secrets.json").unwrap();
    /// sman.export_key("passwordless.key").unwrap();
    ///
    /// // We can now use either the vault password "myVaultPass123" or the
    /// // equivalent keyfile "passwordless.key" to load the store and access
    /// // the secrets.
    ///
    /// let vault_key = KeySource::from_file("passwordless.key");
    /// let sman = SecretsManager::load("secrets.json", vault_key).unwrap();
    /// assert_eq!("password123", sman.get("password").unwrap());
    ///
    /// # std::fs::remove_file("secrets.json").unwrap();
    /// # std::fs::remove_file("passwordless.key").unwrap();
    /// ```
    pub fn export_key<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.cryptokeys.export(path)
    }

    #[doc(hidden)]
    #[inline]
    /// A backwards-compatibile alias for export_key()
    pub fn export_keyfile<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.export_key(path)
    }

    /// Decrypt and retrieve the single secret identified by `name` from the
    /// loaded store as a `String`. If the secret cannot be found, an
    /// [`Error`] with [`Error::kind()`] set to
    /// [`ErrorKind::SecretNotFound`] is returned.
    ///
    /// See [`get_as()`](Self::get_as) to retrieve either binary secrets or
    /// secrets of arbitrary types implementing [`BinaryDeserializable`].
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
                    .map_err(|e| Error::from_inner(ErrorKind::DeserializationError, e))
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
            KeySource::Path(path) => {
                let attr = std::fs::metadata(path)?;
                if (attr.len() as usize) < (shared::KEY_COUNT * shared::KEY_LENGTH) {
                    return ErrorKind::InvalidKeyfile.into();
                }

                let file = File::open(path)?;
                CryptoKeys::import(file)
            }
            KeySource::Buffer(buf) => CryptoKeys::import(&buf[..]),
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
