//! This module contains code that must line up between the various implementations of SecureStore
//! in different languages.

use crate::errors::Error;
use openssl::rand;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// The number of keys we require to be derived from source materials
pub const KEY_COUNT: usize = 2;
/// The length of each individual key in bytes
pub const KEY_LENGTH: usize = 128 / 8;
/// The number of rounds used for PBKDF2 key derivation
pub const PBKDF2_ROUNDS: usize = 10000usize;
/// The size of an initialization vector in bytes
pub const IV_SIZE: usize = KEY_LENGTH;
/// The latest version of the vault schema
pub const SCHEMA_VERSION: u32 = 1;
/// The length of a single HMAC result in bytes
pub const HMAC_SIZE: usize = 160 / 8; // HMAC-SHA1

/// A representation of the on-disk encrypted secrets store. Read and written via
/// `[SecretsManager]`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    /// The version of the serialized vault
    pub version: u32,
    /// The initialization vector for key derivation
    pub iv: Option<[u8; IV_SIZE]>,
    /// The secrets we are tasked with protecting, sorted for version control friendliness.
    pub data: BTreeMap<String, EncryptedBlob>,
}

/// A single secret, independently encrypted and individually decrypted on-demand.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedBlob {
    pub iv: [u8; IV_SIZE],
    pub hmac: [u8; HMAC_SIZE],
    pub payload: Vec<u8>,
}

impl Vault {
    pub fn new() -> Self {
        let mut iv = [0u8; IV_SIZE];
        rand::rand_bytes(&mut iv).expect("IV generation failure!");

        Vault {
            version: SCHEMA_VERSION,
            iv: Some(iv),
            data: Default::default(),
        }
    }

    fn validate(vault: Self) -> Result<Self, Error> {
        if vault.version != SCHEMA_VERSION {
            return Err(Error::UnsupportedVaultVersion);
        }

        Ok(vault)
    }

    pub(crate) fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path).map_err(Error::Io)?;

        Self::load(file)
    }

    pub fn load<R: Read>(source: R) -> Result<Self, Error> {
        let vault = serde_json::from_reader(source).map_err(|e| Error::Serde(e))?;

        Self::validate(vault)
    }

    pub fn save<P: AsRef<Path>>(&self, dest: P) -> Result<(), Error> {
        let path = dest.as_ref();

        let file = File::create(path).map_err(Error::Io)?;
        serde_json::to_writer(file, &self).map_err(Error::Serde)
    }
}

/// The keys contained in a binary key file, in the same order they are stored.
///
/// While the consensus is that SHA1-HMAC and AES are sufficiently different that
/// there should not be a problem reusing the same key for both operations when
/// implementing authenticated encryption (as AES-CBC and HMAC-SHA1), but out of
/// an abundance of precaution we create/derive two separate keys entirely for
/// these two operations.
#[derive(Debug, Eq, PartialEq)]
pub struct Keys {
    /// The key used to encrypt the secrets.
    pub encryption: [u8; KEY_LENGTH],
    /// The key used to generate the HMAC used for authenticated encryption.
    pub hmac: [u8; KEY_LENGTH],
}

impl Keys {
    /// Exports the private key(s) resident in memory to a path on-disk. The exact
    /// binary format (including key order) lines up with other implementations.
    pub fn export<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut file = File::create(path).map_err(Error::Io)?;

        file.write_all(&self.encryption).map_err(Error::Io)?;
        file.write_all(&self.hmac).map_err(Error::Io)
    }

    /// Imports keys from a bytestream
    pub fn import<R: Read>(mut source: R) -> Result<Self, Error> {
        let mut keys: Keys = Keys {
            encryption: [0u8; KEY_LENGTH],
            hmac: [0u8; KEY_LENGTH],
        };

        source
            .read_exact(&mut keys.encryption)
            .map_err(|_| Error::InvalidKeyfile)?;
        source
            .read_exact(&mut keys.hmac)
            .map_err(|_| Error::InvalidKeyfile)?;

        Ok(keys)
    }
}

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{self, Cipher};

impl EncryptedBlob {
    /// Creates an `EncryptedBlob` from a plaintext secret.
    pub fn encrypt(keys: &Keys, secret: &[u8]) -> EncryptedBlob {
        let cipher = Cipher::aes_128_cbc();
        let mut iv = [0u8; KEY_LENGTH];

        rand::rand_bytes(&mut iv).expect("Error reading IV bytes from RNG!");

        // Unlike with decryption, we don't expect this to ever fail
        let payload = symm::encrypt(cipher, &keys.encryption, Some(&iv), secret)
            .expect("Error encrypting payload!");

        EncryptedBlob {
            hmac: Self::calculate_hmac(&keys.hmac, &iv, &payload),
            iv,
            payload,
        }
    }

    /// Decrypts an `EncryptedBlob` object and retrieves the plaintext equivalent
    /// of `[EncryptedBlob::Data]`.
    pub fn decrypt(&self, keys: &Keys) -> Result<Vec<u8>, Error> {
        if !self.authenticate(&keys.hmac) {
            return Err(Error::DecryptionFailure);
        }

        let cipher = Cipher::aes_128_cbc();
        symm::decrypt(cipher, &keys.encryption, Some(&self.iv), &self.payload)
            .map_err(|_| Error::DecryptionFailure)
    }

    fn calculate_hmac(
        &hmac_key: &[u8; KEY_LENGTH],
        &iv: &[u8; IV_SIZE],
        encrypted: &[u8],
    ) -> [u8; HMAC_SIZE] {
        let key = PKey::hmac(&hmac_key).expect("Failed to load HMAC encryption key!");
        let mut signer =
            Signer::new(MessageDigest::sha1(), &key).expect("Failed to create HMAC signer!");

        signer.update(&iv).unwrap();
        signer.update(&encrypted).unwrap();

        let mut hmac = [0u8; HMAC_SIZE];
        signer
            .sign(&mut hmac)
            // this is not the same as the HMAC not matching
            .expect("Failed to create HMAC signature!");

        hmac
    }

    /// Authenticates the encrypted payload against the provided HMAC key
    pub fn authenticate(&self, &hmac_key: &[u8; KEY_LENGTH]) -> bool {
        let hmac = Self::calculate_hmac(&hmac_key, &self.iv, &self.payload);
        openssl::memcmp::eq(&hmac, &self.hmac)
    }
}
