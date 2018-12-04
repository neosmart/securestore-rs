//! This module contains code that must line up between the various implementations of SecureStore
//! in different languages.

use crate::errors::Error;
use openssl::rand;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The number of keys we require to be derived from source materials
pub const KEY_COUNT: usize = 2;
/// The length of each individual key in bytes
pub const KEY_LENGTH: usize = 128 / 8;
/// The number of rounds used for PBKDF2 key derivation
pub const PBKDF2_ROUNDS: u32 = 10000;
/// The size of an initialization vector in bytes
pub const IV_SIZE: usize = KEY_LENGTH;
/// The latest version of the vault schema
pub const SCHEMA_VERSION: u32 = 1;

/// A representation of the on-disk encrypted secrets store. Read and written via
/// `[SecretsManager]`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    /// The version of the serialized vault
    pub version: u32,
    /// The initialization vector for the
    pub iv: [u8; IV_SIZE],
}

impl Vault {
    pub fn new() -> Self {
        let mut iv = [0u8; IV_SIZE];
        rand::rand_bytes(&mut iv).expect("IV generation failure!");

        Vault {
            version: SCHEMA_VERSION,
            iv: iv,
        }
    }

    fn validate(vault: Self) -> Result<Self, Error> {
        if vault.version != SCHEMA_VERSION {
            return Err(Error::UnsupportedVaultVersion);
        }

        Ok(vault)
    }

    pub fn from_str(json: &str) -> Result<Self, Error> {
        let vault = serde_json::from_str(json).map_err(Error::Serde)?;

        Self::validate(vault)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path).map_err(Error::Io)?;
        let vault = serde_json::from_reader(file).map_err(Error::Serde)?;

        Self::validate(vault)
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
