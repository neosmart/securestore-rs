//! This (private) module contains code that must line up between the various
//! implementations of SecureStore in different languages.

use crate::errors::{Error, ErrorKind};
use openssl::hash::MessageDigest;
use openssl::rand;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// The number of keys we require to be derived from source materials
pub const KEY_COUNT: usize = 2;
/// The length of each individual key in bytes
pub const KEY_LENGTH: usize = 128 / 8;
/// The number of rounds used for PBKDF2 key derivation. The resulting key is
/// still considered to be a secret and is not stored!
pub const PBKDF2_ROUNDS: usize = 256_000;
/// The hash function used for PBKDF2, but only when password-based encryption/
/// decryption is used. CSPRNG-derived symmetric keys are intentionally not
/// stretched as their entropy may be constrained by the PBKDF2 digest, (at
/// the cost of being vulnerable to a weekly seeded or compromised CSPRNG).
pub const PBKDF2_DIGEST: fn() -> MessageDigest = MessageDigest::sha1;
/// The size of an initialization vector in bytes
pub const IV_SIZE: usize = KEY_LENGTH;
/// The latest version of the vault schema
pub const SCHEMA_VERSION: u32 = 3;
/// The length of a single HMAC result in bytes
pub const HMAC_SIZE: usize = 160 / 8; // HMAC-SHA1

/// A representation of the on-disk encrypted secrets store. Read and written
/// via `[SecretsManager]`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    /// The version of the serialized vault
    pub version: u32,
    /// The initialization vector for key derivation
    #[serde(serialize_with = "to_base64", deserialize_with = "iv_from_base64")]
    pub iv: [u8; IV_SIZE],
    /// An optional sentinel, used to verify that the same key/password is used
    /// across invocations. To be more clear, while it is permitted for a vault
    /// not to contain a sentinel, any SecureStore-compliant library/app must
    /// check for and create a sentinel if it doesn't exist - i.e. this isn't an
    /// optional part of the SecureStore spec.
    pub sentinel: Option<EncryptedBlob>,
    /// The secrets we are tasked with protecting, sorted for version control
    /// friendliness.
    pub secrets: BTreeMap<String, EncryptedBlob>,
}

/// A single secret, independently encrypted and individually decrypted
/// on-demand.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedBlob {
    #[serde(serialize_with = "to_base64", deserialize_with = "iv_from_base64")]
    pub iv: [u8; IV_SIZE],
    #[serde(serialize_with = "to_base64", deserialize_with = "hmac_from_base64")]
    pub hmac: [u8; HMAC_SIZE],
    #[serde(serialize_with = "to_base64", deserialize_with = "vec_from_base64")]
    pub payload: Vec<u8>,
}

fn to_base64<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(value.as_ref()))
}

fn iv_from_base64<'de, D>(deserializer: D) -> Result<[u8; IV_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    // We can't deserialize to a borrowed type (&str or &[u8]) because we
    // deserialize with serde_json::from_reader, which doesn't support borrowing
    // and mandates copying into a user-provided buffer :(
    let b64: String = Deserialize::deserialize(deserializer)?;

    let mut result = [0u8; IV_SIZE];
    base64::decode_config_slice(&b64, base64::STANDARD, &mut result)
        .map_err(|e| Error::custom(e.to_string()))?;

    Ok(result)
}

fn hmac_from_base64<'de, D>(deserializer: D) -> Result<[u8; HMAC_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let b64: String = Deserialize::deserialize(deserializer)?;

    let mut result = [0u8; HMAC_SIZE];
    base64::decode_config_slice(&b64, base64::STANDARD, &mut result)
        .map_err(|e| Error::custom(e.to_string()))?;

    Ok(result)
}

fn vec_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: String = Deserialize::deserialize(deserializer)?;
    base64::decode(&s).map_err(|e| Error::custom(e.to_string()))
}

impl Vault {
    pub fn new() -> Self {
        let mut iv = [0u8; IV_SIZE];
        rand::rand_bytes(&mut iv).expect("IV generation failure!");

        Vault {
            version: SCHEMA_VERSION,
            iv,
            secrets: Default::default(),
            sentinel: None,
        }
    }

    fn validate(vault: Self) -> Result<Self, Error> {
        if vault.version != SCHEMA_VERSION {
            return ErrorKind::UnsupportedVaultVersion.into();
        }

        Ok(vault)
    }

    #[allow(unused)]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path)?;

        Self::load(file)
    }

    pub fn load<R: Read>(source: R) -> Result<Self, Error> {
        let vault = serde_json::from_reader(source)?;

        Self::validate(vault)
    }

    pub fn save<W: Write>(&self, dest: W) -> Result<(), Error> {
        // Using `to_writer_pretty()` makes changes to the store play nicer
        // with version control and plain-text diffing.
        serde_json::to_writer_pretty(dest, &self)?;
        Ok(())
    }
}

/// The keys contained in a binary key file, in the same order they are stored.
///
/// While the consensus is that SHA1-HMAC and AES are sufficiently different
/// that there should not be a problem reusing the same key for both operations
/// when implementing authenticated encryption (as AES-CBC and HMAC-SHA1), but
/// out of an abundance of precaution we create/derive two separate keys
/// entirely for these two operations.
#[derive(Debug, Eq, PartialEq)]
pub struct CryptoKeys {
    /// The key used to encrypt the secrets.
    pub encryption: [u8; KEY_LENGTH],
    /// The key used to generate the HMAC used for authenticated encryption.
    pub hmac: [u8; KEY_LENGTH],
}

impl CryptoKeys {
    /// Exports the private key(s) resident in memory to a path on-disk. The
    /// exact binary format (including key order) lines up with other
    /// implementations.
    pub fn export<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut file = File::create(path)?;
        let mut b64_writer = base64::write::EncoderStringWriter::new(base64::STANDARD);

        file.write_all(b"-----BEGIN PRIVATE KEY-----\n")
            .map_err(|e| Error::from_inner(ErrorKind::IoError, e))?;

        b64_writer.write_all(&self.encryption).unwrap();
        b64_writer.write_all(&self.hmac).unwrap();
        let encoded = b64_writer.into_inner();
        // encoded.as_bytes() is guaranteed to be ASCII, so we can index it safely
        let mut encoded = encoded.as_bytes();

        loop {
            let line_bytes = match encoded.len() {
                0 => break,
                65.. => &encoded[0..63],
                _ => encoded,
            };

            file.write_all(line_bytes)
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|e| Error::from_inner(ErrorKind::IoError, e))?;
            encoded = &encoded[line_bytes.len()..];
        }

        file.write_all(b"-----END PRIVATE KEY-----\n")
            .map_err(|e| Error::from_inner(ErrorKind::IoError, e))?;

        Ok(())
    }

    /// Imports keys from a bytestream
    pub fn import<R: Read>(mut source: R) -> Result<Self, Error> {
        const MAX_READ: usize = 4096;

        // A legacy/binary key is KEY_COUNT * KEY_LENGTH == 32 bytes, while the new
        // ASCII-armored base64 key format (PEM-like) is 90 bytes as generated
        // by `export()` (begin block, new line, 4*(KEY_COUNT * KEY_LENGTH)/3
        // base64 bytes (with a new line after every 64th base64 character), end
        // block, and trailing new line).
        let mut buffer = vec![0u8; 128];
        let mut total_read = 0;
        loop {
            let bytes_read = match source.read(&mut buffer[total_read..]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from_inner(ErrorKind::IoError, e)),
                Ok(0) => break,
                Ok(count) => count,
            };
            total_read += bytes_read;

            if total_read > MAX_READ {
                return Err(ErrorKind::InvalidKeyfile.into());
            } else if total_read == buffer.len() {
                buffer.resize(buffer.len() + 128, 0u8);
            }
        }
        // Shadow `buffer` to prevent reading past valid data
        let buffer = &buffer[..total_read];

        if buffer.len() == KEY_LENGTH * KEY_COUNT {
            // Input was binary keys concatenated (legacy or in-memory format)
            Self::import_binary(buffer)
        } else {
            // Try loading as base64/PEM format
            use std::io::{BufRead, BufReader};

            #[derive(PartialEq)]
            enum ParseState {
                WaitingStart,
                WaitingEnd,
                Complete,
            }

            let mut encoded = String::new();
            let mut state = ParseState::WaitingStart;
            let source = BufReader::new(buffer);
            for line in source.lines() {
                let line = line.map_err(|e| Error::from_inner(ErrorKind::InvalidKeyfile, e))?;
                let line = line.trim();

                if state == ParseState::WaitingStart {
                    if line == "-----BEGIN PRIVATE KEY-----" {
                        state = ParseState::WaitingEnd;
                    }
                    continue;
                } else if line == "-----END PRIVATE KEY-----" {
                    state = ParseState::Complete;
                    break;
                }

                encoded.push_str(line);
            }

            if state != ParseState::Complete {
                return Err(ErrorKind::InvalidKeyfile.into());
            }
            let decoded = base64::decode(encoded)
                .map_err(|e| Error::from_inner(ErrorKind::InvalidKeyfile, e))?;
            if decoded.len() != KEY_COUNT * KEY_LENGTH {
                return Err(ErrorKind::InvalidKeyfile.into());
            }

            Self::import_binary(&decoded)
        }
    }

    fn import_binary(buffer: &[u8]) -> Result<Self, Error> {
        use std::convert::TryInto;

        if buffer.len() != KEY_COUNT * KEY_LENGTH {
            return ErrorKind::InvalidKeyfile.into();
        }

        Ok(CryptoKeys {
            encryption: buffer[0..KEY_LENGTH].try_into().unwrap(),
            hmac: buffer[KEY_LENGTH..][..KEY_LENGTH].try_into().unwrap(),
        })
    }
}

use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{self, Cipher};

impl EncryptedBlob {
    /// Creates an `EncryptedBlob` from a plaintext secret.
    pub fn encrypt<'a>(keys: &CryptoKeys, secret: &'a [u8]) -> EncryptedBlob {
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

    /// Decrypts an `EncryptedBlob` object and retrieves the plaintext
    /// equivalent of `[EncryptedBlob::Data]`.
    pub fn decrypt(&self, keys: &CryptoKeys) -> Result<Vec<u8>, Error> {
        if !self.authenticate(&keys.hmac) {
            return ErrorKind::DecryptionFailure.into();
        }

        let cipher = Cipher::aes_128_cbc();
        let result = symm::decrypt(cipher, &keys.encryption, Some(&self.iv), &self.payload)?;

        Ok(result)
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
            // NB: this is not the same as the HMAC not matching
            .expect("Failed to create HMAC signature!");

        hmac
    }

    /// Authenticates the encrypted payload against the provided HMAC key
    pub fn authenticate(&self, &hmac_key: &[u8; KEY_LENGTH]) -> bool {
        let hmac = Self::calculate_hmac(&hmac_key, &self.iv, &self.payload);
        openssl::memcmp::eq(&hmac, &self.hmac)
    }
}
