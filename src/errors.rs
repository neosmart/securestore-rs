#[derive(Debug)]
pub enum Error {
    MissingVaultIV,
    InvalidKeyfile,
    /// May be caused by using the wrong key or attempting to load ciphertext that has been
    /// tampered with.
    DecryptionFailure,
    SecretNotFound,
    UnsupportedVaultVersion,
    Serde(serde_json::Error),
    Io(std::io::Error),
}
