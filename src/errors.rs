pub enum Error {
    MissingVaultIV,
    InvalidKeyfile,
    UnsupportedVaultVersion,
    Serde(serde_json::Error),
    Io(std::io::Error),
}
