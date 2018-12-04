pub enum Error {
    MissingVaultIV,
    UnsupportedVaultVersion,
    Serde(serde_json::Error),
    Io(std::io::Error),
}
