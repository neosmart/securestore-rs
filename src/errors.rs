pub enum Error {
    UnsupportedVaultVersion,
    Serde(serde_json::Error),
    Io(std::io::Error),
}
