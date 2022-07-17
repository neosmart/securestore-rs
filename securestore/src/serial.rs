//! This module houses the [`BinarySerializable`] and [`BinaryDeserializable`]
//! traits and implementations for the natively supported primitive secret
//! types.
//!
//! This is intentionally not implemented as a global impl for all
//! `TryFrom<&[u8]>`/`TryInto<Vec<u8>>` as the binary conversion must be stable
//! to survive cold storage. Keep in mind compatibility with other SecureStore
//! clients accessing or setting secrets in the same vault from
//! different languages or frameworks when implementing these traits, if that is
//! a concern.

/// A trait enabling directly saving a secret of the implementing type to the
/// SecureStore vault.
///
/// `BinarySerializable` implementations for `String`, `&str`, `Vec<u8>`, and
/// `&[u8]` are provided by this crate; implement this trait to support directly
/// setting other types via calls to
/// [`SecretsManager::set()`](crate::SecretsManager::set) but make sure to keep
/// compatibility with other clients accessing the same store from different
/// languages or frameworks in mind, if that is a concern.
pub trait BinarySerializable {
    fn serialize<'a>(&'a self) -> &'a [u8];
}

impl BinarySerializable for String {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self.as_bytes()
    }
}

impl BinarySerializable for &str {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self.as_bytes()
    }
}

impl BinarySerializable for Vec<u8> {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self.as_slice()
    }
}

impl BinarySerializable for &[u8] {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self
    }
}

/// A trait enabling directly retrieving a secret from the SecureStore vault as
/// an instance of the implementing type.
///
/// `BinaryDeserializable` implementations for `String` and `Vec<u8>` are
/// provided by this crate; implement this trait to support directly retrieving
/// other owned types via calls to
/// [`SecretsManager::get()`](crate::SecretsManager::set) but make sure to keep
/// compatibility with other clients accessing the same store from different
/// languages or frameworks in mind, if that is a concern.
pub trait BinaryDeserializable
where
    Self: Sized,
{
    type Error: std::error::Error + Send + Sync + 'static;
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Self::Error>;
}

impl BinaryDeserializable for String {
    type Error = std::string::FromUtf8Error;
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(String::from_utf8(bytes)?)
    }
}

impl BinaryDeserializable for Vec<u8> {
    type Error = std::convert::Infallible;
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(bytes)
    }
}
