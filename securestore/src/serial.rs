//! This module houses various implementations of [`BinarySerializable`] which
//! are natively supported payloads for secrets. This is intentionally not
//! implemented as a global impl for all `TryFrom<u8>`/`TryInto<u8>` as the
//! binary conversion must be stable to survive cold storage.

pub trait BinarySerializable {
    fn serialize<'a>(&'a self) -> &'a [u8];
}

pub trait BinaryDeserializable
where
    Self: Sized,
{
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Box<dyn std::error::Error + 'static>>;
}

impl BinarySerializable for String {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self.as_bytes()
    }
}

impl BinaryDeserializable for String {
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let s = String::from_utf8(bytes)?;
        Ok(s)
    }
}

impl BinarySerializable for &str {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self.as_bytes()
    }
}

impl BinarySerializable for &[u8] {
    fn serialize<'a>(&'a self) -> &'a [u8] {
        self
    }
}

impl BinaryDeserializable for Vec<u8> {
    fn deserialize(bytes: Vec<u8>) -> Result<Self, Box<dyn std::error::Error + 'static>> {
        Ok(bytes)
    }
}
