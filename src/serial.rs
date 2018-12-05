//! This module houses various implementations of [`BinarySerializable`] which are natively
//! supported payloads for secrets.

pub trait BinarySerializable {
    fn serialize(&self) -> Vec<u8>;
}

pub trait BinaryDeserializable {
    fn deserialize(bytes: Vec<u8>) -> Self;
}

impl BinarySerializable for String {
    fn serialize(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl BinaryDeserializable for String {
    fn deserialize(bytes: Vec<u8>) -> String {
        String::from_utf8_lossy(&bytes).to_string()
    }
}

impl BinarySerializable for &str {
    fn serialize(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
