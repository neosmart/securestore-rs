use crate::shared::*;
use crate::*;
use openssl::rand;

/// Verifies that exporting keys derived from a password results in keys
/// dependent on the IV.
#[test]
fn key_derivation_iv() {
    let mut iv1 = [0u8; IV_SIZE];
    rand::rand_bytes(&mut iv1).unwrap();

    let mut iv2 = [0u8; IV_SIZE];
    rand::rand_bytes(&mut iv2).unwrap();

    let derived1 = KeySource::Password("foo").extract_keys(&iv1).unwrap();
    let derived2 = KeySource::Password("foo").extract_keys(&iv1).unwrap();

    assert_eq!(
        derived1, derived2,
        "Two keys derived from same password and same IV should not differ"
    );

    let derived3 = KeySource::Password("foo").extract_keys(&iv2).unwrap();
    assert_ne!(
        derived1, derived3,
        "Two keys derived from the same password but different IVs should differ"
    );
}
