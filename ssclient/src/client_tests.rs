use securestore::*;
use base64::{Engine as _, engine::general_purpose};
#[test]
pub fn binary_decode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sman = SecretsManager::new(KeySource::Csprng)?;

    let secret_base64 = "Gl8WuHef7yWq7mRL/vLvrQ==";
    let secret = &general_purpose::STANDARD.decode(secret_base64)?;

    // Verify that the chosen secret isn't a valid UTF-8 string
    if let Ok(_) = String::from_utf8(secret.clone()) {
        panic!("Cannot test with a binary secret that's also valid UTF-8 string!");
    }

    sman.set("secret", secret.as_slice());

    // get_secret() is the centralized place where arbitrary secrets are coerced to
    // strings
    let secret_str = super::get_secret(&sman, "secret")?;
    assert_eq!(secret_str, format!("base64:{}", secret_base64));

    Ok(())
}
