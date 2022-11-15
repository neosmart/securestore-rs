use crate::*;
use std::io::prelude::*;
use std::io::Cursor;
use tempfile::NamedTempFile;

struct TempFileVault {
    temp_file: NamedTempFile,
}

impl<'a> GenericVaultSource<'a> for &TempFileVault {
    type Source = &'a NamedTempFile;
    type Error = std::io::Error;

    fn path(&self) -> Option<PathBuf> {
        Some(PathBuf::from(self.temp_file.path()))
    }

    fn as_read(&'a self) -> Result<Self::Source, Self::Error> {
        Ok(&self.temp_file)
    }
}

/// Verify that we can implement [`GenericVaultSource`] for arbitrary types and
/// use that to load a [`SecretsManager`] instance where
/// `GenericVaultSource::Source` is a reference type.
#[test]
fn custom_borrowed_vault_type() {
    let vault = TempFileVault {
        temp_file: NamedTempFile::new().unwrap(),
    };
    let keyfile = NamedTempFile::new().unwrap().into_temp_path();
    let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();
    sman.set("foo", b"bar".as_slice());
    sman.export_key(&keyfile).unwrap();
    sman.save_as((&vault).path().unwrap()).unwrap();

    let sman = SecretsManager::load(&vault, keyfile)
        .expect("Failed to load SecretsManager from custom type!");
    assert_eq!(sman.get("foo").unwrap(), "bar");
}

struct VecVault {
    vec: Vec<u8>,
}

impl<'a> GenericVaultSource<'a> for VecVault {
    type Source = std::io::Cursor<&'a [u8]>;
    type Error = std::io::Error;

    fn path(&self) -> Option<PathBuf> {
        None
    }

    fn as_read(&'a self) -> Result<Self::Source, Self::Error> {
        Ok(Cursor::new(self.vec.as_slice()))
    }
}

/// Verify that we can implement [`GenericVaultSource`] for arbitrary types and
/// use that to load a [`SecretsManager`] instance where
/// `GenericVaultSource::Source` is an owned type.
#[test]
fn custom_owning_vault_type() {
    let vault = NamedTempFile::new().unwrap().into_temp_path();
    let keyfile = NamedTempFile::new().unwrap().into_temp_path();
    let mut sman = SecretsManager::new(KeySource::Csprng).unwrap();
    sman.set("foo", "bar");
    sman.export_key(&keyfile).unwrap();
    sman.save_as(&vault).unwrap();

    let mut buf = Vec::new();
    let mut file = File::open(&vault).unwrap();
    file.read_to_end(&mut buf).unwrap();
    let vault = VecVault { vec: buf };
    let sman = SecretsManager::load(vault, keyfile)
        .expect("Failed to load SecretsManager from custom type!");
    assert_eq!(sman.get("foo").unwrap(), "bar");
}
