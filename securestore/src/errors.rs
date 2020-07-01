/// A strongly-typed enumeration of errors one can expect to encounter in using
/// the SecureStore API.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorKind {
    /// The key did not meet the requirements for a valid keyfile.
    InvalidKeyfile,
    /// May be caused by using the wrong key or attempting to load ciphertext
    /// that has been tampered with.
    DecryptionFailure,
    /// The [`BinaryDeserializable`](crate::BinaryDeserializable) type converter
    /// failed to convert the decrypted payload.
    DeserializationError,
    /// The requested secret was not found in the store.
    SecretNotFound,
    /// The vault was created with a version that is not supported by this
    /// library.
    UnsupportedVaultVersion,
    /// An IO error occurred reading/writing from/to the store.
    IoError,
    /// An error occurred during the (de)serialization of the secure store. This
    /// typically implies either an incorrect file was loaded as the secrets
    /// store, the file has been corrupted/truncated, or was produced by a
    /// buggy or incompatible implementation.
    InvalidStore,
}

pub(crate) type StdError = dyn std::error::Error + Send + Sync + 'static;

/// The high-level wrapper type for user-facing errors in the SecureStore API.
///
/// Individual errors are categorized as [`ErrorKind`], which implements
/// [`PartialEq`] and [`Debug`](std::fmt::Debug), whereas `Error` itself cannot
/// as that would constrain the possible values of wrapped inner errors to a
/// too-strict subset of real-world values.
#[derive(Debug)]
pub struct Error {
    inner: Option<Box<StdError>>,
    kind: ErrorKind,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn inner(&self) -> Option<&StdError> {
        self.inner.as_ref().map(|e| &**e)
    }

    pub(crate) fn from_inner(kind: ErrorKind, inner: Box<StdError>) -> Self {
        Error {
            kind,
            inner: Some(inner),
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, rhs: &Self) -> bool {
        self.kind == rhs.kind && self.inner.is_some() == self.inner.is_some()
    }
}

impl std::convert::From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { kind, inner: None }
    }
}

impl<R> std::convert::Into<Result<R, Error>> for Error {
    fn into(self) -> Result<R, Error> {
        Err(self)
    }
}

impl<R> std::convert::Into<Result<R, Error>> for ErrorKind {
    fn into(self) -> Result<R, Error> {
        Err(self.into())
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error {
            inner: Some(Box::new(e)),
            kind: ErrorKind::IoError,
        }
    }
}

impl std::convert::From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error {
            inner: Some(Box::new(e)),
            kind: ErrorKind::InvalidStore,
        }
    }
}

impl std::convert::From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Error {
        Error {
            inner: Some(Box::new(e)),
            kind: ErrorKind::DecryptionFailure,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.kind() {
            ErrorKind::InvalidKeyfile => "An invalid key file was supplied",
            ErrorKind::DecryptionFailure => "There was an error decrypting the secrets store. Check the password or key file and verify the store has not been tampered with",
            ErrorKind::SecretNotFound => "No secret was found with the specified name",
            ErrorKind::UnsupportedVaultVersion => "An attempt was made to open a vault with an unsupported version",
            ErrorKind::IoError => "An IO error occurred reading or writing from/to the secrets store",
            ErrorKind::DeserializationError => "An error occured in the type converter deserializing the secret to the requested type",
            ErrorKind::InvalidStore => "The contents of the store did not match what was expected",
        };

        match &self.inner {
            Some(inner) => write!(fmt, "{}: {}", s, inner),
            None => write!(fmt, "{}.", s),
        }
    }
}

impl std::error::Error for Error {}
