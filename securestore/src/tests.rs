mod encrypted_blob;
mod key_management;
mod secrets;

pub use temp_file::TempFile;

mod temp_file {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    static SSTEMP: AtomicUsize = AtomicUsize::new(0);

    pub struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        pub fn new() -> Self {
            let path = loop {
                let id = SSTEMP.fetch_add(1, Relaxed);
                let name = format!(".sstemp-{id:03}");
                let path = PathBuf::from(name);
                if !path.exists() {
                    break path;
                }
            };

            std::fs::File::create(&path).expect(&format!(
                "Error creating temporary file in {}",
                std::env::current_dir().unwrap().display()
            ));

            TempFile {
                path: PathBuf::from(path),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            if let Err(err) = std::fs::remove_file(self.path()) {
                eprintln!(
                    "Error cleaning up temp file at {}: {}",
                    self.path().display(),
                    err
                );
            }
        }
    }

    impl AsRef<Path> for TempFile {
        fn as_ref(&self) -> &Path {
            self.path()
        }
    }
}
