use std::collections::HashSet;
use std::io::BufRead;
use std::path::{Path, PathBuf};

fn main() {
    #[cfg(feature = "openssl")]
    let deps = ["openssl"];

    #[cfg(not(feature = "openssl"))]
    let deps = [
        "aes",
        "cbc",
        "getrandom",
        "hmac",
        "pbkdf2",
        "sha1",
        "subtle",
    ];

    let versions = get_dep_versions(HashSet::from(deps));

    let version_string = versions
        .iter()
        .map(|(dep, ver)| format!("{dep}@{ver}"))
        .collect::<Vec<_>>()
        .join(", ");

    println!("cargo:rustc-env=CRYPTO_VERSIONS={}", version_string);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.lock");
}

fn get_dep_versions(mut deps: HashSet<&str>) -> Vec<(String, String)> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let lock_path = find_cargo_lock(Path::new(&manifest_dir)).expect("Error finding Cargo.lock!");
    let lock_file = std::fs::File::open(lock_path).unwrap();
    let reader = std::io::BufReader::new(lock_file);

    let mut dep = None;
    let mut results = Vec::with_capacity(deps.len());
    for line in reader.lines() {
        let line = line.as_deref().unwrap().trim();
        if let Some(next) = line
            .strip_prefix("name = \"")
            .map(|dep| dep.trim_end_matches('"'))
        {
            dep = Some(next.to_owned());
        } else if let Some(dep) = dep.as_deref() {
            if let Some(version) = line
                .strip_prefix("version = \"")
                .map(|v| v.trim_end_matches('"'))
            {
                // println!("Found {dep}@{version}");

                if deps.contains(dep) {
                    results.push((dep.to_string(), version.to_string()));
                    deps.remove(dep);
                }
            }
        }
    }

    if !deps.is_empty() {
        let missing = deps.iter().cloned().collect::<Vec<_>>().join(", ");
        panic!(
            "Could not find versions for the following dependencies: {}",
            missing
        );
    }

    results.sort_unstable();
    results
}

fn find_cargo_lock(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    loop {
        let lock_path = current.join("Cargo.lock");
        if lock_path.exists() {
            return dbg!(Some(lock_path));
        }
        if !current.pop() {
            break;
        }
    }
    dbg!(None)
}
