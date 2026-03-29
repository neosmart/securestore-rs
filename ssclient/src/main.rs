#[cfg(test)]
mod client_tests;

use clap::parser::ValueSource;
use clap::{Arg, ArgAction, Command};
use securestore::{KeySource, SecretsManager};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};

const ENOENT: i32 = 2;
const EEXIST: i32 = 17;

/// Determines how many parent paths to check when determining whether the key
/// file is under VCS control or not.
const VCS_TEST_MAX_DEPTH: i32 = 48;

#[derive(Debug, PartialEq)]
enum Mode<'a> {
    Get(GetKey<'a>, OutputFormat),
    Set(&'a str, Option<&'a str>),
    Create {
        export_key: Option<&'a Path>,
        no_vcs: bool,
    },
    Delete(&'a str),
    ExportKey {
        export_path: &'a Path,
        no_vcs: bool,
    },
}

#[derive(Debug, PartialEq)]
enum GetKey<'a> {
    Single(&'a str),
    All,
}

#[derive(Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, PartialEq)]
enum VcsType {
    /// None can mean literally none or "none that we support"
    None,
    Git,
}

#[cfg(not(target_arch = "wasm32"))]
fn stdin_is_tty() -> bool {
    atty::is(atty::Stream::Stdin)
}

#[cfg(not(not(target_arch = "wasm32")))]
fn stdin_is_tty() -> bool {
    true
}

fn main() {
    let is_tty = stdin_is_tty();

    let no_vcs = Arg::new("no_vcs")
        .long("no-vcs")
        .action(ArgAction::SetTrue)
        .help("Do not exclude generated encryption key in vcs ignore file.")
        .long_help(concat!(
            "By default, when ssclient generates a new key file (either when a new ",
            "SecureStore vault is created via `ssclient create -k secrets.key` or ",
            "when exporting a key file to use interchangeably with a password via ",
            "`ssclient --export-key secrets.key ...`), if the path to the key is found ",
            "to reside in a VCS-owned directory, ssclient generates an exclude rule for ",
            "for the newly created key file to ensure it is never accidentally committed ",
            "to a repository. The usage of `--no-vcs` suppresses this check and behavior.",
        ));

    let mut cmd = Command::new("SecureStore")
        .disable_version_flag(true)
        .author(concat!(
            "Copyright NeoSmart Technologies 2018-2026.\n",
            "Developed by Mahmoud Al-Qudsi and SecureStore contributors"
        ))
        .about(concat!(
            "Create and manage encrypted secrets stores.\n",
            "Learn more at https://neosmart.net/SecureStore/"
        ))
        .arg(
            Arg::new("store")
                .global(true)
                .short('s')
                .long("store")
                .value_name("STORE")
                .help("Specify the path to the secrets store to use for all operations.")
                .long_help(concat!(
                    "When omitted, the standardized SecureStore vault name/path ",
                    "of 'secrets.json' is used."
                ))
                .default_value("secrets.json")
                .value_parser(clap::value_parser!(PathBuf))
                .num_args(1),
        )
        .arg(
            Arg::new("password")
                .global(true)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                // Passing the password as a literal argument is normally disallowed to encourage
                // entering it interactively for security reasons, but we have no other option
                // if operating non-interactively.
                .num_args(if is_tty { 0 } else { 1 })
                .conflicts_with("keyfile")
                .help(concat!(
                    "Prompt for password used to derive key. \n",
                    "In headless environments, takes the password as an argument."
                ))
                .long_help(concat!(
                    "If neither `-p` (use password) nor `-k` (use keyfile) is specified ",
                    "ssclient defaults to password-based encryption/decryption.\n",
                    "When used in an interactive tty, the password may not be specified ",
                    "as a command line argument; instead ssclient will provide a secure ",
                    "prompt for the password to be entered in.\n",
                    "When used in a headless environment or as part of a script without ",
                    "stdin connected to a tty, the password may be specified as an argument ",
                    "to the `-p`/`--password` switch.",
                )),
        )
        .arg(
            Arg::new("keyfile")
                .global(true)
                .short('k')
                .long("key")
                .alias("keyfile")
                .alias("key-file")
                .value_name("KEYFILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Use key stored at path KEYFILE.")
                .num_args(1),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .help("Display version info ('--version' for detailed version info)")
                .long_help("Display version info ('-V' for minimal version)")
                .num_args(0)
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("create")
                .about(concat!(
                    "Create a new SecureStore vault for secrets storage.\n",
                    "See `ssclient help create` for more info"
                ))
                .arg(
                    Arg::new("create_store")
                        .index(1)
                        .value_name("STORE")
                        .value_parser(clap::value_parser!(PathBuf))
                        .default_value("secrets.json")
                        .help("The path to the SecureStore vault to create.")
                        .long_help(concat!(
                            "If not provided, the SecureStore standard location 'secrets.json' ",
                            "is used as a default.",
                        )),
                )
                .arg(no_vcs.clone())
                .arg(
                    Arg::new("export_key")
                        .long("export-key")
                        .value_name("EXPORT_PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1)
                        .help("Exports a keyfile equivalent to the supplied password.")
                        .long_help(concat!(
                            "When used in combination with password-based encryption/",
                            "decryption, exports a keyfile containing the encryption/",
                            "decryption key(s) derived from PASSWORD to the path ",
                            "specified by EXPORT_PATH. \n",
                            "This allows for subsequent keyless, non-interactive ",
                            "usage via the SecureStore API while still retaining the ",
                            "convenience of password-based encryption/decryption ",
                            "when using ssclient at the command line."
                        )),
                ),
        )
        .subcommand(
            Command::new("get")
                .about(concat!(
                    "Decrypt and retrieve secrets.\n",
                    "See `ssclient help get` for more info"
                ))
                .long_about(concat!(
                    "The value of a single secret may be retrieved by specifying its name ",
                    "as the first parameter after `get`, or all secrets may be retrieved by ",
                    "using --all in place of the secret name.\n",
                    "Plain-text secrets are retrieved as-is when looking up a single secret ",
                    "or when exporting all secrets to text, but binary secrets that cannot be ",
                    "interpreted as UTF-8 strings will be encoded as base64 and returned ",
                    "as `base64:<encoded>`. Secrets are always retrieved as-is if exporting ",
                    "to a JSON file (via `ssclient get --all --format json`).",
                ))
                .arg(
                    Arg::new("get_key")
                        .index(1)
                        .value_name("KEY")
                        .conflicts_with("get_all")
                        .required_unless_present("get_all")
                        .help("The name of the secret to be decrypted."),
                )
                .arg(
                    Arg::new("get_all")
                        .short('a')
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .help("Decrypt all secrets, e.g. for export.")
                        .long_help(concat!(
                            "Enumerates and decrypts all secrets found in the SecureStore vault, ",
                            "to the format specified by the `--format` argument. Output is ",
                            "written to stdout and should be redirected to a file with an ",
                            "extension matching the format for best results.\n\n",
                            "Examples: \n",
                            "  ssclient -k secrets.key get --all --format json > passwords.json\n",
                            "  ssclient -s secrets.json get --all --format text > passwords.txt\n",
                        )),
                )
                .arg(
                    Arg::new("get_format")
                        .long("format")
                        .num_args(1)
                        .requires("get_all")
                        .value_parser(["json", "text"])
                        .help("Specifies the format to export all decrypted values in.")
                        .long_help(concat!(
                            "Currently supported formats include `text` and `json` (the default); ",
                            "note that if exporting to text, non-string secrets are returned as ",
                            "base64-encoded values (in the format base64:<encoded>, without the ",
                            "angle brackets. If exporting to JSON, text secrets are exported as ",
                            "JSON strings, and binary secrets are exported as JSON arrays of ",
                            "byte values.",
                        )),
                ),
        )
        .subcommand(
            Command::new("set")
                .about(concat!(
                    "Add or update an encrypted value to/in the store.\n",
                    "See `ssclient help set` for more info"
                ))
                .arg(
                    Arg::new("set_key")
                        .index(1)
                        .value_name("KEY")
                        .required(true)
                        .help("The name of the secret to be created/updated.")
                        .long_help(concat!(
                            "If a secret already exists by the same name, its value will be ",
                            "silently overwritten; use with appropriate care. SecureStore ",
                            "vaults are intended to be stored under version control - remember ",
                            "that you can always use git/hg/etc to retrieve an older version ",
                            "of the secrets file if you made a mistake!",
                        )),
                )
                .arg(
                    Arg::new("set_value")
                        .index(2)
                        .value_name("VALUE")
                        .required(false)
                        .help("The value of the secret identified by KEY.")
                        .long_help(concat!(
                            "VALUE may be omitted to instead enter the secret in an ",
                            "ssclient-provided secure prompt instead, to avoid secrets being ",
                            "logged to shell history or similar."
                        )),
                ),
        )
        .subcommand(
            Command::new("delete")
                .alias("remove")
                .about(concat!(
                    "Remove a secret from the store.\n",
                    "See `ssclient help set` for more info"
                ))
                .arg(
                    Arg::new("delete_key")
                        .value_name("KEY")
                        .index(1)
                        .required(true)
                        .help("The unique name of the secret to be deleted."),
                ),
        )
        .subcommand(
            Command::new("export-key")
                .about(concat!(
                    "Exports a keyfile equivalent to the supplied password.\n",
                    "See `ssclient help export-key` for more info"
                ))
                .long_about(concat!(
                    "When used in combination with password-based encryption/",
                    "decryption, exports a keyfile containing the encryption/",
                    "decryption key(s) derived from PASSWORD to the path ",
                    "specified by EXPORT_PATH. \n",
                    "This allows for subsequent keyless, non-interactive ",
                    "usage via the SecureStore API while still retaining the ",
                    "convenience of password-based encryption/decryption ",
                    "when using ssclient at the command line."
                ))
                .arg(
                    Arg::new("export_path")
                        .value_name("EXPORT_PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1)
                        .help("Where to export the keyfile version of the vault password")
                        .required(true),
                )
                .arg(no_vcs),
        );

    let app_args = cmd.get_matches_mut();
    let subcommand = match app_args.subcommand_name() {
        Some(name) => name,
        None => {
            if app_args.get_flag("version") {
                // Clap itself can tell the difference between -V and --version but doesn't let
                // us do the same :(
                let short = std::env::args().any(|arg| &arg == "-V");
                print_version_info(short);
            } else {
                let _ = cmd.print_help();
            }
            return;
        }
    };

    let mode_args = app_args.subcommand_matches(subcommand).unwrap();

    let mode = match subcommand {
        "get" => {
            let key = match mode_args.get_one::<String>("get_key") {
                Some(key) => GetKey::Single(key),
                None => GetKey::All,
            };
            let format = match mode_args
                .get_one::<String>("get_format")
                .map(|s| s.as_str())
            {
                Some("text") => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
            Mode::Get(key, format)
        }
        "set" => Mode::Set(
            mode_args.get_one::<String>("set_key").unwrap(),
            mode_args.get_one::<String>("set_value").map(|s| s.as_str()),
        ),
        "delete" => Mode::Delete(mode_args.get_one::<String>("delete_key").unwrap()),
        "create" => {
            let export_key = mode_args.get_one::<PathBuf>("export_key").map(Path::new);
            let no_vcs = mode_args.get_flag("no_vcs");
            Mode::Create { export_key, no_vcs }
        }
        "export-key" => {
            let export_path = mode_args
                .get_one::<PathBuf>("export_path")
                .map(Path::new)
                .unwrap();
            let no_vcs = mode_args.get_flag("no_vcs");
            Mode::ExportKey {
                export_path,
                no_vcs,
            }
        }
        _ => {
            let _ = cmd.print_help();
            std::process::exit(1);
        }
    };

    // In the specific case of `ssclient create`, a store path can be provided via a
    // positional argument (e.g. `ssclient create path.json`) or via the global
    // `-s`/`--store` option (e.g. `ssclient create -s path.json`). The
    // positional argument takes priority.
    if matches!(mode, Mode::Create { .. })
        && mode_args.value_source("create_store") != Some(ValueSource::DefaultValue)
        && app_args.value_source("store") != Some(ValueSource::DefaultValue)
        && mode_args.get_one::<String>("create_store") != app_args.get_one::<String>("store")
    {
        eprintln!("Conflicting store paths provided!");
        std::process::exit(1);
    }

    // We can't use `.is_present()` as the default value would coerce a true result.
    // It is safe to call unwrap because a default value is always present.
    let store_path = if matches!(mode, Mode::Create { .. })
        && mode_args.value_source("create_store") == Some(ValueSource::CommandLine)
    {
        mode_args.get_one::<PathBuf>("create_store").unwrap()
    } else {
        // This has a default value of secrets.json so it's safe to unwrap
        app_args.get_one::<PathBuf>("store").unwrap()
    };

    if !matches!(mode, Mode::Create { .. }) && !store_path.exists() {
        eprintln!("Cannot find secure store: {}", store_path.display());
        // 0x02 is both ENOENT and ERROR_FILE_NOT_FOUND 👍
        std::process::exit(ENOENT);
    }

    let mut password;
    let keysource = if app_args.value_source("keyfile").is_some() {
        let keyfile = app_args.get_one::<PathBuf>("keyfile").unwrap();
        KeySource::Path(keyfile)
    } else if is_tty {
        loop {
            password = secure_read("Password: ");

            if matches!(mode, Mode::Create { .. }) {
                let password2 = secure_read("Confirm password: ");
                if password != password2 {
                    continue;
                }

                if password.len() < 8 {
                    eprintln!("Password does not meet minimum length requirements!");
                    continue;
                }
            }
            break KeySource::Password(&password);
        }
    } else {
        if app_args.value_source("password").is_none() {
            eprintln!("Either a password or keyfile is required in headless mode!");
            let _ = cmd.print_help();
            std::process::exit(1);
        }
        KeySource::Password(app_args.get_one::<String>("password").unwrap())
    };

    match run(mode, store_path, keysource) {
        Ok(_) => {}
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    }
}

fn print_version_info(short: bool) {
    let variant = securestore::BACKEND;

    let client_version = env!("CARGO_PKG_VERSION");
    let target_tuple = env!("CARGO_TARGET");
    let target_os = env!("CARGO_TARGET_OS");
    println!("ssclient {client_version}/{variant} ({target_os}/{target_tuple})");

    if !short {
        let lib_version = securestore::VERSION;
        #[cfg(feature = "rustls")]
        let dep_versions = env!("CRYPTO_VERSIONS");
        #[cfg(feature = "openssl")]
        let dep_versions = securestore::openssl_version();
        println!("SecureStore {lib_version} ({dep_versions})");
    }
}

/// Retrieves the named secret from the vault just like
/// [`SecretsManager::get()`] in the usual case, but if the secret cannot be
/// deserialized into a valid UTF-8 string this function returns the
/// binary representation of the secret (currently as a base64 string).
fn get_secret(sman: &SecretsManager, name: &str) -> Result<String, securestore::Error> {
    match sman.get(name) {
        Ok(secret) => Ok(secret),
        Err(e) if matches!(e.kind(), securestore::ErrorKind::DeserializationError) => {
            let bytes = sman.get_as::<Vec<u8>>(name)?;
            let encoded = radix64::STD.encode(&bytes);
            Ok(format!("base64:{encoded}"))
        }
        Err(e) => Err(e)?,
    }
}

fn run(
    mode: Mode,
    store_path: &Path,
    keysource: KeySource,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (keysource, key_export_paths) = match &mode {
        Mode::Create { export_key, .. } => {
            let mut key_export_paths = Vec::new();
            if let &Some(export_key_path) = export_key {
                key_export_paths.push(export_key_path);
            }
            match &keysource {
                &KeySource::Path(path) => {
                    // If it doesn't exist or is empty
                    if !std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
                        // Add if it's not the same path being exported to
                        if !export_key.is_some_and(|p| p == path) {
                            key_export_paths.push(path);
                        }
                        (KeySource::Csprng, key_export_paths)
                    } else {
                        eprintln!("Using existing keyfile {}", path.display());
                        (keysource, key_export_paths)
                    }
                }
                _ => (keysource, key_export_paths),
            }
        }
        Mode::ExportKey { export_path, .. } => (keysource, vec![*export_path]),
        _ => (keysource, Vec::new()),
    };

    let mut sman = match &mode {
        Mode::Create { .. } => {
            if std::fs::metadata(store_path).is_ok_and(|m| m.len() > 0) {
                if !confirm(format!(
                    "Overwrite existing keystore {}",
                    store_path.display()
                )) {
                    eprintln!("New store creation aborted.");
                    std::process::exit(EEXIST);
                }
            }
            SecretsManager::new(&keysource)?
        }
        _ => SecretsManager::load(store_path, &keysource)?,
    };

    // Safety: Ask user to confirm all overwrites before actually updating any of
    // them
    for &path in &key_export_paths {
        if path.exists() && path.metadata().unwrap().len() > 0 {
            if !confirm(format!("Overwrite existing keyfile at {}?", path.display())) {
                eprintln!("Keyfile export aborted.");
                std::process::exit(EEXIST);
            }
        }
    }
    for &path in &key_export_paths {
        eprintln!("Saving newly generated key to {}", path.display());
        sman.export_key(path)?;
    }

    let mut exclude_in_vcs = false;
    let write_store;

    match mode {
        Mode::Create { no_vcs, .. } => {
            write_store = true;
            exclude_in_vcs = !no_vcs;
        }
        Mode::Get(GetKey::Single(key), _) => {
            write_store = false;
            let secret = get_secret(&sman, key)?;
            println!("{}", secret);
        }
        Mode::Get(GetKey::All, OutputFormat::Text) => {
            write_store = false;
            for key in sman.keys() {
                println!("{}: {}", key, get_secret(&sman, key)?);
            }
        }
        Mode::Get(GetKey::All, OutputFormat::Json) => {
            write_store = false;
            let dump: Vec<_> = sman
                .keys()
                .map(|key| match sman.get(key) {
                    Ok(value) => json!({
                        "key": key,
                        "value": value,
                    }),
                    Err(e) if e.kind() == securestore::ErrorKind::DeserializationError => {
                        let value = sman.get_as::<Vec<u8>>(key).expect(Box::leak(
                            format!("Failed to retrieve secret {key}").into_boxed_str(),
                        ));

                        json!({
                            "key": key,
                            "value": value,
                        })
                    }
                    Err(e) => Err(e).expect(Box::leak(
                        format!("Failed to retrieve secret {key}").into_boxed_str(),
                    )),
                })
                .collect();

            let json = serde_json::to_string_pretty(&dump)
                .map_err(|err| format!("Failed to serialize secrets to JSON: {err}"))?;
            println!("{}", json);
        }
        Mode::Set(key, Some(value)) => {
            write_store = true;
            sman.set(key, value)
        }
        Mode::Set(key, None) => {
            write_store = true;
            let is_tty = stdin_is_tty();
            if is_tty {
                eprint!("Value: ");
            }
            let value = read();
            sman.set(key, value);
        }
        Mode::Delete(key) => {
            write_store = true;
            sman.remove(key)?;
        }
        Mode::ExportKey { no_vcs, .. } => {
            write_store = false;
            exclude_in_vcs = !no_vcs;
        }
    }

    if write_store {
        sman.save_as(store_path)?;
    }

    if exclude_in_vcs {
        for &vcs_exclude_path in &key_export_paths {
            if repo_type(vcs_exclude_path, VCS_TEST_MAX_DEPTH) != VcsType::None {
                let parent_dir = vcs_exclude_path.parent().unwrap();
                let ignore_file = parent_dir.join(".gitignore");

                add_path_to_ignore_file(&ignore_file, &vcs_exclude_path)?;
            }
        }
    }

    Ok(())
}

fn confirm<S: AsRef<str>>(prompt: S) -> bool {
    let is_tty = stdin_is_tty();
    if !is_tty {
        return true;
    }

    // stdin.read_line(..) doesn't give us a way to detect Ctrl+C on Windows
    let prompt = prompt.as_ref();
    loop {
        eprint!("{}? [y/n] ", prompt.trim_matches('?'));
        let input = read();
        let line = input.trim().to_lowercase();
        if line == "y" || line == "yes" {
            return true;
        } else if line == "n" || line == "no" {
            return false;
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_masked(mask_input: bool, prompt: &str) -> String {
    const STATUS_CONTROL_C_EXIT: i32 = 0xC000013Au32 as i32;

    const CTRL_C: u8 = 0x03; // ASCII ETX on Windows
    const BKSPC: u8 = 0x08;
    const BKSPC_TERMIOS: u8 = 0x7F;

    if !prompt.is_empty() {
        eprint!("{prompt}");
    }

    let mut input = String::with_capacity(16);
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    loop {
        let getch = getch::Getch::new();
        let c = match getch.getch() {
            Ok(c) => c,
            Err(_) => break,
        };

        match c {
            b'\r' | b'\n' => {
                eprintln!("");
                break;
            }
            CTRL_C => {
                // We only reach here on platforms without a signal handler installed
                // by default, i.e. Windows.
                eprintln!("");
                std::process::exit(STATUS_CONTROL_C_EXIT);
            }
            BKSPC | BKSPC_TERMIOS => {
                if input.len() > 0 {
                    input.truncate(input.len() - 1);
                    stderr.write_all(&[BKSPC, b' ', BKSPC]).unwrap();
                }
            }
            c => {
                input.push(c as char);
                if mask_input {
                    stderr.write_all(&[b'*']).unwrap();
                } else {
                    stderr.write_all(&[c]).unwrap();
                }
            }
        }
    }

    if input.trim().len() != input.len() {
        input.trim().to_owned()
    } else {
        input
    }
}

#[cfg(target_arch = "wasm32")]
fn read_masked(mask_input: bool, prompt: &str) -> String {
    use std::io::BufRead;

    if !prompt.is_empty() {
        eprint!("{prompt}");
    }

    let mut input = String::with_capacity(16);
    let mut stdin = std::io::stdin().lock();
    stdin.read_line(&mut input).unwrap();
    if mask_input {
        // Clear the previous line then reprint the prompt plus the masked input
        // to emulate secure read.
        let masked: String = input.chars().map(|_| '*').collect();
        let _ = std::io::stderr().write_all("\u{001b}[1A\r\u{001b}[K".as_bytes());
        eprintln!("{prompt}{masked}");
    }

    if input.trim().len() != input.len() {
        input.trim().to_owned()
    } else {
        input
    }
}

fn read() -> String {
    read_masked(false, "")
}

fn secure_read(prompt: &str) -> String {
    read_masked(true, prompt)
}

/// Determines whether a path is under VCS control, and if so, what that VCS is.
/// Parent traversal is capped to `max_depth` ancestors.
fn repo_type(path: &Path, max_depth: i32) -> VcsType {
    let abs_path = path.canonicalize().unwrap();
    let mut path = abs_path.as_path();
    for _ in 0..max_depth {
        path = match path.parent() {
            Some(parent) => parent,
            None => break,
        };

        let vcs_path = path.join(".git");
        if vcs_path.exists() {
            return VcsType::Git;
        }
    }

    VcsType::None
}

fn add_path_to_ignore_file(
    ignore_file: &Path,
    path: &Path,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    // Currently, only ignore files that are in the same dir as the path to be
    // ignored are supported; this drastically simplifies both checking whether
    // a path is already ignored and determining how to express the path
    // relative to the ignore file.
    if ignore_file.parent() != path.parent() {
        panic!("Ignore file must be in the same directory as the file to be excluded from vcs!");
    }
    if ignore_file.exists() && !ignore_file.is_file() {
        eprintln!(
            "An ignore file already exists at {} but is not a regular file!",
            ignore_file.display()
        );
        return Ok(false);
    }

    // We treat the contents of the ignore file as UTF-8, so we can't handle
    // non-UTF-8 paths to be excluded.
    // It should be fine to unwrap .file_name() because we've already asserted that
    // it's a file.
    let path_file_name = match path.file_name().unwrap().to_str() {
        Some(str) => str,
        // This isn't an error because the user is perfectly allowed to use a non-Unicode path for
        // the key file. This use case is just presently not implemented.
        None => return Ok(false),
    };

    // Contains either the string "newly-created" or "existing" depending on whether
    // we created the VCS ignore file ourselves or not.
    let ignore_file_status;
    // Create an empty file if it doesn't already exist, so we can always start
    // from the same place.
    if !ignore_file.exists() {
        // eprintln!("Creating new ignore file at {}", ignore_file.display());
        File::create(&ignore_file).map_err(|err| {
            format!(
                "Error creating VCS ignore file at {}: {}",
                ignore_file.display(),
                err
            )
        })?;
        ignore_file_status = "newly-created";
    } else {
        ignore_file_status = "existing";
    }

    let mut matched_paths = vec![path_file_name];
    // Allow a wildcard ignore like *.key to match
    let wildcard_exclude;
    if let Some(ext) = path.extension() {
        // It's safe to unwrap because we've verified above that all of path.filename()
        // is a valid UTF-8 string.
        let ext = ext.to_str().unwrap();
        wildcard_exclude = format!("*.{ext}");
        matched_paths.push(wildcard_exclude.as_str());
    }

    let reader = BufReader::new(File::open(ignore_file)?);
    for line in reader.lines() {
        let line = match line {
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                // No I/O errors, but the line contained invalid UTF-8 contents
                continue;
            }
            result => result,
        }?;

        // An ignore rule for foo and /foo should both match since we are excluding a
        // path in the same directory as the ignore file itself.
        // NB: An ignore rule for ./foo is a red herring and will not match!
        let cleaned_rule = line.strip_prefix("/").unwrap_or(&line);

        // Check if the processed line/rule already excludes the path we want to exclude
        if matched_paths.contains(&cleaned_rule) {
            // eprintln!("The key file {} is already excluded in ignore file {} by rule {}",
            //     path.display(), ignore_file.display(), &line);
            return Ok(true);
        }
    }

    // We only get here if the ignore file didn't contain the path we want to
    // exclude.

    // While we support both pathed (/foo) and unpathed (foo) pre-existing rules,
    // we prefer to always write out pathed rules only.
    // NB: ./foo is NOT correct (at least for git) and will not match!
    let rule = format!("/{path_file_name}\n");
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(ignore_file)
        .map_err(|err| {
            format!(
                "Error opening ignore file at {} for writing: {}",
                ignore_file.display(),
                err
            )
        })?;
    writer
        .write_all(b"# SecureStore key file ignore rule:\n")
        .and_then(|()| writer.write_all(rule.as_bytes()))
        .map_err(|err| {
            format!(
                "Error writing to vcs ignore file at {}: {}",
                ignore_file.display(),
                err
            )
        })?;

    eprintln!(
        "Excluding key file in {ignore_file_status} VCS ignore file {}",
        ignore_file.display()
    );

    Ok(true)
}
