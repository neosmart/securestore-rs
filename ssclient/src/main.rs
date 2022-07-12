use clap::{App, Arg, SubCommand, ValueSource};
use securestore::{KeySource, SecretsManager};
use serde_json::json;
use std::io::Write;
use std::path::Path;

const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const STATUS_CONTROL_C_EXIT: i32 = 0xC000013Au32 as i32;

/// Determines how many parent paths to check when determining whether the key
/// file is under VCS control or not.
const VCS_TEST_MAX_DEPTH: i32 = 48;

#[derive(Debug, PartialEq)]
enum Mode<'a> {
    Get(GetKey<'a>, OutputFormat),
    Set(&'a str, Option<&'a str>),
    Create,
    Delete(&'a str),
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

fn main() {
    let is_tty = atty::is(atty::Stream::Stdin);
    let mut args = App::new("SecureStore")
        .version(env!("CARGO_PKG_VERSION"))
        .author(concat!(
            "Copyright NeoSmart Technologies 2018-2020.\n",
            "Developed by Mahmoud Al-Qudsi and SecureStore contributors"
        ))
        .about(concat!(
            "Create and manage encrypted secrets stores.\n",
            "Learn more at https://neosmart.net/SecureStore/"
        ))
        .arg(
            Arg::with_name("store")
                .global(true)
                .short('s')
                .long("store")
                .value_name("STORE")
                .help("Specify the path to the secrets store to use")
                .default_value("secrets.json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .global(true)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .takes_value(!is_tty)
                .conflicts_with("keyfile")
                .help(concat!(
                    "Prompt for password used to derive key. \n",
                    "In headless environments takes the password as an argument."
                )),
        )
        .arg(
            Arg::with_name("export_key")
                .long("export-key")
                .value_name("EXPORT_PATH")
                .number_of_values(1)
                .global(true)
                // We shouldn't use .requires("password") here because we default
                // to password-based encryption if no other method is specified.
                // .requires("password")
                .conflicts_with("keyfile")
                .help("Exports a key equivalent to the supplied password")
                .long_help(concat!(
                    "When used in combination with password-based encryption/",
                    "decryption, exports a keyfile containing the encryption/",
                    "decryption key(s) derived from PASSWORD to the path ",
                    "specified by EXPORT_PATH. \n",
                    "This allows for subsequent keyless, non-interactive ",
                    "usage via the SecureStore API while still retaining the",
                    "convenience of password-based encryption/decryption ",
                    "when using ssclient at the command line."
                )),
        )
        .arg(
            Arg::with_name("keyfile")
                .global(true)
                .short('k')
                .long("key")
                .alias("keyfile")
                .alias("key-file")
                .value_name("KEYFILE")
                .help("Use key stored at KEYFILE")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("create")
                .about("Create a new store")
                .arg(
                    Arg::with_name("create_store")
                        .index(1)
                        .value_name("STORE")
                        .default_value("secrets.json")
                        .help("The path to the secrets store to create"),
                )
                .arg(
                    Arg::new("no_vcs")
                        .long("no-vcs")
                        .takes_value(false)
                        .help("Do not exclude private key in vcs ignore file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Decrypt one or more secrets")
                .arg(
                    Arg::with_name("all")
                        .short('a')
                        .long("all")
                        .help("Decrypt all secrets (e.g. for export)"),
                )
                .arg(
                    Arg::with_name("format")
                        .long("format")
                        .takes_value(true)
                        .requires("all")
                        .possible_value("json")
                        .possible_value("text")
                        .help("Specifies the format to export all decrypted values in"),
                )
                .arg(
                    Arg::with_name("key")
                        .index(1)
                        .value_name("KEY")
                        .conflicts_with("all")
                        .required(true)
                        .help("The name of the secret to be decrypted"),
                ),
        )
        .subcommand(
            SubCommand::with_name("set")
                .about("Add or update an encrypted value to the store")
                .arg(
                    Arg::with_name("key")
                        .index(1)
                        .value_name("KEY")
                        .required(true)
                        .help("The name of the secret to be created/updated"),
                )
                .arg(
                    Arg::with_name("value")
                        .index(2)
                        .value_name("VALUE")
                        .required(false)
                        .help("The value of the secret identifyied by KEY"),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .alias("remove")
                .about("Remove a secret from the store")
                .arg(
                    Arg::with_name("key")
                        .value_name("KEY")
                        .index(1)
                        .required(true)
                        .help("The unique name of the secret to be deleted"),
                ),
        );

    let usage = args.render_usage();
    let matches = args.get_matches();
    let subcommand = match matches.subcommand_name() {
        Some(name) => name,
        None => {
            eprintln!("{}", usage);
            return;
        }
    };

    let mode_args = matches.subcommand_matches(subcommand).unwrap();

    // In the specific case of `ssclient create`, a store path can be provided via a
    // positional argument (e.g. `ssclient create path.json`) or via the global
    // `-s`/`--store` option (e.g. `ssclient create -s path.json`). The
    // positional argument takes priority.
    if mode_args.value_source("create_store").unwrap() != ValueSource::DefaultValue
        && mode_args.value_source("store").unwrap() != ValueSource::DefaultValue
        && mode_args.value_of("create_store") != mode_args.value_of("store")
    {
        eprintln!("Conflicting store paths provided!");
        std::process::exit(1);
    }

    // We can't use `.is_present()` as the default value would coerce a true result.
    // It is safe to call unwrap because a default value is always present.
    let store = if mode_args.value_source("create_store").unwrap() == ValueSource::CommandLine {
        Path::new(mode_args.value_of("create_store").unwrap())
    } else {
        // This has a default value of secrets.json so it's safe to unwrap
        Path::new(matches.value_of("store").unwrap())
    };

    let mode = match matches.subcommand_name() {
        Some("get") => {
            let key = match mode_args.value_of("key") {
                Some(key) => GetKey::Single(key),
                None => GetKey::All,
            };
            let format = match mode_args.value_of("format") {
                Some("text") => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
            Mode::Get(key, format)
        }
        Some("set") => Mode::Set(
            mode_args.value_of("key").unwrap(),
            mode_args.value_of("value"),
        ),
        Some("delete") => Mode::Delete(mode_args.value_of("key").unwrap()),
        Some("create") => Mode::Create,
        _ => {
            eprintln!("{}", usage);
            std::process::exit(1);
        }
    };

    if mode != Mode::Create && !store.exists() {
        eprintln!("Cannot find secure store: {}", store.display());
        // 0x02 is both ENOENT and ERROR_FILE_NOT_FOUND 👍
        std::process::exit(ENOENT);
    }

    let mut password;
    let keysource = if matches.is_present("keyfile") {
        let keyfile = Path::new(matches.value_of("keyfile").unwrap());
        KeySource::File(keyfile)
    } else if is_tty {
        let keysource;
        loop {
            eprint!("Password: ");
            password = secure_read();

            if mode == Mode::Create {
                eprint!("Confirm password: ");
                let password2 = secure_read();
                if password != password2 {
                    continue;
                }

                if password.len() < 8 {
                    eprintln!("Password does not meet minimum length requirements!");
                    continue;
                }
            }
            keysource = KeySource::Password(&password);
            break;
        }
        keysource
    } else {
        if !matches.is_present("password") {
            eprintln!("Either a password or keyfile is required!");
            eprintln!("{}", usage);
            std::process::exit(1);
        }
        KeySource::Password(matches.value_of("password").unwrap())
    };

    let export_path = matches.value_of("export_key");
    let exclude_vcs = !mode_args.contains_id("no_vcs");
    match run(mode, &store, keysource, export_path, exclude_vcs) {
        Ok(_) => {}
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    }
}

fn run(
    mode: Mode,
    store: &Path,
    keysource: KeySource,
    key_export_path: Option<&str>,
    exclude_vcs: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (keysource, key_export_path) = match (&mode, &keysource) {
        (Mode::Create, KeySource::File(path)) => {
            if !path.exists() || std::fs::metadata(path).unwrap().len() == 0 {
                (KeySource::Csprng, Some(*path))
            } else {
                eprintln!("Using existing keyfile {}", path.display());
                (keysource, None)
            }
        }
        _ => (keysource, key_export_path.map(|path| Path::new(path))),
    };

    let mut sman = match &mode {
        Mode::Create => {
            if store.exists() && std::fs::metadata(store).unwrap().len() > 0 {
                if !confirm(format!("Overwrite existing keystore {}", store.display())) {
                    eprintln!("New store creation aborted.");
                    std::process::exit(EEXIST);
                }
            }
            SecretsManager::new(store, keysource.clone())?
        }
        _ => SecretsManager::load(store, keysource.clone())?,
    };

    if let Some(path) = key_export_path {
        if path.exists() && path.metadata().unwrap().len() > 0 {
            if !confirm(format!("Overwrite existing keyfile at {}", path.display())) {
                eprintln!("Keyfile export aborted.");
                std::process::exit(EEXIST);
            }
        }
        eprintln!("Saving newly generated key to {}", path.display());
        sman.export_keyfile(path)?;
    }

    match mode {
        Mode::Create => {}
        Mode::Get(GetKey::Single(key), _) => {
            let secret: String = sman.get(key)?;
            println!("{}", secret);
        }
        Mode::Get(GetKey::All, OutputFormat::Text) => {
            for key in sman.keys() {
                println!("{}: {}", key, sman.get::<String>(key)?);
            }
        }
        Mode::Get(GetKey::All, OutputFormat::Json) => {
            let dump: Vec<_> = sman
                .keys()
                .map(|key| {
                    json!({
                        "key": key,
                        "value": sman.get::<String>(key).unwrap(),
                    })
                })
                .collect();

            let json =
                serde_json::to_string_pretty(&dump).expect("Failed to serialize secrets export!");
            println!("{}", json);
        }
        Mode::Set(key, Some(value)) => sman.set(key, value),
        Mode::Set(key, None) => {
            let is_tty = atty::is(atty::Stream::Stdin);
            if is_tty {
                eprint!("Value: ");
            }
            let value = read();
            sman.set(key, value)
        }
        Mode::Delete(key) => sman.remove(key)?,
    }

    sman.save()?;

    if exclude_vcs {
        let vcs_exclude_path = match (mode, keysource, key_export_path) {
            // Exclude the already present/created key file
            (Mode::Create, KeySource::File(path), _) => Some(path),
            // Exclude the key file we just exported
            (_, _, Some(path)) => Some(path),
            // No key file to exclude
            _ => None,
        };

        if let Some(vcs_exclude_path) = vcs_exclude_path {
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
    let is_tty = atty::is(atty::Stream::Stdin);
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

fn read_masked(mask_input: bool) -> String {
    const CTRL_C: u8 = 0x03; // ASCII ETX on Windows
    const BKSPC: u8 = 0x08;
    const BKSPC_TERMIOS: u8 = 0x7F;

    let mut input = String::new();
    input.reserve(16);
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

    input
}

fn read() -> String {
    read_masked(false)
}

fn secure_read() -> String {
    read_masked(true)
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
    use std::io::{BufRead, BufReader};

    // Currently, only ignore files that are in the same dir as the path to be
    // ignored are supported; this drastically simplifies both checking whether
    // a path is already ignored and determining how to express the path
    // relative to the ignore file.
    if ignore_file.parent() != path.parent() {
        panic!("Ignore file must be in the same directory as the file to be excluded from vcs!");
    }
    if ignore_file.exists() && !ignore_file.is_file() {
        panic!(
            "An ignore file already exists at {} but is not a regular file!",
            ignore_file.display()
        );
    }

    // We treat the contents of the ignore file as UTF-8, so we can't handle
    // non-UTF-8 paths to be excluded.
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

        // An ignore rule for foo and ./foo should both match since we are excluding a
        // path in the same directory as the ignore file itself.
        let cleaned_rule = line.strip_prefix("./").unwrap_or(&line);

        // Check if the processed line/rule already excludes the path we want to exclude
        if matched_paths.contains(&cleaned_rule) {
            // eprintln!("The key file {} is already excluded in ignore file {} by rule {}",
            //     path.display(), ignore_file.display(), &line);
            return Ok(true);
        }
    }

    // We only get here if the ignore file didn't contain the path we want to
    // exclude.

    // While we support both pathed (./foo) and unpathed (foo) pre-existing rules,
    // we prefer to always write out pathed rules only.
    let rule = format!("./{path_file_name}\n");
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
    writer.write_all(rule.as_bytes()).map_err(|err| {
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
