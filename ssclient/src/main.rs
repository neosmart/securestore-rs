use clap::{App, Arg, SubCommand};
use securestore::{KeySource, SecretsManager};
use serde_json::json;
use std::io::Write;
use std::path::Path;

const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const STATUS_CONTROL_C_EXIT: i32 = 0xC000013Au32 as i32;

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

fn main() {
    let is_tty = atty::is(atty::Stream::Stdin);
    let args = App::new("SecureStore")
        .version(env!("CARGO_PKG_VERSION"))
        .author(concat!("Copyright NeoSmart Technologies 2018-2020.\n",
                "Developed by Mahmoud Al-Qudsi and SecureStore contributors"))
        .about(concat!("Create and manage encrypted secrets stores.\n",
                "Learn more at https://neosmart.net/SecureStore/"))
        .arg(
            Arg::with_name("store")
                .global(true)
                .short("s")
                .long("store")
                .value_name("STORE")
                .help("Specify the path to the secrets store to use")
                .default_value("secrets.json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .global(true)
                .short("p")
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
            Arg::with_name("export-key")
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
                .short("k")
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
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Decrypt one or more secrets")
                .arg(
                    Arg::with_name("all")
                        .short("a")
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
        )
        .get_matches();

    let subcommand = match args.subcommand_name() {
        Some(name) => name,
        None => {
            eprintln!("{}", args.usage());
            return;
        }
    };

    let mode_args = args.subcommand_matches(subcommand).unwrap();

    // We can't use `.is_present()` as the default value would coerce a true result
    let store = if mode_args.occurrences_of("STORE") > 0 {
        Path::new(mode_args.value_of("create_store").unwrap())
    } else {
        // This has a default value of secrets.json so it's safe to unwrap
        Path::new(args.value_of("store").unwrap())
    };

    let mode = match args.subcommand_name() {
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
            eprintln!("{}", args.usage());
            std::process::exit(1);
        }
    };

    if mode != Mode::Create && !store.exists() {
        eprintln!("Cannot find secure store: {}", store.display());
        // 0x02 is both ENOENT and ERROR_FILE_NOT_FOUND 👍
        std::process::exit(ENOENT);
    }

    let mut password;
    let keysource = if args.is_present("keyfile") {
        let keyfile = Path::new(args.value_of("keyfile").unwrap());
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
            }
            keysource = KeySource::Password(&password);
            break;
        }
        keysource
    } else {
        if !args.is_present("password") {
            eprintln!("Either a password or keyfile is required!");
            eprintln!("{}", args.usage());
            std::process::exit(1);
        }
        KeySource::Password(args.value_of("password").unwrap())
    };

    let export_path = args.value_of("export-key");
    match run(mode, &store, keysource, export_path) {
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
) -> Result<(), Box<dyn std::error::Error>> {
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
            SecretsManager::new(store, keysource)?
        }
        _ => SecretsManager::load(store, keysource)?,
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
                    stderr.write(&[BKSPC, b' ', BKSPC]).unwrap();
                }
            }
            c => {
                input.push(c as char);
                if mask_input {
                    stderr.write(&[b'*']).unwrap();
                } else {
                    stderr.write(&[c]).unwrap();
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
