use clap::{App, Arg, SubCommand};
use securestore::{KeySource, SecretsManager};
use serde_json::json;
use std::io::Write;
use std::path::Path;

#[derive(Debug, PartialEq)]
enum Mode<'a> {
    Get(GetKey<'a>, OutputFormat),
    Set(&'a str, &'a str),
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
        .author("Mahmoud Al-Qudsi, NeoSmart Technologies")
        .about("Securely store secrets in version control")
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
            Arg::with_name("keyfile")
                .global(true)
                .short("k")
                .long("keyfile")
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
                        .required(true)
                        .help("The value of the secret identifyied by KEY"),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
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
            std::process::exit(0);
        }
    };

    let mode_args = args.subcommand_matches(subcommand).unwrap();

    // We can't use `.is_present()` as the default value would coerce a true result
    let store = if mode_args.occurrences_of("STORE") > 0 {
        eprintln!("is present reported!");
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
            mode_args.value_of("value").unwrap(),
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
        std::process::exit(2); // 2 is both ENOENT and ERROR_FILE_NOT_FOUND 👍
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

    match run(mode, &store, keysource) {
        Ok(_) => {}
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(1);
        }
    }
}

fn run(mode: Mode, store: &Path, keysource: KeySource) -> Result<(), Box<dyn std::error::Error>> {
    let (keysource, key_export_path) = match (&mode, &keysource) {
        (Mode::Create, KeySource::File(path)) => {
            if !path.exists() || std::fs::metadata(path).unwrap().len() == 0 {
                (KeySource::Generate, Some(path))
            } else {
                eprintln!("Using existing keyfile {}", path.display());
                (keysource, None)
            }
        }
        _ => (keysource, None),
    };

    let mut sman = match &mode {
        Mode::Create => SecretsManager::new(store, keysource)?,
        _ => SecretsManager::load(store, keysource)?,
    };

    if let Some(path) = key_export_path {
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
        Mode::Set(key, value) => sman.set(key, value),
        Mode::Delete(key) => sman.remove(key)?,
    }

    sman.save()?;

    Ok(())
}

fn secure_read() -> String {
    const BKSPC_IN: u8 = 0x7F;
    const BKSPC_OUT: u8 = 0x08;

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
            b'\n' => {
                eprintln!("");
                break;
            }
            BKSPC_IN => {
                if input.len() > 0 {
                    input.truncate(input.len() - 1);
                    stderr.write(&[BKSPC_OUT, b' ', BKSPC_OUT]).unwrap();
                }
            }
            c => {
                input.push(c as char);
                stderr.write(&[b'*']).unwrap();
            }
        }
    }

    input
}
