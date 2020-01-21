# Rust SecureStore library

[![crates.io](https://img.shields.io/crates/v/securestore.svg)](https://crates.io/crates/securestore)
[![docs.rs](https://docs.rs/securestore/badge.svg)](https://docs.rs/crate/securestore)

This crate contains a rusty implementation of [the open SecureStore secrets storage
protocol](http://neosmart.net/blog/2020/securestore-open-secrets-format/), that can read, write and
update encrypted password storage files that are designed to be stored alongside your code in your
GIT repository (or wherever else).

You can read more about SecureStore [on our
website](https://neosmart.net/blog/2020/securestore-secrets-storage). The associated command-line
client for managing the secrets store (creating a new store, adding, removing, and updating secrets)
can also be found [in this repository](../ssclient/).

## SecureStore API

The API for using SecureStore is primarily self-documenting and intentionally kept small. The
primary interface is via an instance of `SecretsManager`, which can only be created from scratch via
`SecretsManager::new(..)` or loaded from an existing on-disk store via `SecretsManager::load(..)`.

In the usual case, a SecureStore is created and updated via the command line, and the SecureStore
API is only used at runtime to retrieve and decrypt secrets individually. A SecureStore is decrypted
via either a password or a keyfile, and both the API and the command line interface provide a means
of creating a password-encrypted store but exporting a keyfile for use by the application at
runtime.

## Sample usage

As an example of its usage, including a brief demonstration of `ssclient`, the CLI companion to this
library (also available via crates.io and installable with `cargo`), can be seen below:

```bash
# First, install ssclient, the SecureStore CLI interface
~> cargo install ssclient

# Use ssclient to create a new store with password-based encryption,
# and export the derived keyfile so we can use the SecureStore API
# in a passwordless fashion.
~> ssclient create secrets.json --export-key secrets.key
Password: ***********
Confirm password: ***********

# Add a secret to the store. When -s/--store is not specified,
# defaults to secrets.json
~>  ssclient set foo EXtRAsuPErSECRET
Password: ***********
```

Back in the world of code, we can now use the SecureStore API from this crate to interface with the
secrets file we just created, and selectively decrypt its contents with either the password we used
at the time the store was created or the in a passwordless manner by means of the keyfile we
exported that contains the key derived from our password:

```rust
use securestore::{KeySource, SecretsManager};

fn get_api_key() -> String {
    let sman = SecretsManager::load("secrets.json",
                KeySource::File("secrets.key")).unwrap();
    let api_key = sman.get("foo").unwrap();

    assert_eq!("EXtRAsuPErSECRET", api_key.as_str());
    return api_key;
}
```

The SecureStore API also includes the relevant APIs for creating new stores; adding, removing,
and updating secrets; exporting keyfiles; and everything else typically done with the `ssclient` CLI
companion (which is built on this crate for maximum dogfooding).

## License and authorship

The SecureStore crate was originally developed by Mahmoud Al-Qudsi of NeoSmart Technologies and is
actively updated and maintained by NeoSmart Technologies and the SecureStore contributors. The
SecureStore crate is released under a dual MIT and Apache 2.0 License. Any contributions to this
crate are assumed to be licensed likewise; contributions not under the both of these licenses are
not being accepted at this time.

## See also

* For more information about the open SecureStore format, the cryptography used, the rationale
  behind shipping your passwords alongside your code, and more, please refer to the original article
  [published at the time of the initial SecureStore implementation for
  .NET](https://neosmart.net/blog/2017/securestore-a-net-secrets-manager/) and the updated article
  [covering the release of version 1.0 of this
  crate](http://neosmart.net/blog/2020/securestore-open-secrets-format/).
* [The documentation for this crate](https://docs.rs/crate/securestore) on docs.rs
* [`ssclient`, the companion CLI utility for creating and managing secrets stores](../ssclient/)
