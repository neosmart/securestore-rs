# `ssclient` SecureStore companion utility

`ssclient` is a companion utility to the (rust) implementation [of the SecureStore open secrets
format](http://neosmart.net/blog/2020/securestore-open-secrets-format/), although it may be used to
create and manage SecureStore secrets files for any compatible SecureStore implementation. The
companion crate to this utility for creating or consuming SecureStore secrets from within rust code
can be found [in this same crate](../securestore/).

## The SecureStore open format

[SecureStore is an open protocol for securely storing
secrets](http://neosmart.net/blog/2020/securestore-open-secrets-format/) in human-readable files that are
versioned alongside the code that uses them and are intended to be shipped with your deployed
binaries. To make things really nice and easy for developers, this command line utility was
developed to allow for creating secrets stores and managing their secrets via a simple interface.

## Installation

`ssclient` is published as an installable binary crate on crates.io, and can be installed directly
via `cargo`, the rust package manager:

```bash
~> cargo install ssclient
```

## Usage

The command line options available for usage with `ssclient` can be seen by running either
`ssclient -h` for a basic listing of options or `ssclient --help` for extended usage information:

```
USAGE:
    ssclient [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help        Prints help information
    -p, --password    Prompt for password used to derive key.
                      In headless environments takes the password as an argument.
    -V, --version     Prints version information

OPTIONS:
        --export-key <EXPORT_PATH>    Exports a key equivalent to the supplied password
    -k, --key <KEYFILE>               Use key stored at KEYFILE
    -s, --store <STORE>               Specify the path to the secrets store to use [default: secrets.json]

SUBCOMMANDS:
    create    Create a new store
    delete    Remove a secret from the store
    get       Decrypt one or more secrets
    help      Prints this message or the help of the given subcommand(s)
    set       Add or update an encrypted value to the store
```

The command line interface has been optimized to reduce friction when working with secrets, it
should be a ~~joy~~ breeze to manage secrets for a new or existing projects, and developers
shouldn't have to hesitate or put off securing secrets.

### Creating a new secrets store

Secrets are stored in human-readable, pretty-printed JSON files that are intended to be added to
version control along with the same code that depends on them. The file format is carefully designed
to be VCS-friendly and is resilient to merging/rebasing. A new store can be created with the
`ssclient create` subcommand. Stores are always encrypted (both on-disk and in-memory in SecureStore
API clients) and both the API and the `ssclient` frontend support multiple options for encryption
key sources, with the option to use password-based encryption/decryption, have the application/api
generate encryption keyfiles for you, or bring your own keyfiles.

The typical scenario is to create a new store using a password, from which the needed encryption
key(s) are automatically (and securely) derived, and also export a compatible copy of the encryption
key with it. This lets you interact with `ssclient` using the convenience of password-based
encryption/decryption while securely deploying the encryption key out-of-band to your production
servers where it can be used to decrypt the secrets file in a password less manner.

To create a new store using password-based encryption at the command line:

```bash
~> ssclient create secrets.json
Password: ***********
Confirm password: ***********
```

Where `secrets.json` is the name of the store to be created. If no store name is specified,  omitted,
`secrets.json` is used by default.

To create a store using key-based authentication (i.e. no option to decrypt with a password), use
the following instead:

```bash
ssclient create secrets.json -k secrets.key
```

If `secrets.key` exists and is a valid key file, it will be used to encrypt a new store at
`secrets.json`. If `secrets.key` does not exist, a CSPRNG will be used to securely generate a new
key for you, a copy of which is saved to the supplied path (in this case, `secrets.key`), with the
new store itself being saved at the path provided (`secrets.json` in this example).

When neither `-p`/`--password` nor `-k`/`--keyfile` is supplied, `ssclient` defaults to
password-based encryption/decryption for convenience.

When using password-based encryption, you can use `--export-key PATH` to export a copy of the key(s)
derived from the password to `PATH`, so that the keyfile can subsequently be used together with the
SecureStore API to decrypt individual secrets in a passwordless fashion:

```bash
~> ssclient create secrets.json --export-key secrets.key
Password: ***********
Confirm password: ***********
```

### Adding or updating secrets

With a store created, naturally the first thing you'll want to do is add a secret to it. Secrets are
added one-at-a-time via the `ssclient set` subcommand.

Secrets may be provided directly as command line arguments (tip: prefixing a command with a single
space excludes it from the history file in most shells):

```bash
ssclient set aws:s3:accesskey 715a868e-3c83-11ea-99bd-af944d8d3940
```

or interactively for added security:

```bash
~> ssclient set aws:s3:accesskey
Password: ********
Value: 715a868e-3c83-11ea-99bd-af944d8d3940
```

If a secret by the same name already exists, it will be overwritten without confirmation.

### Retrieving and decrypting a single secret

As a direct parallel to `ssclient set`, `ssclient get` can be used to retrieve a single secret. As
with all other subcommands, the name of the store to use can be specified with `-s`/`--store` and
defaults to `secrets.json` and the mode of encryption/decryption can be picked with
`-p`/`--password` or `-k/--key KEY`, defaulting to `--password` in interactive environments.

```bash
~> ssclient -k secrets.key get aws:s3:accesskey
715a868e-3c83-11ea-99bd-af944d8d3940
```

When used in a headless environment, the password may be specified directly as a command line
argument (after the `-p`/`--password`). **We do not recommend doing this, export and use a keyfile
instead!**

### Exporting all secrets

`ssclient get` supports an optional `-a`/`--all` parameter that exports all the `(key, secret)`
pairs in the store. SecureStore is an open format and we believe you should always be able to get
your data in a universal format, but please use this option with care!

The optional `--format` switch can be used to influence the output format of the exported data. The
default is `json`, but `text` may be used instead (please keep in mind that in `text` mode, no
escaping is performed and it may be tricky to correctly parse the results):

```bash
~> ssclient get --all -k secrets.key
[
  {
    "key": "aws:s3:accesskey",
    "value": "715a868e-3c83-11ea-99bd-af944d8d3940"
  },
  {
    "key": "secret",
    "value": "password"
  }
]
```

In `json` mode, the output is guaranteed to be valid JSON and is a JSON array of objects, each with
a `key` (the secret name) and a `value` (the secret itself).

In text mode, each result is printed on a new line:

```bash
~> ssclient get --all --format text --key secrets.key
aws:s3:accesskey: 715a868e-3c83-11ea-99bd-af944d8d3940
secret: password
```

Notice how naive text splitting on `:` would not have parsed the results correctly.

### Removing a secret

A secret may be removed from the store by means of the `ssclient delete` subcommand. An error is
displayed if the requested key is not found in the store.

```bash
~> ssclient delete aws:s3:accesskey
Password: ********
```

## License and Copyright

`ssclient` was created by Mahmoud Al-Qudsi of NeoSmart Technologies, and is Copyright NeoSmart
Technologies 2019-2010. `ssclient` is released to the general public without any warranty in the
hopes that it might be beneficial, dually licensed (at your choosing) under the MIT and Apache
2.0 public licenses.

## Contributions

Contributions are welcome in the form of bug reports and pull requests, as well as new projects
implementing SecureStore in/for other languages.
