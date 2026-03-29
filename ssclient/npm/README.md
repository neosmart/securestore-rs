# `ssclient`, the SecureStore CLI

This npmjs package contains a universal binary installer for [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) the rust cli companion to the open source, cross-platform, language-agnostic [SecureStore secrets management protocol](https://neosmart.net/SecureStore/).

This package will attempt to automatically download and install precompiled, dependency-free binaries for your os/architecture via the npmjs package repos. Please refer to the [`ssclient` documentation](https://github.com/neosmart/securestore-rs/tree/master/ssclient) for more information on the use of `ssclient` to create and manage truly secure secrets containers and help put an end to `.env` madness and insecurity.

## Installation

This package is compatible with `npm` and `bun`, and can be installed or run directly with with `npx`/`bunx`.

```sh
npm install [--global] @neosmart/ssclient
```

or

```sh
bun --global add @neosmart/ssclient
```

Will attempt to locate, download, and install a precompiled, dependency-free `ssclient` binary for your current platform/architecture. If no such precompiled binary currently exists, a WASM-compiled version of the binary [will be deployed instead](https://neosmart.net/blog/ssclient-wasm).

## Usage

Please refer to the [`ssclient` documentation](https://github.com/neosmart/securestore-rs/tree/master/ssclient) for full usage information, but the following is a brief guide on creating and access secrets with the `ssclient` cli:

Note that you may substitute `npx @neosmart/ssclient` or `bunx @neosmart/ssclient` for `ssclient` in the steps below if you have not globally installed `ssclient` via whatever means you prefer.

### Creating a new secrets container

```bash
~> mkdir secrets/
~> cd secrets/
~> ssclient create --export-key secrets.key
Password: ************
Confirm Password: ************

# Now you can use `ssclient -p` with your old password
# or `ssclient -k secrets.key` to encrypt/decrypt with
# the same keys.
```

### Adding secrets

Secrets may be added with your password or the equivalent encryption key file, and may be specified in-line as arguments to `ssclient` or more securely at a prompt by omitting the value when calling `ssclient create`:

```bash
# ssclient defaults to password-based decryption:
~> ssclient set aws:s3:accessId AKIAV4EXAMPLE7QWERT
Password: *********
```

similarly:

```bash
# Use `-k secrets.key` to load the encryption key and
# skip the prompt for the vault password:
~> ssclient -k secrets.key set aws:s3:accessKey
Value: v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

Note that in the latter example, the secret being stored was not typed into the shell (bash, fish, etc) and, as such, is not contained in/leaked by the shell history.

### Retrieving secrets

While you normally use one of the [SecureStore libraries for your language of choice](https://neosmart.net/SecureStore/) to load the SecureStore vault and decrypt secrets with the exported encryption/decryption key (`secrets.key`, in the example above), you can also use `ssclient` to view them at the command line:

```bash
~> ssclient get aws:s3:accessKey
Password: *********
v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

or you can export all secrets, either as text or json (again, either with the password or with the equivalent private key).

```bash
~> ssclient get --all # defaults to JSON
Password: *********
[
  {
    "key": "aws:s3:accessId",
    "value": "AKIAV4EXAMPLE7QWERT"
  },
  {
    "key": "aws:s3:accessKey",
    "value": "v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j"
  }
]
```

or

```bash
~> ssclient get --key secrets.key -a --format text
aws:s3:accessId:AKIAV4EXAMPLE7QWERT
aws:s3:accessKey:v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

Please refer to the [`ssclient` documentation](https://github.com/neosmart/securestore-rs/tree/master/ssclient) for full usage information.
