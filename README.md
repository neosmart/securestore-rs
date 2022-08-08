# SecureStore for Rust

[![crates.io](https://img.shields.io/crates/v/securestore.svg)](https://crates.io/crates/securestore)
[![docs.rs](https://docs.rs/securestore/badge.svg)](https://docs.rs/crate/securestore)

This repository houses [the `ssclient` command-line utility](./ssclient/) for creating and
manipulating [SecureStore secrets
files](http://neosmart.net/blog/2020/securestore-open-secrets-format/) as well as [the `securestore`
rust crate](./securestore/) providing an API for retrieving and decrypting secrets from a
SecureStore at runtime.

## Usage

This rust implementation of the SecureStore protocol ships in two separate, complementary parts: [a command line client](./ssclient/) (`ssclient`) and [a rust library/crate](./securestore/) (`securestore`). Both (mostly) expose the same functionality, but are intended to be used together for maximum productivity and ergonomics.

The typical workflow for deploying versioned secrets alongside a restricted-access binary (e.g. a web app, a kiosk, or similar where the application isn't distributed directly to end users and is running in what is considered to be a privileged environment) is demonstrated here.

## Adding a SecureStore vault to your rust workspace

Start by installing a copy of `ssclient`, the interactive SecureStore cli. Pre-built binaries are available (see releases), but the majority of rust developers will find the most convenient option for distribution to be direct installation via `cargo`:

<pre>
&gt; cargo install ssclient
<b><span style="color:#0A0">    Updating</span></b><b><span style="color:#0A0"></span></b> crates.io index
<b><span style="color:#0A0">  Installing</span></b> ssclient v0.100.0
<b><span style="color:#0A0">   Compiling</span></b> securestore v0.100.0
<b><span style="color:#0A0">   Compiling</span></b> ssclient v0.100.0
<b><span style="color:#0A0">    Finished</span></b> release [optimized] target(s) in 36.14s
<b><span style="color:#0A0">  Installing</span></b> /home/mqudsi/.cargo/bin/ssclient
<b><span style="color:#0A0">   Installed</span></b> package `ssclient v0.100.0` (executable `ssclient`)
</pre>

`ssclient` will be installed and added to the cargo binary directory in your `$PATH`, making it available in a terminal session merely by invoking `ssclient`.

Let's imagine your worktree is a typical rust binary application with a layout matching a typical Cargo-based rust project:

```sh
> tree
.
├── .git/
├── Cargo.toml
└── src
    └─ main.rs
```

We'll be storing our secrets in a folder called `secure` in the root of our cargo workspace. Open a terminal, `cd` into your rust project, and execute the following to create a new `secure` directory and use `ssclient` to create a new secrets vault called `secrets.json` (which is the SecureStore protocol default name):

```sh
> cd my-rust-project
> mkdir secure
> cd secure
> ssclient create secrets.json --export-key secrets.key
Password: ************
Confirm password: ************
Saving newly generated key to secrets.key
Excluding key file in newly-created VCS ignore file .gitignore
```

`ssclient` will prompt you to enter (then confirm) a password before it creates a new `secrets.json` file (currently a skeleton SecureStore vault without any secrets). The vault is symmetrically encrypted but can be decrypted either with the password you just entered or with the key file we just exported (`secrets.key`). When updating or interacting with the SecureStore vault via `ssclient` at the command line, we'll use password-based encryption/decryption, but when we deploy the app in dev or production, we'll be using key-based encryption/decryption instead.

The layout of our project folder now looks like this:

```sh
> tree .
.
├── .git/
├── Cargo.toml
├── secure
│   ├── .gitignore
│   ├── secrets.json
│   └── secrets.key
└── src
    └── main.rs
```

As you can see, there are three new files under the `secrets` subdirectory: `secrets.json` (the human-readable SecureStore vault), `secrets.key` (the <span style="color: red; font-weight:bold;">sensitive &amp; secure</span> master key that lets us bypass password protection to decrypt secrets in production without manual intervention), and a `.gitignore` file that was helpfully created by `ssclient` and prevents `secrets.key` from being accidentally committed to the git repo.

The [SecureStore protocol](http://neosmart.net/blog/2020/securestore-open-secrets-format/) specifies that `secrets.json` _should_ be added to the git repository and versioned alongside the rest of the code that uses its secrets, and absolutely forbids `secrets.key` from being committed to a VCS.

Here's what the "empty" `secrets.json` file looks like right now, before we've added any secrets:

```json
{
  "version": 3,
  "iv": "eebJviP8bIC6XF6fp1g4Cw==",
  "sentinel": {
    "iv": "dVEOSg1OaM6LLF2fB7W7jg==",
    "hmac": "mY1LP5gBDQaYFenC2oHHRb7LXSg=",
    "payload": "7mFgSJSYclBBPo+Xbel0DA5y8e24QKqUh7m8EXy5+8bSagUoHGoIi2sJSKlSDP4X"
  },
  "secrets": {}
}
```

This is the basic "skeleton" of a SecureStore (v3) vault, containing just enough info to let `ssclient` or the `securestore` crate verify that we're using the correct encryption/decryption key the next time we open the vault.

The generated `secure/.gitignore` file contains the following (one) rule:

```
secrets.key
```

All it does is stop `secure/secrets.key` from being accidentally added to the git repo.

Go ahead and add the `secure` directory to git, then move on to the next section to see how we'll add secrets and then access them at run-time from our rust application:

```sh
git add secure/
git commit -m "Add empty SecureStore vault"
git push
```

## Adding secrets to your SecureStore vault

At this point, the vault has been created and we're ready to add one or more secrets to the vault. The secrets will be stored encrypted in `secrets.json` and versioned in git alongside the same code using them, making it easy to roll back to earlier versions and make sure that managed secrets are kept in lock-step with the code that depends on them, across merges and PRs.

Starting from the terminal where we left off, let's add a secret or two (say, the credentials for accessing PostgreSQL and the AWS IAM credentials to upload or sign S3 urls). We can either specify the secret value at the command line (`ssclient set secret_name secret_value`) or enter it at a prompt provided by `ssclient` for more security (e.g. to avoid the secret being stored in our bash history) or for convenience (e.g. entering special characters that would otherwise need to be escaped under bash) by only specifying the secret name (`ssclient set secret_name`). We can omit the store name/path because we're using the default (`secrets.json`) and we don't need to specify `-p` or `--password` because `ssclient` defaults to password-based decryption.

Let's `cd` into the `secure` directory and set the first secret:

```sh
> cd secure/
> ssclient set db:username
Password: ************
Value: pgadmin
```

To demonstrate how the SecureStore protocol allows interchangeable encryption/decryption with either a password or a key file, we'll set the next secret value using the key file we generated earlier (`secrets.key`) and we'll notice that the secret is added without `ssclient` prompting us to enter a password (but it's still encrypted, of course):

```sh
> ssclient -k secrets.key set db:password pgsql123
Value: pgsql123
```

Let's go ahead and set two more secrets, representing the AWS S3 IAM username and password:

```sh
> ssclient -k secrets.key set aws:s3:access_id AKIAIOSFODNN7
> ssclient -k secrets.key set aws:s3:access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCY
```

The secrets vault (`secrets.json`) now contains four secrets (two not-actually-secret usernames and two actually-secret passwords). The only file that has changed in our git worktree is the secrets vault:

```sh
> git status
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
    (use "git restore <file>..." to discard changes in working directory)
            modified:   secrets.json
```

Let's see what our `secrets.json` file looks like now:

```json
{
  "version": 3,
  "iv": "eebJviP8bIC6XF6fp1g4Cw==",
  "sentinel": {
    "iv": "dVEOSg1OaM6LLF2fB7W7jg==",
    "hmac": "mY1LP5gBDQaYFenC2oHHRb7LXSg=",
    "payload": "7mFgSJSYclBBPo+Xbel0DA5y8e24QKqUh7m8EXy5+8bSagUoHGoIi2sJSKlSDP4X"
  },
  "secrets": {
    "aws:s3:access_id": {
      "iv": "4YEmTY9rwW7pq7/Iv6Vncg==",
      "hmac": "tFO2cN/Fh/jO7ijbAXh98yrm2Nk=",
      "payload": "ejKs4D2anovxS1OyX8e4Eg=="
    },
    "aws:s3:access_key": {
      "iv": "czwulU+ejDXD0dryqA6aaA==",
      "hmac": "w/egLShBDwu9L/Wagk/EKQVzpK0=",
      "payload": "OfJM7ZDLOkGhD8OwjfOOQrHNgyeQqYPuDZKwARxN/nw="
    },
    "db:password": {
      "iv": "rN0a3GVuTkBctAbCO51VQA==",
      "hmac": "ko8YB33XxhCEIge8Rxdyab1EA4Y=",
      "payload": "uvq/NsjCfVkc6Upv8EWg8A=="
    },
    "db:username": {
      "iv": "CkWYqyIWOTquFco/NZGiKA==",
      "hmac": "ODcnI82hkzQ+9feyf/1WlV3yxt8=",
      "payload": "oEmn2rQE9Hva97XwdNYkoA=="
    }
  }
}
```

We can see there are four new named JSON objects under `secrets`, one for each secret. They're encrypted and encoded per the cross-platform SecureStore protocol in a way that's human-readable (plain-text, compact base64 representation of binary payloads, well-formatted), git-friendly (sorted by name, formatted with new lines between each secret and delimiting each secrets component, etc), and cross-platform compatible (standardized encryption and base64 encoding).

If you're following along in your own terminal, you'll hopefully notice that while the basic structure of your `secrets.json` file is the same as this one, the secret values themselves differ - this isn't just because we picked different passwords, though! This is part of what makes a SecureStore vault so secure, and prevents attackers from guessing your password or the encrypted secret contents if they get their hands on your `secrets.json` (which is safe enough to publish to GitHub or even the front page of _The New York Times_ without worry) -- as long as your `secrets.key` stays secure, of course!

Go ahead and commit your updated secrets to git:

```sh
> git add secrets.json
> git commit -m "Add secrets for db and s3 access"
```

## Retrieving secrets at runtime

At this point, we're going to set `ssclient` aside and focus on the rust side of things to see how secrets can be retrieved at runtime. First, let's add a dependency on the `securestore` crate to our `Cargo.toml`. We'll also add a dependency on `once_cell` to use `securestore::SecretsManager` as a singleton for demonstration purposes:

```toml
[package]
name = "sstemp"
version = "0.1.0"
edition = "2021"

[dependencies]
once_cell = "1.13.0"
securestore = "0.99.3"
```

After which we can open `src/main.rs` and add some code to open the secrets file and decrypt + retrieve one or more secrets at runtime. [The ssclient documentation](https://docs.rs/securestore/latest/securestore/) covers how the `securestore` crate and its primary `SecretsManager` type are used, but we'll demo the basics below.

At the top of `main.rs`, let's add some imports and a `once_cell::sync::Lazy` instance to hold our `SecretsManager`, since it's highly recommended to only have one `SecretsManager` instance servicing all secrets requests for the lifetime of the application:

```rust
use securestore::{KeySource, SecretsManager};
use std::path::Path;
use once_cell::sync::Lazy;

static SECRETS: Lazy<SecretsManager> = Lazy::new(|| {
    let keyfile = Path::new("secure/secrets.key");
    SecretsManager::load("secure/secrets.json", KeySource::File(keyfile))
        .expect("Failed to load SecureStore vault!")
})
```

As for accessing the secrets, let's add a helper function `get_db_credentials()` that will look up the secrets named `db:username` and `db:password` that we previously saved to the vault and return them as a `(String, String)` tuple:

```rust
fn get_db_credentials() -> Result<(String, String), securestore::Error> {
    let username = SECRETS.get("db:username")?;
    let password = SECRETS.get("db:password")?;
    Ok((username, password))
}
```

and verify that the application builds without any issues:

```sh
> cargo build
   Compiling sstemp v0.1.0 (/tmp/sstemp)
    Finished dev [unoptimized + debuginfo] target(s) in 0.74s
```

And that's all there is to it! We can demonstrate that it works by adding a test asserting the contents of the secrets (of course this would be a no-no in the real world!):

```rust
#[test]
fn verify_db_credentials() -> Result<(), securestore::Error> {
    let expected = ("pgadmin".to_owned(), "pgsql123".to_owned());
    let actual = get_db_credentials()?;

    assert_eq!(expected, actual);
    return Ok(());
}
```

Then run the test:

```sh
> cargo test
    Finished test [unoptimized + debuginfo] target(s) in 0.06s
         Running unittests src/main.rs (tar et/debug/deps/sstemp-b3b06ea1ff58c9da)

         running 1 test
         test verify_db_credentials ... ok
```


We just need to make sure that when we deploy our code (via whatever method we normally deploy our app into production), we also send a copy of the `./secure` folder and store it alongside the executable (or in the CWD we execute our app under) -- this includes both the versioned and safe-to-share-with-the-world `secure/secrets.json` as well as the highly secret `secure/secrets.key` that mustn't ever be leaked to a non-secure environment.

# Advanced secrets management topics

You'll notice that in the guide above, we stored two secrets (`db:password` and `aws:s3:access_key`) and two not-so-secret values (`db:username` and `aws:s3:access_id`) that could have been instead hard-coded into the application. What gives?

The answer lies in how SecureStore should be used in the real world, with teams of *n* > 1 and where not everyone may have the commit bit. Ideally, your dev and production infrastructure should be completely separate, as should your secrets. The SecureStore protocol makes this easy because it's really just a glorified (but secure!) key-value database, versioned and stored alongside your code itself. In practice, you won't just have `secrets.key` and `secrets.json` - you'll actually have a vault/key pair for each of your dev/staging/production environments, with all the vaults saved under the `secure/` folder and committed to the repository, but with the corresponding `secrets.key` file for each environment's vault only shared with the people that should have access to it. Perhaps everyone has access to `secrets.dev.key` and can add/retrieve/remove secrets from `secrets.dev.json` but the production `secrets.prod.key` is only stored on the CI servers as a protected asset deployed to production but protected from being retrieved by any team members except for those with direct access to the secure CI environment or remote access to the production servers (your actual scenario will likely differ, but the basic idea stands).

The generic KV-nature of the SecureStore protocol and the SecureStore crate make it easy to abstract over the different dev/staging/prod configurations by simply loading a different store at startup depending on the environment (identified, say, by an environment variable), combined with storing any configuration-dependent non-secret values (usernames, connection strings, host addresses, etc) _as if_ they were secrets in the same SecureStore vault, all automatically resolved just by determining and loading the correct store just once. For example, your actual `SECRETS` declaration could look like this:

```rust
static SECRETS: Lazy<SecretsManager> = Lazy::new(|| {
    let (store_path, key_path) = match std::env::var("MYWEBAPP_ENV").as_ref().map(|s| s.as_str()) {
        Ok("STAGING") => ("secure/secrets.staging.json", Path::new("secure/secrets.staging.key")),
        Ok("PRODUCTION") => ("secure/secrets.prod.json", Path::new("secure/secrets.prod.key")),
        _ => ("secure/secrets.dev.json", Path::new("secure/secrets.dev.key")),
    };

    SecretsManager::load(store_path, KeySource::File(key_path))
        .expect("Failed to load SecureStore vault!")
});
```

So while we _could have_ hard-coded `db:username`, that would have meant also testing `MYWEBAPP_ENV` in `get_db_credentials()` to figure out what username to return in addition to the `MYWEBAPP_ENV` check in the `SECRETS` declaration that determined which secrets store to load. But if we store `db:username` as a secret the same way we store `db:password`, all that differentiation is done automatically for us. In addition, it makes sense to keep all the credentials info in one place (the secrets vault), wholly separate from the runtime logic - if you need to update the username and password in the future, you just need to update them in one place (the vault) rather than needing to patch both `secrets.json` and `src/main.rs` (in addition to remembering to do so).
