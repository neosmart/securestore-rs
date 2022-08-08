set rustflags=-Ctarget-feature=+crt-static
cargo build --release --features openssl-vendored
signtool.exe sign -fd sha256 -n "NeoSmart Technologies, Inc." -tr http://sha256timestamp.ws.symantec.com/sha256/timestamp ./target/release/ssclient.exe
del ssclient-xxx-win64.zip
REM Using ./ before a path means include it but not its parent directories
"C:\Program Files\7-Zip\7z.exe" a ssclient-xxx-win64.zip ./target/release/ssclient.exe ./ssclient/README.md ./LICENSE
