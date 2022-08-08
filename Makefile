# CargoMake by NeoSmart Technologies
# Written and maintained by Mahmoud Al-Qudsi <mqudsi@neosmart.net>
# Released under the MIT public license
# Obtain updates from https://github.com/neosmart/CargoMake

COLOR ?= always # Valid COLOR options: {always, auto, never}
CARGO = cargo --color $(COLOR)

.PHONY: all bench build check clean doc install publish run test update target/x86_64-unknown-linux-musl/release/ssclient

all: build

bench:
	@$(CARGO) bench

build:
	@$(CARGO) build

check:
	@$(CARGO) check

clean:
	@$(CARGO) clean

doc:
	@$(CARGO) doc

install: build
	@$(CARGO) install

publish:
	@$(CARGO) publish

run: build
	@$(CARGO) run

test: build
	@$(CARGO) test

update:
	@$(CARGO) update

target/x86_64-unknown-linux-musl/release/ssclient:
	env RUSTFLAGS= cargo build --target x86_64-unknown-linux-musl --release --features openssl-vendored
	strip target/x86_64-unknown-linux-musl/release/ssclient

ssclient-xxx-linux.tar.gz: target/x86_64-unknown-linux-musl/release/ssclient ssclient/README.md LICENSE
	tar cvzf ssclient-xxx-linux.tar.gz LICENSE -C ssclient/ README.md -C ../target/x86_64-unknown-linux-musl/release/ ssclient

release: ssclient-xxx-linux.tar.gz
