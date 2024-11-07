.PHONY: all setup check

all:
	cargo build --release

setup:
	[ ! -f .env ] && cp -v .env.example .env

check:
	cargo clippy
	cargo test --features docker
