.PHONY: all setup check

all:
	cargo build --release

setup:
	[ ! -f .env ] && cp -v .env.example .env

check:
	docker-compose up -d
	cargo clippy
	cargo test
	docker-compose down
