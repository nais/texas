.PHONY: all setup

all:
	cargo build --release

setup:
	[ ! -f .env ] && cp -v dotenv.example .env
