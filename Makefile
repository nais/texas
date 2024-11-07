.PHONY: all setup check

all:
	cargo build --release

setup:
	[ ! -f .env ] && cp -v .env.example .env

check:
	cargo clippy
	cargo test --features docker

test_roundtrip:
	./hack/roundtrip-azure-cc.sh
	./hack/roundtrip-azure-obo.sh
	./hack/roundtrip-maskinporten.sh
	./hack/roundtrip-tokenx.sh
