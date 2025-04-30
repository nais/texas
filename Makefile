.PHONY: all setup check test_roundtrip openapi

all:
	cargo build --release

setup:
	([ ! -f .env ] && cp -v .env.example .env) || true

local:
	RUST_LOG=info,texas=debug cargo run --features local

check:
	cargo clippy
	cargo fmt --check
	cargo test --features docker

test_roundtrip:
	./hack/roundtrip-azure-cc.sh
	./hack/roundtrip-azure-obo.sh
	./hack/roundtrip-idporten.sh
	./hack/roundtrip-maskinporten.sh
	./hack/roundtrip-tokenx.sh

openapi:
	cargo run --bin gen-openapi > doc/openapi-spec.json
