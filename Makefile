.PHONY: all setup check test_roundtrip openapi

all:
	cargo build --release

setup:
	([ ! -f .env ] && cp -v .env.example .env) || true

local:
	RUST_LOG=info,texas=debug cargo run --features local

check:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo fmt --check
	cargo test --features docker

# cargo install cargo-audit cargo-deny cargo-outdated --locked
security:
	cargo audit
	cargo deny check -s --hide-inclusion-graph
	cargo outdated --root-deps-only

test_roundtrip:
	./hack/roundtrip-azure-cc.sh
	./hack/roundtrip-azure-obo.sh
	./hack/roundtrip-idporten.sh
	./hack/roundtrip-maskinporten.sh
	./hack/roundtrip-maskinporten-rar.sh
	./hack/roundtrip-tokenx.sh

openapi:
	cargo run --bin gen-openapi > doc/openapi-spec.json
