run: build
    ./target/release/padding-oracle-server

ambig: build
    ./target/release/padding-oracle-server -a

build:
    cargo build --release

serve: build
    ./target/release/padding-oracle-server -g -k keys.json -t tests.json
    ./target/release/padding-oracle-server -s -k keys.json

clippy:
    cargo clippy --fix --allow-dirty

