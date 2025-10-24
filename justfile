run: build
    ./target/release/padding-oracle-server -vv

ambig: build
    ./target/release/padding-oracle-server -a

build:
    cargo build --release


clippy:
    cargo clippy --fix --allow-dirty

