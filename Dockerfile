FROM docker.io/rust:1.90.0-slim-trixie AS build

WORKDIR /app

ADD . /app
RUN rustup target add x86_64-unknown-linux-musl 
RUN cargo build --release --target x86_64-unknown-linux-musl

# Use a slim Dockerfile with just our app to publish
FROM docker.io/alpine:3.22

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/padding-oracle-server /app/padding-oracle-server

CMD ["/app/padding-oracle-server"]