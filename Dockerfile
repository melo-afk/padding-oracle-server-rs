FROM docker.io/rust:1.90.0-slim-trixie AS build

WORKDIR /app

ADD . /app
RUN rustup target add x86_64-unknown-linux-musl 
RUN cargo build --release --target x86_64-unknown-linux-musl

# Use a slim Dockerfile with just our app to publish
FROM gcr.io/distroless/static-debian12

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/padding-oracle-server /

CMD ["/padding-oracle-server"]