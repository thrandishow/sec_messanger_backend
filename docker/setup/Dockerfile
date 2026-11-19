FROM rust:1.91.1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY admin/Cargo.toml admin/Cargo.lock ./
COPY admin/src ./src
RUN cargo build --release --locked

FROM alpine:3.22
RUN apk add --no-cache openssl
COPY --from=build /build/target/release/shifrctl /usr/local/bin/shifrctl
WORKDIR /work
ENTRYPOINT ["shifrctl"]
