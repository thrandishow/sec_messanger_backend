FROM rust:1.91.1-bookworm AS build
WORKDIR /build
COPY broker/Cargo.toml broker/Cargo.toml
COPY broker/src broker/src
COPY api/ api/
RUN cargo build --release --locked --manifest-path api/Cargo.toml \
    && mkdir /runtime-libs \
    && cp -L /usr/lib/*-linux-gnu/libssl.so.3 /usr/lib/*-linux-gnu/libcrypto.so.3 /runtime-libs/

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /runtime-libs/ /usr/local/lib/
RUN ldconfig
COPY --from=build /build/api/target/release/shifr-api /usr/local/bin/shifr-api
USER 1000:1000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["shifr-api","healthcheck"]
CMD ["shifr-api"]
