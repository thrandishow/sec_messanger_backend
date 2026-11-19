FROM rust:1.91.1-bookworm AS build
WORKDIR /build
COPY broker/Cargo.toml broker/Cargo.lock ./
COPY broker/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /build/target/release/shifr-broker /usr/local/bin/shifr-broker
USER 1000:1000
ENV BROKER_BIND=0.0.0.0:7000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["shifr-broker", "healthcheck"]
ENTRYPOINT ["shifr-broker"]
