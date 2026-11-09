FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl g++ make perl && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Stable upstream release, never the development master branch.
RUN curl -fsSL https://codeload.github.com/inspircd/inspircd/tar.gz/refs/tags/v4.12.1 -o source.tar.gz \
    && echo 'd88d16014349c572776d5dc0a55e4b28e61caba857b5fbee47c3a49ca1591fef  source.tar.gz' | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 \
    && perl ./configure --disable-auto-extras --disable-interactive --disable-ownership --prefix /opt/inspircd \
    && make -j2 install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/inspircd /opt/inspircd
COPY docker/inspircd/inspircd.conf /opt/inspircd/conf/inspircd.conf
USER 1000:1000
WORKDIR /opt/inspircd
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/6667' || exit 1
CMD ["/opt/inspircd/bin/inspircd", "--nofork", "--nopid", "--nolog", "--config", "/opt/inspircd/conf/inspircd.conf"]
