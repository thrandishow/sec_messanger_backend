FROM node:24.22.2-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/setup.mjs /opt/shifr/setup.mjs
WORKDIR /work
ENTRYPOINT ["node", "/opt/shifr/setup.mjs"]
