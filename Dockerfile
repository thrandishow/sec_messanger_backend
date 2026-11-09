FROM node:24.22.2-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM node:24.22.2-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
USER 1000:1000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD node --input-type=module -e "import https from 'node:https'; import fs from 'node:fs'; https.get('https://127.0.0.1:8443/health/ready', {ca: fs.readFileSync('/app/runtime/tls/ca.crt')}, r => {r.resume(); process.exitCode = r.statusCode === 200 ? 0 : 1}).on('error', () => {process.exitCode = 1})"
CMD ["node", "dist/index.js"]
