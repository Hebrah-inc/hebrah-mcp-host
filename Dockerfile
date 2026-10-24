FROM --platform=linux/amd64 node:22.23.4-alpine AS builder

WORKDIR /app

RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates openssl brotli-libs libcrypto3 libssl3 sqlite-libs c-ares nghttp2-libs && corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY . .

RUN find . \( -name '._*' -o -name '.DS_Store' \) -delete

# Generated SDK reference is committed; skip prebuild sync (needs hebrah-sdk-node sibling).
RUN pnpm exec tsc

FROM --platform=linux/amd64 node:22.23.4-alpine AS runner

WORKDIR /app

# Upgrade Alpine base (Node >= 22.23.4, brotli-libs, libcrypto3 / libssl3, sqlite-libs, c-ares, nghttp2-libs) and CA certificates
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache ca-certificates openssl brotli-libs libcrypto3 libssl3 sqlite-libs c-ares nghttp2-libs && \
    node -e "const [maj,min,pat]=process.versions.node.split('.').map(Number); if(maj<22||(maj===22&&(min<23||(min===23&&pat<4)))) { console.error('Unpatched Node version:', process.versions.node); process.exit(1); }"

ENV NODE_ENV=production
ENV PORT=3021
ENV HOST=0.0.0.0

COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/package.json /app/pnpm-lock.yaml ./
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
RUN chown node:node /app

USER node

EXPOSE 3021

CMD ["node", "dist/index.js"]
