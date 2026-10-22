FROM --platform=linux/amd64 node:22-alpine AS builder

WORKDIR /app

RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates openssl && corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY . .

RUN find . \( -name '._*' -o -name '.DS_Store' \) -delete

# Generated SDK reference is committed; skip prebuild sync (needs hebrah-sdk-node sibling).
RUN pnpm exec tsc

FROM --platform=linux/amd64 node:22-alpine AS runner

WORKDIR /app

# Upgrade Alpine base (libcrypto3 / libssl3 3.5.9+) and CA certificates
RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates openssl

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
