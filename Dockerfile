FROM --platform=linux/amd64 node:22-alpine AS builder

WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY . .

RUN find . \( -name '._*' -o -name '.DS_Store' \) -delete

# Generated SDK reference is committed; skip prebuild sync (needs hebrah-sdk-node sibling).
RUN pnpm exec tsc

FROM --platform=linux/amd64 node:22-alpine AS runner

WORKDIR /app

RUN corepack enable

ENV NODE_ENV=production
ENV PORT=3021
ENV HOST=0.0.0.0

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json /app/pnpm-lock.yaml ./
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3021

CMD ["node", "dist/index.js"]
