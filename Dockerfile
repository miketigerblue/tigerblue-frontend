# syntax=docker/dockerfile:1
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Next.js needs these during `next build` (build-time), but Fly secrets are runtime-only.
ARG NEXT_PUBLIC_POSTGREST_BASE
ENV NEXT_PUBLIC_POSTGREST_BASE=$NEXT_PUBLIC_POSTGREST_BASE

ARG NEXUS_BASE
ENV NEXUS_BASE=$NEXUS_BASE

# Ensure /app/public exists so the runner-stage COPY doesn't fail for repos without assets.
RUN mkdir -p public

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/next.config.mjs ./next.config.mjs
EXPOSE 3000
CMD ["npm","run","start"]
