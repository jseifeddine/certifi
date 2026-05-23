# Build context for this Dockerfile is the repo root (set via docker-compose),
# so paths below are repo-relative. The web admin source lives in `web/`
# and the nginx config lives in `deploy/`.

# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN npm ci

COPY web/tsconfig*.json \
     web/vite.config.ts \
     web/tailwind.config.js \
     web/postcss.config.js \
     web/index.html \
     ./
COPY web/src ./src
RUN npm run build

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
