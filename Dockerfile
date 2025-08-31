# ---- base ----
FROM node:20-bullseye-slim

# better-sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY index.js ./
COPY public ./public

RUN mkdir -p /app/data/uploads /app/data/outputs /app/data/subtitles

ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "index.js"]
