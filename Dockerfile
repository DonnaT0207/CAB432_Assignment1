# Dockerfile
FROM node:20-bookworm-slim

# ffmpeg + build deps for better-sqlite3
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg python3 build-essential pkg-config make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

ENV NODE_ENV=production PORT=8080 \
    DEFAULT_PRESET=medium DEFAULT_CRF=28 DEFAULT_THREADS=1 DEFAULT_SCALE=

EXPOSE 8080
CMD ["node", "index.js"]
