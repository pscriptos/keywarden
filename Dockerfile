# Keywarden - Centralized SSH Key Management and Deployment
# Multi-stage build for minimal image size

# Stage 1: Build
FROM golang:1.26.2-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=""
RUN set -e; \
    if [ -z "$VERSION" ]; then \
      VERSION=$(grep 'var Version' internal/version/version.go | sed 's/.*"\(.*\)".*/\1/'); \
    fi; \
    CGO_ENABLED=1 GOOS=linux go build -o keywarden -ldflags="-s -w -X git.techniverse.net/scriptos/keywarden/internal/version.Version=${VERSION}" ./cmd/keywarden/

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache ca-certificates sqlite-libs tzdata curl su-exec

RUN addgroup -S keywarden && adduser -S keywarden -G keywarden

WORKDIR /app
COPY --from=builder /build/keywarden .
COPY entrypoint.sh .

RUN mkdir -p /data/keys /data/master /data/avatars && \
    chown -R keywarden:keywarden /data /app && \
    chmod +x /app/entrypoint.sh

ENV KEYWARDEN_PORT=8080
ENV KEYWARDEN_DB_PATH=/data/keywarden.db
ENV KEYWARDEN_DATA_DIR=/data
ENV KEYWARDEN_KEYS_DIR=/data/keys
ENV KEYWARDEN_MASTER_DIR=/data/master
ENV KEYWARDEN_ENCRYPTION_KEY=change-me-encryption-key-32chars
ENV TZ=UTC

EXPOSE 8080

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${KEYWARDEN_PORT:-8080}/api/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
