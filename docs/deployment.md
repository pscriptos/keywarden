# Installation & Deployment

This guide covers production deployment of Keywarden using Docker.

## Docker Deployment

Keywarden is designed as a single-container application with an embedded SQLite database. No external database server is required.

### Docker Image

Build from source or use the pre-built image:

```bash
# Build from source
docker compose build

# Or build manually
docker build -t keywarden .
```

### Multi-Stage Build

The Dockerfile uses a two-stage build:

1. **Builder stage** (`golang:1.26-alpine`): Compiles the Go binary with CGO (required for SQLite)
2. **Runtime stage** (`alpine:3.21`): Minimal image with only the compiled binary and runtime dependencies (`ca-certificates`, `sqlite-libs`, `tzdata`, `curl`)

The runtime container runs as a non-root user (`keywarden`).

### Docker Compose

A complete `docker-compose.yml`:

```yaml
services:
  keywarden:
    image: git.techniverse.net/scriptos/keywarden:latest
    container_name: keywarden
    restart: unless-stopped
    ports:
      - "${KEYWARDEN_PORT:-8080}:${KEYWARDEN_PORT:-8080}"
    volumes:
      - ./data:/data
    env_file:
      - .env
    networks:
      keywarden_net:
        ipv4_address: 172.23.64.10
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${KEYWARDEN_PORT:-8080}/api/health"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3

networks:
  keywarden_net:
    name: keywarden.dockernetwork.local
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.64.0/24
          gateway: 172.23.64.1
          ip_range: 172.23.64.128/25
```

### Environment File (.env)

Create a `.env` file alongside `docker-compose.yml`:

```env
# Security (REQUIRED - change these!)
KEYWARDEN_SESSION_KEY=generate-a-random-string-of-at-least-32-chars
KEYWARDEN_ENCRYPTION_KEY=generate-another-random-string-32-chars

# Application
KEYWARDEN_PORT=8080
KEYWARDEN_LOG_LEVEL=INFO

# Initial owner (only used on first startup)
KEYWARDEN_OWNER_USER=admin
KEYWARDEN_OWNER_EMAIL=admin@example.com

# HTTPS / Reverse Proxy
KEYWARDEN_BASE_URL=https://keywarden.example.com
KEYWARDEN_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
KEYWARDEN_SECURE_COOKIES=true

# Rate Limiting
KEYWARDEN_RATE_LIMIT_LOGIN=10
KEYWARDEN_MAX_REQUEST_SIZE=10485760

# Email (optional)
KEYWARDEN_SMTP_HOST=smtp.example.com
KEYWARDEN_SMTP_PORT=587
KEYWARDEN_SMTP_USER=keywarden@example.com
KEYWARDEN_SMTP_PASSWORD=smtp-password
KEYWARDEN_SMTP_FROM=keywarden@example.com
KEYWARDEN_SMTP_TLS=true
```

See [Environment Variables](environment-variables.md) for a complete reference.

## Data Persistence

All persistent data is stored in the `/data` volume:

| Path | Content |
|---|---|
| `/data/keywarden.db` | SQLite database (users, keys, servers, settings, audit log) |
| `/data/keys/` | Reserved for future use |
| `/data/master/` | Reserved for future use |
| `/data/avatars/` | User profile pictures |

> **Important:** The SQLite database contains encrypted private keys. Back up the `/data` volume regularly. See [Backup & Restore](backup-restore.md).

## Reverse Proxy Setup

For production use, place Keywarden behind a reverse proxy with TLS termination.

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name keywarden.example.com;

    ssl_certificate     /etc/ssl/certs/keywarden.crt;
    ssl_certificate_key /etc/ssl/private/keywarden.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Recommended limits
        client_max_body_size 10m;
    }
}
```

### Caddy

```caddyfile
keywarden.example.com {
    reverse_proxy localhost:8080
}
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.keywarden.rule=Host(`keywarden.example.com`)"
  - "traefik.http.routers.keywarden.tls=true"
  - "traefik.http.services.keywarden.loadbalancer.server.port=8080"
```

### Important Notes for Reverse Proxy

1. **Set `KEYWARDEN_BASE_URL`**: Required for correct email links and cookie configuration
2. **Set `KEYWARDEN_TRUSTED_PROXIES`**: Configure the CIDR range of your reverse proxy so Keywarden can extract the real client IP from `X-Forwarded-For` headers
3. **Set `KEYWARDEN_SECURE_COOKIES=true`**: Enable secure cookie flag when using HTTPS (auto-derived from `KEYWARDEN_BASE_URL` if the URL starts with `https://`)

## Health Check

Keywarden provides a health check endpoint at `/api/health` that returns JSON:

```json
{
  "status": "healthy",
  "uptime": "2d 5h 30m",
  "uptime_seconds": 194400,
  "checks": {
    "database": {
      "status": "ok"
    }
  }
}
```

The Docker HEALTHCHECK is configured automatically in the Dockerfile.

## Updating

To update Keywarden:

```bash
# Pull latest image and restart
docker compose pull
docker compose down
docker compose up -d
```

Database migrations run automatically on startup. No manual migration steps are required.

## System Master Key

On first startup, Keywarden generates an **Ed25519 system master key**. This key is used for all SSH connections to managed servers (deploying keys, creating users, etc.).

The public key is displayed in:
- The startup log output
- The Admin Settings page (owner only)

You must deploy this public key to every server you want to manage:

```bash
# On each target server
echo "<master-public-key>" >> /root/.ssh/authorized_keys
```

The master key can be regenerated from the Admin Settings page if needed (owner only). After regeneration, redeploy the new public key to all servers.
