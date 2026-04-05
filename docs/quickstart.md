# Quick Start Guide

Get Keywarden running in under 5 minutes using Docker Compose.

## Prerequisites

- Docker and Docker Compose installed
- A Linux host (or any system that runs Docker)

## 1. Create Project Directory

```bash
mkdir keywarden && cd keywarden
```

## 2. Create Environment File

Create a `.env` file with at minimum these settings:

```env
# REQUIRED: Change these for security!
KEYWARDEN_SESSION_KEY=your-random-session-key-at-least-32-characters
KEYWARDEN_ENCRYPTION_KEY=your-random-encryption-key-at-least-32-chars

# Optional: Admin credentials (defaults: admin / auto-generated password)
KEYWARDEN_ADMIN_USER=admin
KEYWARDEN_ADMIN_EMAIL=admin@example.com

# Optional: Port (default: 8080)
KEYWARDEN_PORT=8080
```

> **Important:** The `KEYWARDEN_ENCRYPTION_KEY` is used to encrypt all private keys at rest. If you lose this key, stored private keys cannot be decrypted. Keep it safe!

## 3. Create docker-compose.yml

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

## 4. Start Keywarden

```bash
docker compose up -d
```

## 5. Get the Initial Password

On first startup, Keywarden creates an owner account and generates a secure random password. Check the logs:

```bash
docker compose logs keywarden
```

Look for output like:

```
════════════════════════════════════════════════════════════
  Initial owner account created
  Username: admin
  Password: AbCdEf1234567890XyZw
  Please change this password after first login!
════════════════════════════════════════════════════════════
```

## 6. Log In

Open your browser and navigate to `http://your-host:8080`, then log in with the credentials from the logs.

You will be prompted to change the initial password on first login.

## 7. Deploy the Master Key

After login, Keywarden displays the **system master key** (an Ed25519 public key). This key must be placed in the `~/.ssh/authorized_keys` file of the admin/root user on every server you want to manage.

The master key is shown on the **Admin Settings** page and in the startup logs.

```bash
# On each target server, as root:
echo "ssh-ed25519 AAAA... keywarden-system-master" >> ~/.ssh/authorized_keys
```

## What's Next?

- [Full Deployment Guide](deployment.md) — Production setup with HTTPS and reverse proxy
- [User Guide](user-guide.md) — How to manage SSH keys
- [Admin Guide](admin-guide.md) — How to manage servers and access assignments
- [Environment Variables](environment-variables.md) — All configuration options
