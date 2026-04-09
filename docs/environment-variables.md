# Environment Variables

Complete reference of all configuration options for Keywarden. All settings are read from environment variables at startup.

## Core Settings

| Variable | Default | Description |
|---|---|---|
| `KEYWARDEN_PORT` | `8080` | HTTP server listen port |
| `KEYWARDEN_DB_PATH` | `./data/keywarden.db` | Path to the SQLite database file |
| `KEYWARDEN_DATA_DIR` | `./data` | Base directory for persistent data |
| `KEYWARDEN_KEYS_DIR` | `./data/keys` | Directory for key storage (reserved) |
| `KEYWARDEN_MASTER_DIR` | `./data/master` | Directory for master key storage (reserved) |
| `KEYWARDEN_LOG_LEVEL` | `INFO` | Log level: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE` |
| `TZ` | `UTC` | Timezone for all displayed timestamps (e.g., `Europe/Berlin`, `America/New_York`). Uses standard IANA timezone names. |

## Security

| Variable | Default | Description |
|---|---|---|
| `KEYWARDEN_SESSION_KEY` | `change-me-in-production-please` | Secret key for session cookie signing. **Change this!** |
| `KEYWARDEN_ENCRYPTION_KEY` | `change-me-encryption-key-32chars` | Encryption key for SSH private keys (AES-256). **Change this!** |
| `KEYWARDEN_BASE_URL` | _(empty)_ | External base URL (e.g., `https://keywarden.example.com`). Used for email links and cookie configuration. Auto-derives `KEYWARDEN_SECURE_COOKIES` from scheme. |
| `KEYWARDEN_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDR ranges or IPs of trusted reverse proxies (e.g., `10.0.0.0/8,172.16.0.0/12`). When set, `X-Forwarded-For` is only honored from these networks. |
| `KEYWARDEN_SECURE_COOKIES` | _(auto)_ | Set `true` to enable `Secure` flag on cookies. Auto-derived from `KEYWARDEN_BASE_URL` if it starts with `https://`. |
| `KEYWARDEN_RATE_LIMIT_LOGIN` | `10` | Maximum login POST attempts per IP per minute. Set to `0` to disable. |
| `KEYWARDEN_MAX_REQUEST_SIZE` | `10485760` | Maximum request body size in bytes (default: 10 MB). Set to `0` for no limit. |

## Initial Owner Account

These variables are only used on first startup when no users exist in the database:

| Variable | Default | Description |
|---|---|---|
| `KEYWARDEN_OWNER_USER` | `admin` | Username for the initial owner account |
| `KEYWARDEN_OWNER_EMAIL` | `admin@keywarden.local` | Email for the initial owner account |

> **Note:** The previous variable names `KEYWARDEN_ADMIN_USER` and `KEYWARDEN_ADMIN_EMAIL` are still accepted for backward compatibility but are deprecated. Please update your `.env` file to use the new names.

The initial password is auto-generated (20 characters, alphanumeric) and printed to the startup log. It must be changed on first login.

## Email / SMTP

| Variable | Default | Description |
|---|---|---|
| `KEYWARDEN_SMTP_HOST` | _(empty)_ | SMTP server hostname. Email is disabled if not set. |
| `KEYWARDEN_SMTP_PORT` | `587` | SMTP server port. Use `587` for STARTTLS or `465` for implicit TLS. |
| `KEYWARDEN_SMTP_USER` | _(empty)_ | SMTP authentication username |
| `KEYWARDEN_SMTP_PASSWORD` | _(empty)_ | SMTP authentication password |
| `KEYWARDEN_SMTP_FROM` | `keywarden@localhost` | Sender email address (`From` header) |
| `KEYWARDEN_SMTP_TLS` | `true` | Enable TLS for SMTP connections. Set `false` for unencrypted SMTP (not recommended). |

## Docker-Specific Defaults

When running in the Docker container, these defaults are set in the Dockerfile:

| Variable | Docker Default |
|---|---|
| `KEYWARDEN_PORT` | `8080` |
| `KEYWARDEN_DB_PATH` | `/data/keywarden.db` |
| `KEYWARDEN_DATA_DIR` | `/data` |
| `KEYWARDEN_KEYS_DIR` | `/data/keys` |
| `KEYWARDEN_MASTER_DIR` | `/data/master` |
| `TZ` | `UTC` |

## Example .env File

```env
# ──────────────────────────────────────────────
# Keywarden Configuration
# ──────────────────────────────────────────────

# Security (REQUIRED - change these!)
KEYWARDEN_SESSION_KEY=Rj9kL2mN4pQ8sT1vW3xY5zA7bC0dF6gH
KEYWARDEN_ENCRYPTION_KEY=mX9nP2qR4sT6uV8wY0zA1bC3dE5fG7hI

# Application
KEYWARDEN_PORT=8080
KEYWARDEN_LOG_LEVEL=INFO

# Timezone (IANA timezone name, e.g. Europe/Berlin)
TZ=Europe/Berlin

# Initial owner (only used on first startup)
KEYWARDEN_OWNER_USER=admin
KEYWARDEN_OWNER_EMAIL=admin@example.com

# Reverse proxy / HTTPS
KEYWARDEN_BASE_URL=https://keywarden.example.com
KEYWARDEN_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Rate limiting
KEYWARDEN_RATE_LIMIT_LOGIN=10
KEYWARDEN_MAX_REQUEST_SIZE=10485760

# Email (optional)
KEYWARDEN_SMTP_HOST=smtp.example.com
KEYWARDEN_SMTP_PORT=587
KEYWARDEN_SMTP_USER=keywarden@example.com
KEYWARDEN_SMTP_PASSWORD=your-smtp-password
KEYWARDEN_SMTP_FROM=keywarden@example.com
KEYWARDEN_SMTP_TLS=true
```

## Application Settings (Database)

In addition to environment variables, the following settings are configured through the web UI (Admin Settings page, owner only) and stored in the database:

| Setting Key | Default | Description |
|---|---|---|
| `app_name` | `Keywarden` | Application display name in the UI |
| `default_key_type` | `ed25519` | Default key type for generation |
| `default_key_bits` | `256` | Default key size |
| `session_timeout` | `60` | Session inactivity timeout in minutes |
| `pw_min_length` | `8` | Password minimum length |
| `pw_require_upper` | `true` | Require uppercase letter |
| `pw_require_lower` | `true` | Require lowercase letter |
| `pw_require_digit` | `true` | Require digit |
| `pw_require_special` | `false` | Require special character |
| `lockout_attempts` | `5` | Failed login attempts before lockout (0 = disabled) |
| `lockout_duration` | `15` | Lockout duration in minutes |
| `mfa_required` | `false` | Enforce MFA for all users |
| `login_text_color` | `light` | Login text color over background image: `light` or `dark` (auto-detected on upload) |
