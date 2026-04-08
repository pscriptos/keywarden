# Architecture Overview

This document describes the system architecture and design of Keywarden.

## Technology Stack

| Component | Technology |
|---|---|
| Language | Go 1.26 |
| Database | SQLite 3 (WAL mode, embedded) |
| Web Framework | Go standard library (`net/http`) |
| Template Engine | Go `html/template` |
| UI Framework | [Tabler](https://tabler.io) (Bootstrap-based) |
| SSH Library | `golang.org/x/crypto/ssh` |
| Encryption | AES-256-GCM (Go `crypto/aes`, `crypto/cipher`) |
| Password Hashing | bcrypt (`golang.org/x/crypto/bcrypt`) |
| Ed448 Support | `github.com/cloudflare/circl` |
| Containerization | Docker (Alpine Linux) |

## Application Structure

Keywarden is a single Go binary with embedded static assets and templates. It serves a web UI and handles all SSH operations internally.

```
cmd/keywarden/main.go    ← Application entry point
internal/
  audit/                  ← Audit logging service
  auth/                   ← Authentication, users, MFA, password policy, invitations
  config/                 ← Environment-based configuration
  cron/                   ← Scheduled temporary access jobs
  database/               ← SQLite connection, migrations, backup/restore
  deploy/                 ← SSH key deployment to remote servers
  encryption/             ← AES-256-GCM encryption service
  handlers/               ← HTTP handlers and routing (all UI logic)
  keys/                   ← SSH key management, system master key
  logging/                ← Structured logging with levels
  mail/                   ← SMTP email service (notifications, invitations)
  models/                 ← Data models (User, SSHKey, Server, etc.)
  security/               ← CSRF, security headers, rate limiting, proxy detection
  servers/                ← Server and server group management, access assignments
  sshutil/                ← SSH key generation (RSA, Ed25519, Ed448)
  updater/                ← Background update checker (Gitea releases API)
  worker/                 ← Background key enforcement worker (Bastillion-style)
web/
  embed.go                ← Go embed directives for templates and static files
  static/                 ← CSS, JS, fonts (Tabler UI framework)
  templates/              ← HTML templates (Go template syntax)
```

## Startup Sequence

1. **Load configuration** from environment variables
2. **Initialize logging** with the configured log level
3. **Create data directories** (`/data`, `/data/keys`, `/data/master`)
4. **Initialize SQLite database** with WAL mode and run all migrations
5. **Initialize services**: encryption, auth, keys, servers, deploy, audit, cron, mail
6. **Create initial owner account** (if no users exist) with auto-generated password
7. **Ensure system master key** exists (generates on first run)
8. **Configure security** subsystem (trusted proxy parsing)
9. **Set up HTTP routes** and load templates
10. **Start session cleanup** goroutine (removes expired sessions every minute)
11. **Apply middleware chain**: request logger → security headers → rate limiting → size limiting → CSRF
12. **Start cron scheduler** (checks for pending jobs every 30 seconds)
13. **Start key enforcement worker** (if enabled in Admin Settings)
14. **Start HTTP server**

## Database Design

Keywarden uses SQLite with the following tables:

| Table | Purpose |
|---|---|
| `users` | User accounts (username, email, password hash, role, MFA, themes) |
| `ssh_keys` | SSH key pairs (public key, encrypted private key, fingerprint) |
| `servers` | Managed remote servers (hostname, port, SSH username) |
| `server_groups` | Named groups of servers |
| `server_group_members` | Many-to-many relation: servers ↔ groups |
| `access_assignments` | Maps users + keys → hosts/groups with system user config |
| `cron_jobs` | Scheduled temporary access jobs |
| `key_deployments` | Deployment history log |
| `audit_log` | Full audit trail of all actions |
| `settings` | Key-value application settings |
| `invitation_tokens` | One-time invitation links for new users |
| `_migrations` | Tracks applied database migrations |

Database migrations are idempotent and run automatically on every startup. New columns are added via `ALTER TABLE` with migration tracking to prevent duplicate additions.

## Request Flow

```
Client → [Nginx/Caddy] → Keywarden HTTP Server
                              │
                              ├── Request Logger Middleware
                              ├── Security Headers Middleware
                              ├── Rate Limit Middleware (login endpoints)
                              ├── Size Limit Middleware
                              ├── CSRF Middleware (double-submit cookie)
                              │
                              ├── Public Routes (/login, /invite/*)
                              ├── Auth Routes (requireAuth → all authenticated users)
                              ├── Admin Routes (requireAdmin → admin + owner)
                              └── Owner Routes (requireOwner → owner only)
```

## Session Management

Sessions are stored in-memory (not in the database) as a map of session tokens to session data. Each session tracks:

- User ID
- Last activity timestamp (for sliding timeout)
- MFA setup requirement flag

Session tokens are cryptographically random 32-byte hex strings stored in an HTTP-only cookie (`keywarden_session`). Sessions expire after the configured timeout (default: 60 minutes of inactivity). A background goroutine cleans up expired sessions every minute.

## Encryption Architecture

### Private Key Storage

All SSH private keys are encrypted at rest using AES-256-GCM:

1. The `KEYWARDEN_ENCRYPTION_KEY` environment variable is hashed with SHA-256 to derive a 32-byte AES key
2. Each private key is encrypted with a random 12-byte nonce
3. The encrypted blob (nonce + ciphertext + GCM tag) is base64-encoded and stored in the database

### Backup Encryption

Database backups are encrypted with a user-provided password using the same AES-256-GCM scheme. The password is hashed with SHA-256 to derive the encryption key.

### Password Storage

User passwords are hashed with bcrypt at the default cost factor.

## System Master Key

The system master key is an Ed25519 SSH key pair generated on first startup. It is used for all SSH connections to managed servers. The private key is stored encrypted in the `settings` table.

The master key enables Keywarden to:
- Deploy SSH keys to server `authorized_keys`
- Create and manage system users on remote servers
- Add/remove sudo privileges
- Disable or delete system users during access expiry

## Cron Scheduler

The cron service runs a tick every 30 seconds, checking for jobs where `next_run <= now` and `status == 'active'`. For each due job, it:

1. Marks the job as `running`
2. Resolves the SSH key and target servers
3. Deploys the key to the specified system user
4. If `remove_after_min > 0`, starts a background timer that triggers the expiry action
5. Updates the job status and calculates the next run time

Supported schedules: `once`, `hourly`, `daily`, `weekly`, `monthly`.

Expiry actions: `remove_key` (default), `disable_user`, `delete_user`.
