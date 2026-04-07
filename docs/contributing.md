# Contributing

Guide for developers who want to contribute to Keywarden or build from source.

## Prerequisites

- **Go 1.26+** with CGO enabled (required for SQLite)
- **GCC / C compiler** (required by `go-sqlite3`)
- **Git** for version control

### Platform-Specific Requirements

**Linux (Debian/Ubuntu):**
```bash
sudo apt install gcc sqlite3 libsqlite3-dev
```

**Alpine Linux:**
```bash
apk add gcc musl-dev sqlite-dev
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**

Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MinGW-w64, then set `CGO_ENABLED=1`.

## Building from Source

```bash
# Clone the repository
git clone https://git.techniverse.net/scriptos/keywarden.git
cd keywarden

# Download dependencies
go mod download

# Build
CGO_ENABLED=1 go build -o keywarden ./cmd/keywarden/

# Build with version (optional, enables update checker)
CGO_ENABLED=1 go build -ldflags="-X 'main.Version=v1.0.0'" -o keywarden ./cmd/keywarden/

# Run
./keywarden
```

### Docker Build

```bash
docker compose build
docker compose up -d
```

## Project Structure

```
keywarden/
├── cmd/keywarden/main.go       # Application entry point
├── internal/
│   ├── audit/audit.go          # Audit logging service (action constants, logging, queries)
│   ├── auth/auth.go            # Authentication service (login, register, MFA, password policy,
│   │                           #   account lockout, invitations, settings)
│   ├── config/config.go        # Environment-based configuration loader
│   ├── cron/cron.go            # Cron scheduler (temporary access jobs, scheduling logic)
│   ├── database/
│   │   ├── database.go         # SQLite connection, migrations, schema
│   │   └── backup.go           # Encrypted backup export/import
│   ├── deploy/deploy.go        # SSH key deployment (deploy, remove, user management,
│   │                           #   sudo, disable, delete system users)
│   ├── encryption/encryption.go # AES-256-GCM encryption/decryption
│   ├── handlers/handlers.go    # All HTTP handlers, routing, middleware, templates
│   ├── keys/keys.go            # SSH key management, system master key
│   ├── logging/logging.go      # Structured logging with levels, request logger
│   ├── mail/mail.go            # SMTP email service (notifications, invitations, templates)
│   ├── models/models.go        # Data models (User, SSHKey, Server, CronJob, etc.)
│   ├── security/
│   │   ├── csrf.go             # CSRF double-submit cookie middleware
│   │   ├── headers.go          # Security headers middleware (CSP, X-Frame-Options, etc.)
│   │   ├── proxy.go            # Trusted proxy IP extraction
│   │   ├── ratelimit.go        # IP-based rate limiting middleware
│   │   └── sizelimit.go        # Request body size limit middleware
│   ├── servers/servers.go      # Server and group management, access assignments
│   ├── sshutil/keygen.go       # SSH key generation (RSA, Ed25519, Ed448)
│   └── updater/updater.go      # Background update checker (Gitea releases API)
├── web/
│   ├── embed.go                # Go embed directives
│   ├── static/                 # CSS, JS, fonts (Tabler UI)
│   └── templates/              # HTML templates
├── docs/                       # Documentation
├── Dockerfile                  # Multi-stage Docker build
├── docker-compose.yml          # Docker Compose configuration
├── go.mod                      # Go module definition
└── LICENSE                     # AGPL-3.0-or-later
```

## Architecture Principles

- **Single binary**: All assets (templates, CSS, JS) are embedded via Go's `embed` package
- **No external database**: SQLite with WAL mode, embedded in the binary
- **Standard library HTTP**: No web framework — uses `net/http` directly
- **Service pattern**: Each domain has its own service struct with a database dependency
- **Handler pattern**: One large handler file with all routes and template rendering
- **Middleware chain**: Security features implemented as composable HTTP middleware

## Key Design Decisions

### Roles

Three roles: `owner`, `admin`, `user`. The owner is created on first startup. Admins are created by the owner. Users can be created by admins, owner or via invitations.

### Master Key

A single system-wide Ed25519 SSH key pair is used for all server connections. This simplifies deployment: only one public key needs to be added to target servers.

### Access Assignments

Instead of ad-hoc key deployment, access assignments provide a declarative model. The desired state is stored in the database and synced to servers on demand.

### Cron Jobs

Temporary access is implemented as cron jobs that deploy keys on a schedule and remove them after a timeout using background timers.

## Running Tests

```bash
go test ./...
```

Test files are co-located with their packages (e.g., `auth_test.go`, `config_test.go`, `encryption_test.go`).

## Dependencies

| Module | Purpose |
|---|---|
| `github.com/mattn/go-sqlite3` | SQLite3 driver (CGO) |
| `golang.org/x/crypto` | bcrypt, SSH key operations |
| `github.com/cloudflare/circl` | Ed448 key support |

## Code Style

- Use `gofmt` for formatting
- Follow standard Go conventions
- Error messages should be lowercase
- Log messages use the structured logging package (`logging.Info`, `logging.Debug`, etc.)

## Community & Communication

For questions, discussions, and coordination with other contributors, join the Matrix chat:

➡️ [#keywarden:techniverse.net](https://matrix.to/#/#keywarden:techniverse.net)

---

## License

All contributions must be compatible with the [AGPL-3.0-or-later](../LICENSE) license.

Copyright (C) 2026 Patrick Asmus (scriptos)
