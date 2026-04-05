# Keywarden Documentation

Welcome to the official documentation for **Keywarden** — a self-hosted, centralized SSH key management and deployment platform.

## Table of Contents

1. [Quick Start Guide](quickstart.md) — Get Keywarden running in minutes
2. [Installation & Deployment](deployment.md) — Docker setup, reverse proxy, production deployment
3. [Architecture Overview](architecture.md) — System design, components, technology stack
4. [User Guide](user-guide.md) — Day-to-day usage for all users
5. [Administration Guide](admin-guide.md) — Server management, deployments, access assignments, cron jobs
6. [Roles & Permissions](roles.md) — Owner, Admin, and User role details
7. [Security](security.md) — Authentication, MFA, encryption, CSRF, hardening
8. [Environment Variables](environment-variables.md) — Complete configuration reference
9. [Email Configuration](email.md) — SMTP setup, login notifications, invitations
10. [API Reference](api-reference.md) — Health check endpoint and internal APIs
11. [Backup & Restore](backup-restore.md) — Encrypted database backup and restore
12. [Troubleshooting](troubleshooting.md) — Common issues and solutions
13. [Contributing](contributing.md) — Development setup, project structure, guidelines

---

## What is Keywarden?

Keywarden provides a clean web UI to generate, import, and securely store SSH keys (RSA, Ed25519, and Ed448) in one central place. Managed keys can then be deployed to registered Linux servers — individually or via server groups — with a single click. A complete audit log tracks every action in the system.

### Key Features

- **SSH Key Management** — Generate (RSA 2048/4096, Ed25519, Ed448) or import existing key pairs
- **Encrypted Storage** — All private keys stored with AES-256-GCM encryption at rest
- **System Master Key** — Auto-generated Ed25519 key used for all server authentication
- **Host & Group Management** — Register servers, organize them into groups, deploy keys to one or many
- **Access Assignments** — Map users + keys to target hosts/groups with specific system users, sudo rights, and user creation
- **Temporary Access (Cron Jobs)** — Schedule time-limited access with automatic key removal, user disabling, or user deletion on expiry
- **Three-Tier Role System** — Owner, Admin, and User roles with clear permission boundaries
- **User Invitations** — Invite new users via secure email links with self-service password setup
- **TOTP Two-Factor Authentication** — Optional or enforced MFA for all users
- **Password Policies** — Configurable complexity requirements with account lockout
- **Email Notifications** — Login alerts and invitation emails via SMTP
- **Comprehensive Audit Log** — Every action logged with user, timestamp, IP address, and details
- **Encrypted Backup/Restore** — Full database export with AES-256 password encryption
- **Docker-Native** — Single-container deployment with SQLite, no external database needed
- **Security Hardened** — CSRF protection, CSP headers, rate limiting, request size limits

---

## Community

Have questions, ideas, or feedback? Join the Keywarden Matrix chat room:

➡️ [#keywarden:techniverse.net](https://matrix.to/#/#keywarden:techniverse.net)

---

## License

Keywarden is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0-or-later)](../LICENSE).

© 2026 Patrick Asmus ([scriptos](https://git.techniverse.net/scriptos))
