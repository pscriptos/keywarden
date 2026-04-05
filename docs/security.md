# Security

This document describes Keywarden's security features, architecture, and best practices.

## Authentication

### Password Authentication

- Passwords are hashed with **bcrypt** at the default cost factor (10)
- Password policy is configurable by the owner (see below)
- Accounts are locked after configurable failed login attempts

### Password Policy

The owner can configure password requirements in Admin Settings:

| Setting | Default | Description |
|---|---|---|
| Minimum length | 8 | Minimum number of characters |
| Require uppercase | Yes | At least one uppercase letter (A-Z) |
| Require lowercase | Yes | At least one lowercase letter (a-z) |
| Require digit | Yes | At least one number (0-9) |
| Require special character | No | At least one non-alphanumeric character |

The policy is enforced on:
- User registration (invitation acceptance)
- Password changes (manual and forced)
- Admin password resets

### Account Lockout

After a configurable number of failed login attempts (default: 5), an account is locked for a configurable duration (default: 15 minutes).

| Setting | Default |
|---|---|
| Lockout threshold | 5 attempts |
| Lockout duration | 15 minutes |

Setting lockout attempts to 0 disables the lockout feature.

Admins can manually unlock accounts from the user management page.

### Forced Password Change

Admins can flag any user to require a password change. The user will be redirected to the password change page on every request until they set a new password. This is automatically enabled for:
- Newly created accounts
- Accounts where an admin reset the password

## Two-Factor Authentication (MFA)

Keywarden supports TOTP (Time-based One-Time Password) for MFA, compatible with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any RFC 6238 compliant app

### Implementation Details

- **Algorithm**: HMAC-SHA1
- **Code length**: 6 digits
- **Period**: 30 seconds
- **Clock tolerance**: ±1 time step (allows 30 seconds of clock skew)
- **Secret generation**: 20 bytes of cryptographic random data
- **Secret encoding**: Base32 (unpadded)

### MFA Enforcement

The owner can enable system-wide MFA enforcement in Admin Settings. When enabled:
- Users without MFA are redirected to the MFA setup page on every request
- Users cannot disable MFA while enforcement is active
- The owner can always access Admin Settings (even without MFA) to prevent lockout

## Encryption

### Private Key Encryption (At Rest)

All SSH private keys stored in the database are encrypted with **AES-256-GCM**:

1. The `KEYWARDEN_ENCRYPTION_KEY` is hashed with SHA-256 → 32-byte AES key
2. A random 12-byte nonce is generated for each encryption operation
3. Plaintext is encrypted with AES-256-GCM (provides confidentiality + integrity)
4. Result: `nonce || ciphertext || GCM-tag` → base64-encoded → stored in DB

> **Critical:** If `KEYWARDEN_ENCRYPTION_KEY` is changed or lost, all stored private keys become permanently inaccessible.

### Backup Encryption

Database exports are encrypted with a user-provided password using the same AES-256-GCM scheme. The password is required for both export and import.

## CSRF Protection

Keywarden implements the **Double-Submit Cookie** pattern:

1. A `_csrf` cookie is set on every request (32 bytes, hex-encoded, 64 chars)
2. On state-changing methods (POST, PUT, DELETE, PATCH), the request must include a matching token as:
   - A form field named `_csrf`, or
   - An `X-CSRF-Token` request header
3. Tokens are compared using constant-time comparison to prevent timing attacks

The cookie is **not** HttpOnly (JavaScript must read it to inject into forms), but is:
- `SameSite=Strict`
- `Secure` when HTTPS is enabled
- Expires after 24 hours

## Security Headers

Every response includes:

| Header | Value | Purpose |
|---|---|---|
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls Referer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disables unused APIs |
| `Content-Security-Policy` | See below | Restricts resource loading |
| `X-Permitted-Cross-Domain-Policies` | `none` | Blocks cross-domain policy files |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` | Prevents caching of authenticated pages |

### Content Security Policy

```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self' data:;
connect-src 'self';
frame-ancestors 'none';
form-action 'self';
base-uri 'self'
```

## Rate Limiting

Login endpoints (`POST /login`, `POST /login/mfa`) are rate-limited per IP address.

- **Default limit**: 10 attempts per IP per minute
- **Algorithm**: Fixed-window counter
- **Response when exceeded**: HTTP 429 (Too Many Requests)
- **Configuration**: `KEYWARDEN_RATE_LIMIT_LOGIN` (0 = disabled)

A background goroutine cleans up expired rate limit entries every 5 minutes.

## Request Size Limiting

Request bodies are limited to prevent denial-of-service via large uploads.

- **Default limit**: 10 MB (`10485760` bytes)
- **Response when exceeded**: HTTP 413 (Request Entity Too Large)
- **Configuration**: `KEYWARDEN_MAX_REQUEST_SIZE` (0 = no limit)

## Trusted Proxy Configuration

When Keywarden runs behind a reverse proxy, the real client IP must be extracted from `X-Forwarded-For` or `X-Real-IP` headers. However, these headers can be spoofed by clients.

### Strict Mode (Recommended)

Set `KEYWARDEN_TRUSTED_PROXIES` to the CIDR range(s) of your reverse proxy:

```env
KEYWARDEN_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

In strict mode:
- Proxy headers are only trusted when the direct TCP peer is from a trusted network
- `X-Forwarded-For` is walked right-to-left, and the first non-trusted IP is used
- This prevents client-side IP spoofing

### Legacy Mode

If `KEYWARDEN_TRUSTED_PROXIES` is not set, Keywarden trusts all proxy headers unconditionally. A warning is logged at startup:

```
WARN: KEYWARDEN_TRUSTED_PROXIES not set – proxy headers (X-Forwarded-For) are trusted unconditionally
```

## Session Security

- Session tokens: 32 bytes, cryptographically random, hex-encoded
- Cookie name: `keywarden_session`
- Cookie flags:
  - `HttpOnly` — Not accessible via JavaScript
  - `SameSite=Lax` — Prevents CSRF from external sites
  - `Secure` — Only over HTTPS (when enabled)
  - `MaxAge=86400` — 24 hours
- Sessions stored in-memory (not persisted across restarts)
- Configurable inactivity timeout (default: 60 minutes)
- Background cleanup runs every minute

## SSH Connection Security

When deploying keys to servers, Keywarden:

- Uses the system master key (Ed25519) for SSH authentication
- Connects with a 10-second timeout
- **Does not verify host keys** (`InsecureIgnoreHostKey`) — this is a known limitation

> **Note:** Host key verification is not yet implemented. This means Keywarden is susceptible to man-in-the-middle attacks during SSH connections. Only use Keywarden in trusted network environments.

## Best Practices

1. **Change the default secrets**: Set unique values for `KEYWARDEN_SESSION_KEY` and `KEYWARDEN_ENCRYPTION_KEY`
2. **Use HTTPS**: Run behind a reverse proxy with TLS termination
3. **Configure trusted proxies**: Set `KEYWARDEN_TRUSTED_PROXIES` for accurate IP logging
4. **Enable secure cookies**: Set `KEYWARDEN_SECURE_COOKIES=true` (auto-derived from HTTPS base URL)
5. **Enable MFA enforcement**: Require all users to use two-factor authentication
6. **Use strong passwords**: Configure a strict password policy
7. **Regular backups**: Export encrypted backups regularly
8. **Network isolation**: Restrict access to Keywarden and managed servers to trusted networks
9. **Keep the encryption key safe**: Back up `KEYWARDEN_ENCRYPTION_KEY` securely — losing it means losing all private keys
10. **Monitor the audit log**: Review login activity and deployment actions regularly
