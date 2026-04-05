# API Reference

Keywarden is primarily a web application with server-rendered HTML pages. It provides a limited JSON API for health monitoring and internal use.

## Public Endpoints

### Health Check

```
GET /api/health
```

Returns the application health status. No authentication required. Used by Docker HEALTHCHECK and external monitoring tools.

**Response (healthy):**

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

**Response (unhealthy):**

```json
{
  "status": "unhealthy",
  "uptime": "0m",
  "uptime_seconds": 30,
  "checks": {
    "database": {
      "status": "fail"
    }
  }
}
```

| Status Code | Meaning |
|---|---|
| `200 OK` | Application is healthy |
| `503 Service Unavailable` | Database unreachable or other critical failure |

## Internal API Endpoints

These endpoints require authentication and are used by the web UI.

### Cron Keys API

```
GET /api/cron/keys?user_id={id}
```

Returns SSH keys for a specific user as JSON. Used by the cron job creation form to dynamically load keys when the target user is selected.

**Access**: Admin and Owner only.

**Response:**

```json
[
  {
    "id": 1,
    "name": "My Ed25519 Key",
    "key_type": "ed25519",
    "fingerprint": "SHA256:abc..."
  }
]
```

## HTTP Routes Overview

### Public Routes (No Authentication)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/login` | Login page and authentication |
| POST | `/login/mfa` | MFA code verification |
| GET | `/logout` | Session termination |
| GET/POST | `/invite/{token}` | Invitation acceptance |

### Authenticated Routes (All Users)

| Method | Path | Description |
|---|---|---|
| GET | `/` | Redirect to dashboard |
| GET | `/dashboard` | Main dashboard |
| GET/POST | `/password/change` | Forced password change |
| GET | `/keys` | SSH key list |
| GET/POST | `/keys/generate` | Generate new SSH key |
| GET/POST | `/keys/import` | Import existing SSH key |
| GET/POST | `/keys/{id}/{action}` | Key actions (download, delete) |
| GET/POST | `/settings` | User account settings |
| POST | `/settings/theme` | Change theme preference |
| GET/POST | `/settings/mfa/setup` | Enable MFA |
| POST | `/settings/mfa/disable` | Disable MFA |
| POST | `/settings/email/notify` | Toggle email notifications |
| POST | `/settings/avatar` | Upload profile picture |
| GET | `/avatar/{id}` | Serve user avatar |
| GET | `/audit` | Audit log viewer |
| GET | `/my/access` | View own access assignments |
| GET/POST | `/mfa/setup` | MFA enforcement setup page |

### Admin Routes (Admin + Owner)

| Method | Path | Description |
|---|---|---|
| GET | `/servers` | Server list |
| GET/POST | `/servers/add` | Add server |
| POST | `/servers/test` | Test server connection |
| POST | `/servers/test-auth` | Test SSH authentication |
| GET/POST | `/servers/{id}/{action}` | Edit/delete server |
| GET | `/groups` | Server group list |
| GET/POST | `/groups/add` | Add server group |
| GET/POST | `/groups/{id}/{action}` | Edit/delete group, manage members |
| GET/POST | `/deploy` | Manual key deployment |
| POST | `/deploy/group` | Group deployment |
| GET | `/cron` | Cron job list |
| GET/POST | `/cron/add` | Add cron job |
| GET/POST | `/cron/{id}/{action}` | Edit/delete/pause cron job |
| GET | `/users` | User list |
| GET/POST | `/users/add` | Add user |
| GET/POST | `/users/{id}/{action}` | Edit/delete/unlock user |
| GET | `/assignments` | Access assignment list |
| GET/POST | `/assignments/add` | Add assignment |
| GET/POST | `/assignments/{id}/{action}` | Edit/delete/sync assignment |
| GET | `/system` | System information |
| GET | `/api/cron/keys` | Get keys by user (JSON) |

### Owner Routes

| Method | Path | Description |
|---|---|---|
| GET/POST | `/admin/settings` | Application and security settings |
| POST | `/admin/settings/email/test` | Send test email |
| POST | `/admin/masterkey/regenerate` | Regenerate system master key |
| POST | `/admin/backup/export` | Export encrypted database backup |
| POST | `/admin/backup/import` | Import encrypted database backup |

## Static Assets

| Path | Description |
|---|---|
| `/static/css/` | Tabler CSS framework |
| `/static/js/` | Tabler JavaScript |
| `/static/css/fonts/` | Tabler icons font |

Static assets are embedded in the binary and served with long cache headers.
