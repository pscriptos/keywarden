# Email Configuration

Keywarden supports SMTP-based email for login notifications and user invitations. Email is optional — all core functionality works without it.

## Enabling Email

Set the `KEYWARDEN_SMTP_HOST` environment variable to enable email:

```env
KEYWARDEN_SMTP_HOST=smtp.example.com
KEYWARDEN_SMTP_PORT=587
KEYWARDEN_SMTP_USER=keywarden@example.com
KEYWARDEN_SMTP_PASSWORD=your-password
KEYWARDEN_SMTP_FROM=keywarden@example.com
KEYWARDEN_SMTP_TLS=true
```

If `KEYWARDEN_SMTP_HOST` is empty, email is completely disabled and all email-related features are hidden from the UI.

## TLS Configuration

| Port | Mode | Setting |
|---|---|---|
| `587` | STARTTLS | `KEYWARDEN_SMTP_TLS=true` (default) |
| `465` | Implicit TLS | `KEYWARDEN_SMTP_TLS=true` + `KEYWARDEN_SMTP_PORT=465` |
| `25` | Unencrypted | `KEYWARDEN_SMTP_TLS=false` (not recommended) |

- Port **587** uses STARTTLS (upgrade from plaintext to TLS after connection)
- Port **465** uses implicit TLS (TLS from the start)
- Minimum TLS version: TLS 1.2

## Email Features

### Login Notifications

Users can individually enable login notification emails in their account settings. When enabled, each successful login triggers an email containing:

- Username
- Client IP address
- Timestamp
- User agent (browser information)

Emails are sent asynchronously in a background goroutine to avoid slowing down the login flow.

### User Invitations

When an admin creates a new user, they can choose to send an **invitation email** instead of setting a password manually. The invitation email contains:

- The username
- A secure one-time link (`/invite/{token}`)
- Expiration time (48 hours)

The invitation token is a 32-byte cryptographic random value, base32-encoded. Once used, the token is marked as consumed and cannot be reused.

### Test Email

The owner can send a test email from the Admin Settings page to verify that SMTP configuration is working correctly.

## Email Templates

All emails are sent as **multipart/alternative** (both plain text and HTML). The HTML versions use responsive, inline-styled templates.

### Login Notification Email

- **Subject**: `Keywarden: Login notification for {username}`
- **Content**: IP address, timestamp, user agent
- **Trigger**: Successful login when the user has notifications enabled

### Invitation Email

- **Subject**: `Keywarden: You have been invited – {username}`
- **Content**: Username, registration link, expiration time
- **Trigger**: Admin creates a user with "Send Invitation" enabled

### Test Email

- **Subject**: `Keywarden: SMTP Test Email`
- **Content**: Confirmation that SMTP is working

## Base URL Requirement

For invitation emails to contain the correct link, set the `KEYWARDEN_BASE_URL` environment variable:

```env
KEYWARDEN_BASE_URL=https://keywarden.example.com
```

If not set, invitation links use relative paths which may not work in email clients.

## Troubleshooting

### Email Not Sent

1. Check that `KEYWARDEN_SMTP_HOST` is set
2. Verify SMTP credentials
3. Check the application logs for SMTP errors (`KEYWARDEN_LOG_LEVEL=DEBUG` for details)
4. Try sending a test email from Admin Settings
5. Verify network connectivity from the container to the SMTP server

### TLS Errors

- Ensure the SMTP server supports TLS 1.2+
- For self-signed certificates, the default TLS configuration may reject them
- Try different port/TLS combinations

### Authentication Failures

- Verify username and password
- Some providers require app-specific passwords (e.g., Gmail, Microsoft 365)
- Check if the SMTP server requires a specific authentication mechanism
