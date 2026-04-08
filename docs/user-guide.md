# User Guide

This guide covers everyday usage of Keywarden for all authenticated users. For administrative tasks (server management, access assignments, etc.), see the [Admin Guide](admin-guide.md).

## Logging In

Navigate to your Keywarden instance in a web browser and enter your username and password.

- If **MFA is enabled** on your account, you will be prompted for a TOTP code after entering your password.
- If your account is **locked** due to too many failed login attempts, wait for the lockout period to expire or ask an administrator to unlock it.
- If you were **invited via email**, use the invitation link to set your password before logging in.

## Dashboard

The dashboard provides an overview of your environment:

- **Key Count** — Number of SSH keys you own
- **Server Count** — Servers you have access to (admins/owners see all servers)
- **Group Count** — Server groups (admins/owners see all groups)
- **Assignment Count** — Access assignments related to you
- **Recent Keys** — Latest SSH keys
- **Recent Audit Log** — Your recent activity (admins see global activity)
- **Recent Deployments** — Latest key deployment results

## SSH Key Management

### Generating Keys

1. Navigate to **Keys** → **Generate Key**
2. Fill in the form:
   - **Name**: A descriptive name for the key (e.g., "Production Deploy Key")
   - **Key Type**: Choose between:
     - **Ed25519** (recommended) — Fast, secure, compact. 256-bit.
     - **RSA 2048** — Widely compatible
     - **RSA 4096** — Maximum RSA security
     - **Ed448** — 224-bit security level (experimental)
   - **Comment**: Optional comment embedded in the public key
3. Click **Generate**

The private key is encrypted with AES-256-GCM and stored in the database. It never touches the filesystem in plaintext.

### Importing Keys

1. Navigate to **Keys** → **Import Key**
2. Enter a **name** for the key
3. Paste the **private key** (PEM format) into the text area
4. Click **Import**

Keywarden automatically detects the key type (RSA, Ed25519, Ed448) and extracts the public key and fingerprint.

### Viewing Keys

The **Keys** page lists all your SSH keys with:
- Name, type, key size
- SHA-256 fingerprint
- Creation date

Admins and owners see all keys in the system, grouped by owner.

### Viewing and Downloading Keys

From the key list, you can:
- **View Public Key** — Opens a modal overlay showing the public key with a copy-to-clipboard button
- **Download Private Key** — Decrypted and downloaded (use with caution)

### Deleting Keys

Click the delete button next to a key. This permanently removes both the public and encrypted private key from the database.

> **Note:** Deleting a key from Keywarden does **not** remove it from servers where it was previously deployed.

## My Access

Navigate to **My Access** to see all access assignments that grant you access to servers:

- **Target** — Server or server group
- **System User** — The Linux user account on the target server
- **SSH Key** — Which of your keys is deployed
- **Sudo** — Whether sudo privileges are granted
- **Status** — Current sync status (pending, synced, failed)
- **Initial Password** — If a system user was created for you, the initial password is shown here

This is a read-only view. Only administrators can create, modify, or delete access assignments.

## User Settings

Navigate to **Settings** to manage your account:

### Theme

KeyWarden offers five color themes, each available in three modes:

| Theme | Description |
|-------|-------------|
| **Ocean** (default) | Cyan/teal accent |
| **Forest** | Green accent |
| **Sunset** | Amber/orange accent |
| **Rose** | Pink accent |
| **Nord** | Cool blue-gray accent |

Each theme supports:
- **System** — Follows your system/browser preference (light or dark)
- **Light** — Always light mode
- **Dark** — Always dark mode

> Existing installations using the previous theme values (`auto`, `light`, `dark`) are automatically migrated to the Ocean theme.

### Password Change

Change your password. The new password must comply with the configured password policy (displayed on the form).

### Two-Factor Authentication (MFA)

#### Enabling MFA

1. Go to **Settings** → **Two-Factor Authentication**
2. Click **Enable MFA**
3. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)
4. Enter the 6-digit code from your app to confirm
5. MFA is now active for your account

#### Disabling MFA

Click **Disable MFA** in settings. This is only available if the administrator has not enforced MFA system-wide.

> If MFA is enforced by the administrator, you **must** set it up before you can access any other page.

### Email Notifications

If email is configured, you can enable **Login Notifications**. Every time someone logs into your account, you'll receive an email with:
- IP address
- Timestamp
- User agent (browser)

### Profile Picture

Upload a profile picture (avatar) that is displayed next to your name in the navigation. Supported formats: JPEG, PNG, GIF, WebP. Maximum file size: 5 MB.

## Audit Log

Navigate to **Audit** to view the activity log:

- **Regular users** see their own activity
- **Admins** see activity from all non-owner users
- **Owners** see all activity

The audit log records every significant action including logins, key operations, deployments, settings changes, and administrative actions.

## Forced Password Change

If an administrator flags your account for a mandatory password change, you will be redirected to the password change page on every request until you set a new password. This typically happens:
- After your initial account creation
- If an admin resets your password
- If there's a security concern

## Invitation Flow

If you receive an invitation email:

1. Click the invitation link
2. You'll see a registration page with your pre-assigned username
3. Choose a password that meets the password policy
4. Confirm the password
5. Click **Set Password**
6. You can now log in with your username and new password
