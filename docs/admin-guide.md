# Administration Guide

This guide covers administrative features available to users with the **Admin** or **Owner** role. For basic user operations, see the [User Guide](user-guide.md). For role details, see [Roles & Permissions](roles.md).

## Server Management

Admins manage the inventory of remote SSH servers that Keywarden can deploy keys to.

### Adding a Server

1. Navigate to **Servers** → **Add Server**
2. Fill in:
   - **Name** — Descriptive name (e.g., "Web Server 1")
   - **Hostname** — IP address or DNS name
   - **Port** — SSH port (default: 22)
   - **Username** — SSH admin user for connections (typically `root`)
   - **Description** — Optional description
   - **Server Groups** — Optionally assign the server to one or more groups
3. Click **Save**

### Testing Server Connectivity

From the server list, you can run two types of tests:

- **Connection Test** — TCP connectivity check (is the port reachable?)
- **Auth Test** — Full SSH authentication test using the system master key

Both tests help verify that Keywarden can reach and authenticate to the server.

### Editing / Deleting Servers

Use the edit and delete buttons on the server list. Deleting a server removes it from all groups and cancels related assignments.

## Server Groups

Server groups allow you to organize servers and deploy keys to multiple servers at once.

### Creating a Group

1. Navigate to **Groups** → **Add Group**
2. Enter a **name** and optional **description**
3. Click **Create**

### Managing Group Members

From the group edit page:
- **Add servers** to the group by selecting them from the list of all servers
- **Remove servers** from the group

Server groups are used as targets for:
- Group deployments
- Access assignments
- Cron jobs (temporary access)

## Key Deployment

### Manual Deployment

1. Navigate to **Deploy**
2. Select an **SSH key** from the dropdown (shows all keys from all users)
3. Select a **target server**
4. Click **Deploy**

Keywarden connects to the target server using the system master key and appends the selected public key to the server user's `~/.ssh/authorized_keys`.

### Group Deployment

1. Navigate to **Deploy**
2. Select an **SSH key**
3. Select a **server group**
4. Click **Deploy to Group**

The key is deployed to all servers in the group sequentially.

### Deployment History

The deploy page shows the last 50 deployment results with status (success/failed) and error messages.

## Access Assignments

Access assignments are the core feature for managing who has access to which servers. They provide a declarative model: define the desired state, and Keywarden syncs it to the servers.

### Creating an Assignment

1. Navigate to **Assignments** → **Add Assignment**
2. Fill in:
   - **User** — The Keywarden user to grant access to
   - **SSH Key** — Which key to deploy (from that user's keys)
   - **Target Type** — Single server or server group
   - **Target** — Select the server or group
   - **System User** — The Linux username on the target server
   - **Desired State** — `present` (deploy key) or `absent` (remove key)
   - **Sudo** — Grant NOPASSWD sudo privileges to the system user
   - **Create User** — Create the Linux user if it doesn't exist
3. Click **Save**

After creation, the assignment is **automatically synced** — Keywarden immediately connects to the target server(s) and applies the configuration.

### What Sync Does

When an assignment is synced with `desired_state = "present"`:

1. **Creates the system user** (if `create_user` is enabled and user doesn't exist)
   - Uses `useradd -m -s /bin/bash`
   - Sets an initial password if one is configured (auto-generated if empty)
2. **Adds sudo privileges** (if `sudo` is enabled)
   - Creates `/etc/sudoers.d/<username>` with `NOPASSWD:ALL`
3. **Deploys the SSH public key** to the system user's `authorized_keys`

When an assignment is synced with `desired_state = "absent"`:
- Removes the SSH key from the system user's `authorized_keys`

### Manual Re-Sync

Click the **Sync** button on any assignment to re-apply it. This is useful if the server was reinstalled or if a previous sync failed.

### Deleting an Assignment

When deleting an assignment, you have two options:

- **Remove key only** — Only removes the SSH key from the system user's `authorized_keys`
- **Delete system user** — Completely removes the system user account, their home directory, and sudo privileges from the target server(s)

The cleanup operation runs on all target servers (including all servers in a group).

### Assignment Status

| Status | Meaning |
|---|---|
| `pending` | Not yet synced |
| `synced` | Successfully applied to all targets |
| `failed` | Sync failed (see error message) |

## Cron Jobs (Temporary Access)

Cron jobs provide time-limited access to servers. They are essentially scheduled access assignments with an expiry.

### Creating a Cron Job

1. Navigate to **Temporary Access** → **Add Job**
2. Configure:
   - **Name** — Descriptive job name
   - **Target User** — Keywarden user to grant access to
   - **SSH Key** — Which key to deploy
   - **Target** — Single server or server group
   - **System User** — Linux username on the target
   - **Create User** — Create the system user if needed
   - **Sudo** — Grant sudo privileges
   - **Schedule** — `once`, `hourly`, `daily`, `weekly`, or `monthly`
   - **Scheduled Time** — When the job should run (timezone-aware)
   - **Remove After** — Minutes after deployment to remove access (0 = permanent)
   - **Expiry Action** — What to do when access expires:
     - `remove_key` — Only remove the SSH key
     - `disable_user` — Lock the account and set shell to nologin
     - `delete_user` — Completely delete the system user
3. Click **Save**

### Schedule Types

| Schedule | Parameters | Behavior |
|---|---|---|
| `once` | Date + Time | Runs exactly once at the specified time |
| `hourly` | Minute of hour | Runs every hour at the specified minute |
| `daily` | Time of day | Runs every day at the specified time |
| `weekly` | Day of week + Time | Runs every week on the specified day |
| `monthly` | Day of month + Time | Runs monthly (clamped to last day if needed) |

### Cron Job Lifecycle

1. **Active** — Waiting for next run
2. **Running** — Currently executing
3. **Done** — One-time job completed
4. **Paused** — Manually paused by admin
5. **Failed** — Execution failed (recurring jobs stay active, one-time jobs remain failed)

### Expiry Timer

When `remove_after_min > 0`, a background timer starts after successful deployment. When it fires, the configured expiry action is executed on all target servers.

## User Management

### Creating Users

1. Navigate to **Users** → **Add User**
2. Fill in:
   - **Username** — Must be unique
   - **Email** — Must be unique
   - **Role** — `user`, `admin`, or `owner` (see [Roles & Permissions](roles.md))
   - **Password** — Set a password, or...
   - **Send Invitation** — If email is configured, send an invitation email instead of setting a password
3. Click **Create**

When using invitations, the user receives an email with a secure link to set their own password.

### Editing Users

Admins can change a user's username, email, and role. Additional actions:
- **Reset password** — Set a new password (the user will be prompted to change it)
- **Force password change** — Flag the user to change password on next login
- **Unlock account** — Clear a lockout from failed login attempts

### Deleting Users

Deleting a user removes their SSH keys, server records, and all related data (CASCADE delete).

> **Protection:** You cannot delete the last owner account.

## System Information

Navigate to **System** to view runtime information:

- Go version, OS, architecture
- CPU count, goroutine count
- Memory allocation
- Runtime environment (Docker or native)
- Hostname and uptime

## Admin Settings (Owner Only)

See [Roles & Permissions](roles.md) for details on which settings are owner-only.

Navigate to **Admin Settings** (owner only) to configure:

### Application Settings

- **App Name** — Custom application name displayed in the UI
- **Default Key Type** — Default key type for generation (ed25519, rsa)
- **Default Key Bits** — Default key size
- **Session Timeout** — Inactivity timeout in minutes (default: 60)

### Security Settings

- **Password Policy** — Minimum length, uppercase, lowercase, digit, special character requirements
- **Account Lockout** — Number of failed attempts before lockout and lockout duration
- **MFA Enforcement** — Require all users to enable TOTP MFA

### Master Key

- View the system master key's public key and fingerprint
- **Regenerate** the master key (requires password confirmation)

### Email Test

Send a test email to verify SMTP configuration.

### Backup & Restore

See [Backup & Restore](backup-restore.md) for details.
