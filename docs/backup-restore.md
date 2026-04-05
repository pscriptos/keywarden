# Backup & Restore

Keywarden provides a built-in encrypted backup and restore feature for the entire database. This is an **owner-only** feature accessible from the Admin Settings page.

## Overview

- Backups include **all data**: users, SSH keys (encrypted), servers, groups, assignments, cron jobs, settings, audit log, and deployment history
- Backups are encrypted with a **user-provided password** using AES-256-GCM
- Backup files use the `.kwbak` extension
- Restoring a backup **completely replaces** the current database

## Exporting a Backup

1. Navigate to **Admin Settings** (owner only)
2. In the **Backup & Restore** section, enter a **backup password** and confirm it
3. The password must comply with the configured password policy
4. Click **Export Backup**
5. A file named `keywarden-backup-{timestamp}.kwbak` is downloaded

### What's Included

| Data | Included |
|---|---|
| Users (with password hashes, MFA secrets) | ✅ |
| SSH Keys (with encrypted private keys) | ✅ |
| Servers | ✅ |
| Server Groups + Members | ✅ |
| Access Assignments | ✅ |
| Cron Jobs | ✅ |
| Key Deployment History | ✅ |
| Audit Log | ✅ |
| Application Settings | ✅ |

> **Note:** SSH private keys are stored with double encryption in backups — first with the application's `KEYWARDEN_ENCRYPTION_KEY`, then with the backup password. Both keys are needed to access the private keys.

## Importing a Backup

1. Navigate to **Admin Settings** (owner only)
2. In the **Backup & Restore** section, select the `.kwbak` file
3. Enter the **backup password** that was used during export
4. Click **Import Backup**

### Important Warnings

- **Importing a backup completely replaces all data** in the current database
- All current users, keys, servers, and settings are deleted and replaced
- The current session remains valid (you stay logged in as the owner)
- After import, you may need to log in again with credentials from the backup
- The `KEYWARDEN_ENCRYPTION_KEY` must match the one used when the backup was created — otherwise restored SSH private keys cannot be decrypted

### Error Handling

| Error | Cause |
|---|---|
| "Failed to decrypt backup" | Wrong backup password |
| "Failed to parse backup" | Corrupt or invalid backup file |
| "Failed to import" | Database error during restore |

## Backup Security

- Backups are encrypted with AES-256-GCM using a key derived from SHA-256 of the backup password
- The encrypted blob is a single binary file (not JSON)
- Without the correct password, the backup cannot be read or modified
- Use strong, unique passwords for backups
- Store backup files and passwords separately

## Backup Strategy

### Recommended Approach

1. **Regular exports**: Export a backup weekly or after significant changes
2. **Secure storage**: Store `.kwbak` files in a separate, secure location
3. **Password management**: Store backup passwords in a password manager
4. **Test restores**: Periodically verify backups by restoring to a test instance
5. **Encryption key backup**: Keep a secure copy of `KEYWARDEN_ENCRYPTION_KEY`

### Docker Volume Backup

In addition to the application-level backup, you can also back up the Docker volume directly:

```bash
# Stop the container
docker compose down

# Backup the volume
docker run --rm -v keywarden_keywarden_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/keywarden-volume-backup.tar.gz /data

# Start the container
docker compose up -d
```

This captures the raw SQLite database file and all data files. Note that this backup is **not encrypted** — protect it accordingly.
