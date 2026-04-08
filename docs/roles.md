# Roles & Permissions

Keywarden uses a three-tier role system: **Owner**, **Admin**, and **User**. Each role inherits all permissions of the role below it.

## Role Hierarchy

```
Owner  →  Admin  →  User
```

## Role Comparison

| Capability | User | Admin | Owner |
|---|:---:|:---:|:---:|
| **SSH Keys** | | | |
| Generate SSH keys | ✅ | ✅ | ✅ |
| Import SSH keys | ✅ | ✅ | ✅ |
| View own keys | ✅ | ✅ | ✅ |
| Download own keys | ✅ | ✅ | ✅ |
| Delete own keys | ✅ | ✅ | ✅ |
| View all users' keys | ❌ | ✅ | ✅ |
| Delete any user's keys | ❌ | ✅ | ✅ |
| **Account Settings** | | | |
| Change own password | ✅ | ✅ | ✅ |
| Change theme | ✅ | ✅ | ✅ |
| Enable/disable MFA | ✅ | ✅ | ✅ |
| Upload avatar | ✅ | ✅ | ✅ |
| Toggle email notifications | ✅ | ✅ | ✅ |
| **Access** | | | |
| View own access assignments | ✅ | ✅ | ✅ |
| View own audit log | ✅ | ✅ | ✅ |
| **Server Management** | | | |
| Add/edit/delete servers | ❌ | ✅ | ✅ |
| Add/edit/delete server groups | ❌ | ✅ | ✅ |
| Test server connectivity | ❌ | ✅ | ✅ |
| **Deployments** | | | |
| Manual key deployment | ❌ | ✅ | ✅ |
| Deploy system master key | ❌ | ❌ | ✅ |
| Group deployment | ❌ | ✅ | ✅ |
| **Access Assignments** | | | |
| Create/edit/delete assignments | ❌ | ✅ | ✅ |
| Sync assignments | ❌ | ✅ | ✅ |
| **Temporary Access (Cron)** | | | |
| Create/edit/delete cron jobs | ❌ | ✅ | ✅ |
| Pause/resume cron jobs | ❌ | ✅ | ✅ |
| **User Management** | | | |
| Create/edit/delete users | ❌ | ✅ | ✅ |
| Unlock locked accounts | ❌ | ✅ | ✅ |
| Force password change | ❌ | ✅ | ✅ |
| Send user invitations | ❌ | ✅ | ✅ |
| **System** | | | |
| View system information | ❌ | ✅ | ✅ |
| View full audit log | ❌ | ✅ | ✅ |
| **Administration** | | | |
| Application settings | ❌ | ❌ | ✅ |
| Security settings (password policy, MFA enforcement) | ❌ | ❌ | ✅ |
| Regenerate master key | ❌ | ❌ | ✅ |
| Backup / Restore | ❌ | ❌ | ✅ |
| Send test email | ❌ | ❌ | ✅ |

## Role Details

### User

The **User** role is the default role for new accounts. Users can:

- Manage their own SSH keys (generate, import, download, delete)
- View their own access assignments (read-only)
- Manage their account settings (password, theme, MFA, avatar, email notifications)
- View their own audit log entries

Users **cannot** manage servers, deploy keys, create access assignments, or view other users' data.

### Admin

The **Admin** role has full operational access. In addition to all User permissions, admins can:

- Manage servers and server groups (add, edit, delete, test connectivity)
- Deploy SSH keys to servers (manual and group deployments)
- Create and manage access assignments (including sync and cleanup)
- Create and manage cron jobs for temporary access
- Manage users (create, edit, delete, unlock, force password change, send invitations)
- View system information
- View the complete audit log (excluding owner entries)

Admins **cannot** access the Admin Settings page, regenerate the master key, manage backups, or modify security policies.

### Owner

The **Owner** role has unrestricted access. In addition to all Admin permissions, the owner can:

- Deploy the system master key to servers (via the Deploy page)
- Access the Admin Settings page
- Configure application settings (app name, session timeout, default key type)
- Configure security settings (password policy, account lockout, MFA enforcement)
- View and regenerate the system master key
- Export and import encrypted database backups
- Send test emails
- View all audit log entries (including owner actions)

#### Owner Protections

- **Initial owner is permanently protected**: The owner account created during installation cannot be deleted, and its role cannot be changed. This is enforced both server-side and in the UI.
- The last owner account cannot be deleted
- The owner can always access Admin Settings, even when MFA enforcement would otherwise redirect them (to prevent lockout)
- On first startup, the initial account is always created with the `owner` role
- If no owner exists (e.g., after a migration from an older version), the first admin is automatically promoted to owner

> **Note:** Existing installations are automatically migrated — the oldest owner (by ID) is marked as the initial owner during the database migration.

## Audit Log Visibility

The audit log has role-based filtering:

| Viewer | Sees |
|---|---|
| User | Own actions only |
| Admin | All actions except those from owner accounts |
| Owner | All actions from all users |

## Initial Setup

On first startup, Keywarden creates a single **owner** account. The owner should then:

1. Change the initial password
2. (Optional) Create additional admin accounts
3. (Optional) Create regular user accounts or send invitations
