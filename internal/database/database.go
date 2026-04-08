// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the sql.DB connection
type DB struct {
	*sql.DB
}

// New creates a new database connection and runs migrations
func New(dbPath string) (*DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &DB{db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return d, nil
}

// migrate creates all required tables
func (d *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			key_type TEXT NOT NULL,
			bits INTEGER,
			fingerprint TEXT NOT NULL,
			public_key TEXT NOT NULL,
			private_key_enc TEXT NOT NULL,
			passphrase_enc TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 22,
			username TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS key_deployments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ssh_key_id INTEGER NOT NULL,
			server_id INTEGER NOT NULL,
			deployed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			status TEXT NOT NULL DEFAULT 'pending',
			message TEXT,
			FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Migration: add MFA columns to users if not present
		`CREATE TABLE IF NOT EXISTS _migrations (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE IF NOT EXISTS server_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS server_group_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id INTEGER NOT NULL,
			server_id INTEGER NOT NULL,
			FOREIGN KEY (group_id) REFERENCES server_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
			UNIQUE(group_id, server_id)
		)`,
		`CREATE TABLE IF NOT EXISTS access_assignments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			ssh_key_id INTEGER NOT NULL,
			server_id INTEGER DEFAULT 0,
			group_id INTEGER DEFAULT 0,
			system_user TEXT NOT NULL,
			desired_state TEXT NOT NULL DEFAULT 'present',
			sudo INTEGER NOT NULL DEFAULT 0,
			create_user INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'pending',
			last_sync_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS cron_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			ssh_key_id INTEGER NOT NULL,
			server_id INTEGER DEFAULT 0,
			group_id INTEGER DEFAULT 0,
			schedule TEXT NOT NULL DEFAULT 'once',
			scheduled_at DATETIME NOT NULL,
			next_run DATETIME NOT NULL,
			last_run DATETIME,
			remove_after_min INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			message TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id) ON DELETE CASCADE
		)`,
	}

	for _, m := range migrations {
		if _, err := d.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	// Conditional migrations (ALTER TABLE)
	alterMigrations := map[string]string{
		"add_mfa_enabled":           `ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0`,
		"add_mfa_secret":            `ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT ''`,
		"add_is_master_key":         `ALTER TABLE ssh_keys ADD COLUMN is_master INTEGER NOT NULL DEFAULT 0`,
		"add_user_theme":            `ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'auto'`,
		"add_email_notify_login":    `ALTER TABLE users ADD COLUMN email_notify_login INTEGER NOT NULL DEFAULT 0`,
		"add_avatar_base64":         `ALTER TABLE users ADD COLUMN avatar_base64 TEXT NOT NULL DEFAULT ''`,
		"add_cron_auth_key_id":      `ALTER TABLE cron_jobs ADD COLUMN auth_key_id INTEGER NOT NULL DEFAULT 0`,
		"add_initial_password":      `ALTER TABLE access_assignments ADD COLUMN initial_password TEXT NOT NULL DEFAULT ''`,
		"add_cron_timezone":         `ALTER TABLE cron_jobs ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC'`,
		"add_cron_time_of_day":      `ALTER TABLE cron_jobs ADD COLUMN time_of_day TEXT NOT NULL DEFAULT '00:00'`,
		"add_cron_day_of_week":      `ALTER TABLE cron_jobs ADD COLUMN day_of_week INTEGER NOT NULL DEFAULT -1`,
		"add_cron_day_of_month":     `ALTER TABLE cron_jobs ADD COLUMN day_of_month INTEGER NOT NULL DEFAULT 0`,
		"add_cron_minute_of_hour":   `ALTER TABLE cron_jobs ADD COLUMN minute_of_hour INTEGER NOT NULL DEFAULT 0`,
		"add_cron_target_user_id":   `ALTER TABLE cron_jobs ADD COLUMN target_user_id INTEGER NOT NULL DEFAULT 0`,
		"add_cron_assignment_id":    `ALTER TABLE cron_jobs ADD COLUMN assignment_id INTEGER NOT NULL DEFAULT 0`,
		"add_cron_system_user":      `ALTER TABLE cron_jobs ADD COLUMN system_user TEXT NOT NULL DEFAULT ''`,
		"add_cron_sudo":             `ALTER TABLE cron_jobs ADD COLUMN sudo INTEGER NOT NULL DEFAULT 0`,
		"add_cron_create_user":      `ALTER TABLE cron_jobs ADD COLUMN create_user INTEGER NOT NULL DEFAULT 0`,
		"add_cron_init_password":    `ALTER TABLE cron_jobs ADD COLUMN initial_password TEXT NOT NULL DEFAULT ''`,
		"add_cron_expiry_action":    `ALTER TABLE cron_jobs ADD COLUMN expiry_action TEXT NOT NULL DEFAULT 'remove_key'`,
		"add_must_change_password":  `ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`,
		"add_failed_login_attempts": `ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0`,
		"add_locked_until":          `ALTER TABLE users ADD COLUMN locked_until DATETIME`,
		"add_last_login_at":         `ALTER TABLE users ADD COLUMN last_login_at DATETIME`,
	}

	// Invitation tokens table (created via migration to avoid altering initial schema)
	inviteTableMigration := map[string]string{
		"create_invitation_tokens": `CREATE TABLE IF NOT EXISTS invitation_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			used INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
	}

	for name, sql := range inviteTableMigration {
		var count int
		d.QueryRow(`SELECT COUNT(*) FROM _migrations WHERE name = ?`, name).Scan(&count)
		if count == 0 {
			if _, err := d.Exec(sql); err != nil {
				return fmt.Errorf("migration %s failed: %w", name, err)
			}
			d.Exec(`INSERT INTO _migrations (name) VALUES (?)`, name)
		}
	}

	for name, sql := range alterMigrations {
		var count int
		d.QueryRow(`SELECT COUNT(*) FROM _migrations WHERE name = ?`, name).Scan(&count)
		if count == 0 {
			d.Exec(sql) // ignore error if column already exists
			d.Exec(`INSERT INTO _migrations (name) VALUES (?)`, name)
		}
	}

	// Role model migration: promote first admin to owner if no owner exists yet
	{
		var migCount int
		d.QueryRow(`SELECT COUNT(*) FROM _migrations WHERE name = 'promote_admin_to_owner'`).Scan(&migCount)
		if migCount == 0 {
			var ownerCount int
			d.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'owner'`).Scan(&ownerCount)
			if ownerCount == 0 {
				// Find the first admin (by ID) and promote to owner
				var firstAdminID int64
				err := d.QueryRow(`SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1`).Scan(&firstAdminID)
				if err == nil && firstAdminID > 0 {
					d.Exec(`UPDATE users SET role = 'owner' WHERE id = ?`, firstAdminID)
				}
			}
			d.Exec(`INSERT INTO _migrations (name) VALUES ('promote_admin_to_owner')`)
		}
	}

	// Migration: backfill initial_owner_id for existing installations
	{
		var migCount int
		d.QueryRow(`SELECT COUNT(*) FROM _migrations WHERE name = 'backfill_initial_owner_id'`).Scan(&migCount)
		if migCount == 0 {
			// Only set if not already present (new installs set it in EnsureAdmin)
			var existing string
			err := d.QueryRow(`SELECT value FROM settings WHERE key = 'initial_owner_id'`).Scan(&existing)
			if err != nil || existing == "" {
				// Pick the oldest owner (lowest ID) as the initial owner
				var ownerID int64
				err := d.QueryRow(`SELECT id FROM users WHERE role = 'owner' ORDER BY id ASC LIMIT 1`).Scan(&ownerID)
				if err == nil && ownerID > 0 {
					d.Exec(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('initial_owner_id', CAST(? AS TEXT), CURRENT_TIMESTAMP)`, ownerID)
				}
			}
			d.Exec(`INSERT INTO _migrations (name) VALUES ('backfill_initial_owner_id')`)
		}
	}

	return nil
}
