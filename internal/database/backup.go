// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// BackupData contains all exportable data from the database
type BackupData struct {
	Version        string                   `json:"version"`
	CreatedAt      string                   `json:"created_at"`
	Users          []map[string]interface{} `json:"users"`
	SSHKeys        []map[string]interface{} `json:"ssh_keys"`
	Servers        []map[string]interface{} `json:"servers"`
	ServerGroups   []map[string]interface{} `json:"server_groups"`
	GroupMembers   []map[string]interface{} `json:"server_group_members"`
	KeyDeployments []map[string]interface{} `json:"key_deployments"`
	AuditLog       []map[string]interface{} `json:"audit_log"`
	Settings       []map[string]interface{} `json:"settings"`
	AccessAssign   []map[string]interface{} `json:"access_assignments"`
	CronJobs       []map[string]interface{} `json:"cron_jobs"`
}

// ExportAll exports all database tables to a BackupData struct
func (d *DB) ExportAll() (*BackupData, error) {
	backup := &BackupData{
		Version:   "1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	tables := []struct {
		query string
		dest  *[]map[string]interface{}
	}{
		{`SELECT id, username, email, password_hash, role, mfa_enabled, mfa_secret, theme, email_notify_login, avatar_base64, must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at FROM users ORDER BY id`, &backup.Users},
		{`SELECT id, user_id, name, key_type, bits, fingerprint, public_key, private_key_enc, passphrase_enc, created_at FROM ssh_keys ORDER BY id`, &backup.SSHKeys},
		{`SELECT id, user_id, name, hostname, port, username, description, created_at, updated_at FROM servers ORDER BY id`, &backup.Servers},
		{`SELECT id, user_id, name, description, created_at, updated_at FROM server_groups ORDER BY id`, &backup.ServerGroups},
		{`SELECT id, group_id, server_id FROM server_group_members ORDER BY id`, &backup.GroupMembers},
		{`SELECT id, ssh_key_id, server_id, deployed_at, status, message FROM key_deployments ORDER BY id`, &backup.KeyDeployments},
		{`SELECT id, user_id, action, details, ip_address, created_at FROM audit_log ORDER BY id`, &backup.AuditLog},
		{`SELECT key, value, updated_at FROM settings ORDER BY key`, &backup.Settings},
		{`SELECT id, user_id, ssh_key_id, server_id, group_id, system_user, desired_state, sudo, create_user, initial_password, status, last_sync_at, created_at, updated_at FROM access_assignments ORDER BY id`, &backup.AccessAssign},
		{`SELECT id, user_id, name, ssh_key_id, server_id, group_id, schedule, scheduled_at, next_run, last_run, remove_after_min, status, message, timezone, time_of_day, day_of_week, day_of_month, minute_of_hour, target_user_id, system_user, sudo, create_user, initial_password, expiry_action, created_at FROM cron_jobs ORDER BY id`, &backup.CronJobs},
	}

	for _, t := range tables {
		rows, err := d.Query(t.query)
		if err != nil {
			return nil, fmt.Errorf("failed to query table: %w", err)
		}
		data, err := rowsToMaps(rows)
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read rows: %w", err)
		}
		*t.dest = data
	}

	return backup, nil
}

// ImportAll restores all database tables from a BackupData struct.
// It clears existing data and replaces it with the backup data.
func (d *DB) ImportAll(backup *BackupData) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Disable foreign key checks during import
	if _, err := tx.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("failed to disable foreign keys: %w", err)
	}

	// Clear all tables in dependency order
	clearOrder := []string{
		"cron_jobs",
		"access_assignments",
		"key_deployments",
		"server_group_members",
		"server_groups",
		"ssh_keys",
		"servers",
		"audit_log",
		"settings",
		"users",
	}
	for _, table := range clearOrder {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			return fmt.Errorf("failed to clear table %s: %w", table, err)
		}
	}

	// Import tables in reverse dependency order (parents first)
	importOrder := []struct {
		table   string
		columns []string
		data    []map[string]interface{}
	}{
		{"users", []string{"id", "username", "email", "password_hash", "role", "mfa_enabled", "mfa_secret", "theme", "email_notify_login", "avatar_base64", "must_change_password", "failed_login_attempts", "locked_until", "last_login_at", "created_at", "updated_at"}, backup.Users},
		{"ssh_keys", []string{"id", "user_id", "name", "key_type", "bits", "fingerprint", "public_key", "private_key_enc", "passphrase_enc", "created_at"}, backup.SSHKeys},
		{"servers", []string{"id", "user_id", "name", "hostname", "port", "username", "description", "created_at", "updated_at"}, backup.Servers},
		{"server_groups", []string{"id", "user_id", "name", "description", "created_at", "updated_at"}, backup.ServerGroups},
		{"server_group_members", []string{"id", "group_id", "server_id"}, backup.GroupMembers},
		{"key_deployments", []string{"id", "ssh_key_id", "server_id", "deployed_at", "status", "message"}, backup.KeyDeployments},
		{"audit_log", []string{"id", "user_id", "action", "details", "ip_address", "created_at"}, backup.AuditLog},
		{"settings", []string{"key", "value", "updated_at"}, backup.Settings},
		{"access_assignments", []string{"id", "user_id", "ssh_key_id", "server_id", "group_id", "system_user", "desired_state", "sudo", "create_user", "initial_password", "status", "last_sync_at", "created_at", "updated_at"}, backup.AccessAssign},
		{"cron_jobs", []string{"id", "user_id", "name", "ssh_key_id", "server_id", "group_id", "schedule", "scheduled_at", "next_run", "last_run", "remove_after_min", "status", "message", "timezone", "time_of_day", "day_of_week", "day_of_month", "minute_of_hour", "target_user_id", "system_user", "sudo", "create_user", "initial_password", "expiry_action", "created_at"}, backup.CronJobs},
	}

	for _, imp := range importOrder {
		if len(imp.data) == 0 {
			continue
		}

		// Build INSERT statement
		placeholders := ""
		for i := range imp.columns {
			if i > 0 {
				placeholders += ", "
			}
			placeholders += "?"
		}
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", imp.table, joinColumns(imp.columns), placeholders)

		stmt, err := tx.Prepare(query)
		if err != nil {
			return fmt.Errorf("failed to prepare insert for %s: %w", imp.table, err)
		}

		for _, row := range imp.data {
			args := make([]interface{}, len(imp.columns))
			for i, col := range imp.columns {
				args[i] = row[col]
			}
			if _, err := stmt.Exec(args...); err != nil {
				stmt.Close()
				return fmt.Errorf("failed to insert into %s: %w", imp.table, err)
			}
		}
		stmt.Close()
	}

	// Re-enable foreign key checks
	if _, err := tx.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("failed to re-enable foreign keys: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// EncryptBackup encrypts JSON backup data with AES-256-GCM using the given password
func EncryptBackup(data []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend a magic header so we can identify backup files
	magic := []byte("KWBAK1") // Keywarden Backup v1
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	result := append(magic, ciphertext...)
	return result, nil
}

// DecryptBackup decrypts an AES-256-GCM encrypted backup with the given password
func DecryptBackup(encrypted []byte, password string) ([]byte, error) {
	// Check magic header
	magic := []byte("KWBAK1")
	if len(encrypted) < len(magic) {
		return nil, fmt.Errorf("invalid backup file: too short")
	}
	if string(encrypted[:len(magic)]) != string(magic) {
		return nil, fmt.Errorf("invalid backup file: wrong format")
	}
	encrypted = encrypted[len(magic):]

	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("invalid backup file: ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong password or corrupted file")
	}

	return plaintext, nil
}

// rowsToMaps converts sql.Rows to a slice of maps
func rowsToMaps(rows *sql.Rows) ([]map[string]interface{}, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// Convert byte slices to strings for JSON serialization
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
	}

	if result == nil {
		result = []map[string]interface{}{}
	}

	return result, rows.Err()
}

// joinColumns joins column names with commas
func joinColumns(cols []string) string {
	result := ""
	for i, col := range cols {
		if i > 0 {
			result += ", "
		}
		result += col
	}
	return result
}

// ParseBackupJSON parses decrypted JSON data into a BackupData struct
func ParseBackupJSON(data []byte) (*BackupData, error) {
	var backup BackupData
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}
	if backup.Version == "" {
		return nil, fmt.Errorf("invalid backup: missing version")
	}
	return &backup, nil
}
