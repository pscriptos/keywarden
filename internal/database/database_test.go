// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	// Verify file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("Database file was not created")
	}
}

func TestMigrationsCreateTables(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	tables := []string{"users", "ssh_keys", "servers", "key_deployments", "audit_log", "settings", "_migrations"}
	for _, table := range tables {
		var count int
		err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check table %s: %v", table, err)
		}
		if count == 0 {
			t.Fatalf("Table %q was not created", table)
		}
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Run migrations twice (opening creates + migrates)
	db1, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() first call failed: %v", err)
	}
	db1.Close()

	db2, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() second call failed (migrations should be idempotent): %v", err)
	}
	defer db2.Close()
}

func TestAlterMigrationsTracked(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	// Check that alter migrations are tracked
	expectedMigrations := []string{"add_mfa_enabled", "add_mfa_secret", "add_is_master_key"}
	for _, name := range expectedMigrations {
		var count int
		err := db.QueryRow(`SELECT COUNT(*) FROM _migrations WHERE name = ?`, name).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check migration %s: %v", name, err)
		}
		if count == 0 {
			t.Fatalf("Migration %q was not tracked", name)
		}
	}
}

func TestInsertAndQueryUser(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	result, err := db.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", "hash123", "user",
	)
	if err != nil {
		t.Fatalf("Insert user failed: %v", err)
	}

	id, _ := result.LastInsertId()
	if id == 0 {
		t.Fatal("Expected non-zero insert ID")
	}

	var username string
	err = db.QueryRow(`SELECT username FROM users WHERE id = ?`, id).Scan(&username)
	if err != nil {
		t.Fatalf("Query user failed: %v", err)
	}
	if username != "testuser" {
		t.Fatalf("Expected username 'testuser', got %q", username)
	}
}

func TestSSHKeyWithMasterFlag(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	// Create a user first
	db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", "hash", "user")

	// Insert a master key
	_, err = db.Exec(
		`INSERT INTO ssh_keys (user_id, name, key_type, bits, fingerprint, public_key, private_key_enc, is_master)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		1, "Master Key", "ed25519", 256, "SHA256:test", "pubkey", "encpriv", 1,
	)
	if err != nil {
		t.Fatalf("Insert master key failed: %v", err)
	}

	// Verify is_master flag
	var isMaster int
	err = db.QueryRow(`SELECT is_master FROM ssh_keys WHERE user_id = 1 AND is_master = 1`).Scan(&isMaster)
	if err != nil {
		t.Fatalf("Query master key failed: %v", err)
	}
	if isMaster != 1 {
		t.Fatalf("Expected is_master=1, got %d", isMaster)
	}
}

func TestForeignKeyCascade(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	// Insert user and key
	db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", "hash", "user")
	db.Exec(`INSERT INTO ssh_keys (user_id, name, key_type, bits, fingerprint, public_key, private_key_enc)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "Test", "ed25519", 256, "fp", "pub", "priv")

	// Delete user — key should cascade
	db.Exec(`DELETE FROM users WHERE id = 1`)

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM ssh_keys WHERE user_id = 1`).Scan(&count)
	if count != 0 {
		t.Fatalf("Expected 0 keys after user deletion (cascade), got %d", count)
	}
}
