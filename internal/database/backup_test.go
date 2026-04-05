// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"encoding/json"
	"testing"
)

func TestEncryptDecryptBackup(t *testing.T) {
	password := "TestP@ssw0rd123!"
	original := &BackupData{
		Version:   "1",
		CreatedAt: "2026-04-05T12:00:00Z",
		Users: []map[string]interface{}{
			{"id": float64(1), "username": "admin", "email": "admin@test.local"},
		},
		SSHKeys:      []map[string]interface{}{},
		Servers:      []map[string]interface{}{},
		ServerGroups: []map[string]interface{}{},
		GroupMembers: []map[string]interface{}{},
	}

	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	encrypted, err := EncryptBackup(jsonData, password)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Check magic header
	if string(encrypted[:6]) != "KWBAK1" {
		t.Error("Missing KWBAK1 magic header")
	}

	// Decrypt with correct password
	decrypted, err := DecryptBackup(encrypted, password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify content matches
	var restored BackupData
	if err := json.Unmarshal(decrypted, &restored); err != nil {
		t.Fatalf("Failed to unmarshal decrypted data: %v", err)
	}

	if restored.Version != original.Version {
		t.Errorf("Version mismatch: got %s, want %s", restored.Version, original.Version)
	}
	if len(restored.Users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(restored.Users))
	}

	// Wrong password should fail
	_, err = DecryptBackup(encrypted, "wrong-password")
	if err == nil {
		t.Error("Expected error with wrong password, got nil")
	}
}

func TestDecryptBackupInvalidFile(t *testing.T) {
	_, err := DecryptBackup([]byte("invalid data"), "password")
	if err == nil {
		t.Error("Expected error for invalid file, got nil")
	}

	_, err = DecryptBackup([]byte("short"), "password")
	if err == nil {
		t.Error("Expected error for too-short data, got nil")
	}
}

func TestParseBackupJSON(t *testing.T) {
	valid := `{"version":"1","created_at":"2026-04-05T12:00:00Z","users":[],"ssh_keys":[],"servers":[],"server_groups":[],"server_group_members":[],"key_deployments":[],"audit_log":[],"settings":[],"access_assignments":[],"cron_jobs":[]}`
	backup, err := ParseBackupJSON([]byte(valid))
	if err != nil {
		t.Fatalf("Failed to parse valid JSON: %v", err)
	}
	if backup.Version != "1" {
		t.Errorf("Version mismatch: got %s, want 1", backup.Version)
	}

	// Missing version
	invalid := `{"created_at":"2026-04-05T12:00:00Z"}`
	_, err = ParseBackupJSON([]byte(invalid))
	if err == nil {
		t.Error("Expected error for missing version, got nil")
	}

	// Invalid JSON
	_, err = ParseBackupJSON([]byte("not json"))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}
