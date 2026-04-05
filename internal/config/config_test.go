// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear all KEYWARDEN_ env vars to ensure defaults
	envs := []string{
		"KEYWARDEN_PORT", "KEYWARDEN_DB_PATH", "KEYWARDEN_DATA_DIR",
		"KEYWARDEN_KEYS_DIR", "KEYWARDEN_MASTER_DIR", "KEYWARDEN_SESSION_KEY",
		"KEYWARDEN_ENCRYPTION_KEY",
	}
	for _, e := range envs {
		os.Unsetenv(e)
	}

	cfg := Load()

	if cfg.Port != "8080" {
		t.Fatalf("Expected default port 8080, got %q", cfg.Port)
	}
	if cfg.DBPath != "./data/keywarden.db" {
		t.Fatalf("Expected default DBPath, got %q", cfg.DBPath)
	}
	if cfg.DataDir != "./data" {
		t.Fatalf("Expected default DataDir, got %q", cfg.DataDir)
	}
	if cfg.KeysDir != "./data/keys" {
		t.Fatalf("Expected default KeysDir, got %q", cfg.KeysDir)
	}
	if cfg.MasterDir != "./data/master" {
		t.Fatalf("Expected default MasterDir, got %q", cfg.MasterDir)
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("KEYWARDEN_PORT", "9090")
	os.Setenv("KEYWARDEN_DB_PATH", "/custom/db.sqlite")
	os.Setenv("KEYWARDEN_DATA_DIR", "/custom/data")
	os.Setenv("KEYWARDEN_ENCRYPTION_KEY", "my-custom-key")
	defer func() {
		os.Unsetenv("KEYWARDEN_PORT")
		os.Unsetenv("KEYWARDEN_DB_PATH")
		os.Unsetenv("KEYWARDEN_DATA_DIR")
		os.Unsetenv("KEYWARDEN_ENCRYPTION_KEY")
	}()

	cfg := Load()

	if cfg.Port != "9090" {
		t.Fatalf("Expected port 9090, got %q", cfg.Port)
	}
	if cfg.DBPath != "/custom/db.sqlite" {
		t.Fatalf("Expected custom DBPath, got %q", cfg.DBPath)
	}
	if cfg.DataDir != "/custom/data" {
		t.Fatalf("Expected custom DataDir, got %q", cfg.DataDir)
	}
	if cfg.EncryptionKey != "my-custom-key" {
		t.Fatalf("Expected custom EncryptionKey, got %q", cfg.EncryptionKey)
	}
}
