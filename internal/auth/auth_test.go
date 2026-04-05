// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package auth

import (
	"path/filepath"
	"testing"

	"git.techniverse.net/scriptos/keywarden/internal/database"
)

func setupTestDB(t *testing.T) *database.DB {
	t.Helper()
	tmpDir := t.TempDir()
	db, err := database.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	return db
}

func TestRegisterAndLogin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	user, err := svc.Register("testuser", "test@example.com", "password123", "user", false)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Fatalf("Expected username 'testuser', got %q", user.Username)
	}
	if user.Role != "user" {
		t.Fatalf("Expected role 'user', got %q", user.Role)
	}

	// Login with correct credentials
	loggedIn, err := svc.Login("testuser", "password123")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if loggedIn.ID != user.ID {
		t.Fatalf("Login returned different user ID")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	svc.Register("testuser", "test@example.com", "password123", "user", false)

	_, err := svc.Login("testuser", "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	_, err := svc.Login("nonexistent", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got %v", err)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	_, err := svc.Register("testuser", "test@example.com", "pass1", "user", false)
	if err != nil {
		t.Fatalf("First register failed: %v", err)
	}

	_, err = svc.Register("testuser", "test2@example.com", "pass2", "user", false)
	if err != ErrUserExists {
		t.Fatalf("Expected ErrUserExists, got %v", err)
	}
}

func TestRegisterDefaultRole(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	user, err := svc.Register("testuser", "test@example.com", "pass", "", false)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if user.Role != "user" {
		t.Fatalf("Expected default role 'user', got %q", user.Role)
	}
}

func TestGetUserByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	created, _ := svc.Register("testuser", "test@example.com", "pass", "admin", false)

	user, err := svc.GetUserByID(created.ID)
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Fatalf("Expected username 'testuser', got %q", user.Username)
	}
	if user.Role != "admin" {
		t.Fatalf("Expected role 'admin', got %q", user.Role)
	}
}

func TestGetUserByIDNotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	_, err := svc.GetUserByID(999)
	if err != ErrUserNotFound {
		t.Fatalf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	created, _ := svc.Register("testuser", "test@example.com", "pass", "user", false)

	err := svc.UpdateUser(created.ID, "newname", "new@example.com", "admin")
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	user, _ := svc.GetUserByID(created.ID)
	if user.Username != "newname" {
		t.Fatalf("Expected updated username 'newname', got %q", user.Username)
	}
	if user.Email != "new@example.com" {
		t.Fatalf("Expected updated email, got %q", user.Email)
	}
	if user.Role != "admin" {
		t.Fatalf("Expected updated role 'admin', got %q", user.Role)
	}
}

func TestUpdatePassword(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	created, _ := svc.Register("testuser", "test@example.com", "oldpass", "user", false)

	err := svc.UpdatePassword(created.ID, "newpass")
	if err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}

	// Old password should fail
	_, err = svc.Login("testuser", "oldpass")
	if err != ErrInvalidCredentials {
		t.Fatalf("Old password should no longer work")
	}

	// New password should work
	_, err = svc.Login("testuser", "newpass")
	if err != nil {
		t.Fatalf("Login with new password failed: %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	created, _ := svc.Register("testuser", "test@example.com", "pass", "user", false)

	err := svc.DeleteUser(created.ID)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	_, err = svc.GetUserByID(created.ID)
	if err != ErrUserNotFound {
		t.Fatalf("Expected ErrUserNotFound after deletion, got %v", err)
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	err := svc.DeleteUser(999)
	if err != ErrUserNotFound {
		t.Fatalf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestEnsureAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	created, generatedPass, err := svc.EnsureAdmin("admin", "admin@test.com")
	if err != nil {
		t.Fatalf("EnsureAdmin failed: %v", err)
	}
	if !created {
		t.Fatal("Expected user to be created")
	}
	if len(generatedPass) != 20 {
		t.Fatalf("Expected 20-char generated password, got %d chars", len(generatedPass))
	}

	// Admin should be loginable with generated password
	user, err := svc.Login("admin", generatedPass)
	if err != nil {
		t.Fatalf("Login as admin failed: %v", err)
	}
	if user.Role != "owner" {
		t.Fatalf("Expected owner role, got %q", user.Role)
	}

	// Second call should be no-op
	created2, _, err := svc.EnsureAdmin("admin2", "admin2@test.com")
	if err != nil {
		t.Fatalf("Second EnsureAdmin should not fail: %v", err)
	}
	if created2 {
		t.Fatal("Second EnsureAdmin should not create a user")
	}

	// admin2 should NOT exist (was skipped)
	_, err = svc.Login("admin2", "anypass")
	if err != ErrInvalidCredentials {
		t.Fatalf("admin2 should not have been created")
	}
}

func TestGetAllUsers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	svc.Register("user1", "user1@test.com", "pass1", "user", false)
	svc.Register("user2", "user2@test.com", "pass2", "admin", false)

	users, err := svc.GetAllUsers()
	if err != nil {
		t.Fatalf("GetAllUsers failed: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(users))
	}
}

func TestHasUsers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	has, err := svc.HasUsers()
	if err != nil {
		t.Fatalf("HasUsers failed: %v", err)
	}
	if has {
		t.Fatal("Expected no users initially")
	}

	svc.Register("user1", "user1@test.com", "pass1", "user", false)

	has, err = svc.HasUsers()
	if err != nil {
		t.Fatalf("HasUsers failed: %v", err)
	}
	if !has {
		t.Fatal("Expected users after registration")
	}
}

func TestSettings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	// Get non-existent setting
	val, err := svc.GetSetting("app_name")
	if err != nil {
		t.Fatalf("GetSetting failed: %v", err)
	}
	if val != "" {
		t.Fatalf("Expected empty value, got %q", val)
	}

	// Set and get
	err = svc.SetSetting("app_name", "Keywarden Test")
	if err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	val, err = svc.GetSetting("app_name")
	if err != nil {
		t.Fatalf("GetSetting failed: %v", err)
	}
	if val != "Keywarden Test" {
		t.Fatalf("Expected 'Keywarden Test', got %q", val)
	}

	// Update existing
	err = svc.SetSetting("app_name", "Updated")
	if err != nil {
		t.Fatalf("SetSetting update failed: %v", err)
	}

	val, _ = svc.GetSetting("app_name")
	if val != "Updated" {
		t.Fatalf("Expected 'Updated', got %q", val)
	}
}

func TestGetAllSettings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	svc.SetSetting("key1", "val1")
	svc.SetSetting("key2", "val2")

	settings, err := svc.GetAllSettings()
	if err != nil {
		t.Fatalf("GetAllSettings failed: %v", err)
	}
	if len(settings) != 2 {
		t.Fatalf("Expected 2 settings, got %d", len(settings))
	}
	if settings["key1"] != "val1" || settings["key2"] != "val2" {
		t.Fatal("Settings values mismatch")
	}
}

func TestMFASecret(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	secret := svc.GenerateMFASecret()
	if len(secret) == 0 {
		t.Fatal("MFA secret should not be empty")
	}

	// Should be valid base32
	if len(secret) < 16 {
		t.Fatalf("MFA secret seems too short: %d chars", len(secret))
	}
}

func TestEnableDisableMFA(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	svc := NewService(db)

	user, _ := svc.Register("testuser", "test@example.com", "pass", "user", false)

	err := svc.EnableMFA(user.ID, "TESTSECRET")
	if err != nil {
		t.Fatalf("EnableMFA failed: %v", err)
	}

	updated, _ := svc.GetUserByID(user.ID)
	if !updated.MFAEnabled {
		t.Fatal("MFA should be enabled")
	}
	if updated.MFASecret != "TESTSECRET" {
		t.Fatalf("MFA secret mismatch: got %q", updated.MFASecret)
	}

	err = svc.DisableMFA(user.ID)
	if err != nil {
		t.Fatalf("DisableMFA failed: %v", err)
	}

	updated, _ = svc.GetUserByID(user.ID)
	if updated.MFAEnabled {
		t.Fatal("MFA should be disabled")
	}
}
