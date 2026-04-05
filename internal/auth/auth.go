// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/models"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserExists         = errors.New("username or email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrMFARequired        = errors.New("mfa verification required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
	ErrAccountLocked      = errors.New("account is temporarily locked")
)

// Service handles user authentication
type Service struct {
	db *database.DB
}

// NewService creates a new auth service
func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Register creates a new user account. If mustChangePassword is true, the user
// will be forced to change their password on next login.
func (s *Service) Register(username, email, password, role string, mustChangePassword bool) (*models.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	if role == "" {
		role = "user"
	}

	mcp := 0
	if mustChangePassword {
		mcp = 1
	}

	result, err := s.db.Exec(
		`INSERT INTO users (username, email, password_hash, role, must_change_password) VALUES (?, ?, ?, ?, ?)`,
		username, email, string(hash), role, mcp,
	)
	if err != nil {
		return nil, ErrUserExists
	}

	id, _ := result.LastInsertId()
	return &models.User{
		ID:                 id,
		Username:           username,
		Email:              email,
		Role:               role,
		MustChangePassword: mustChangePassword,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}, nil
}

// Login authenticates a user and returns the user if successful
func (s *Service) Login(username, password string) (*models.User, error) {
	user := &models.User{}
	err := s.db.QueryRow(
		`SELECT id, username, email, password_hash, role, mfa_enabled, mfa_secret, theme, email_notify_login, must_change_password, failed_login_attempts, locked_until, created_at, updated_at FROM users WHERE username = ?`,
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.MFAEnabled, &user.MFASecret, &user.Theme, &user.EmailNotifyLogin, &user.MustChangePassword, &user.FailedLoginAttempts, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	// Check account lockout
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// GetUserByID returns a user by their ID
func (s *Service) GetUserByID(id int64) (*models.User, error) {
	user := &models.User{}
	err := s.db.QueryRow(
		`SELECT id, username, email, password_hash, role, mfa_enabled, mfa_secret, theme, email_notify_login, avatar_base64, must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at FROM users WHERE id = ?`,
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.MFAEnabled, &user.MFASecret, &user.Theme, &user.EmailNotifyLogin, &user.AvatarBase64, &user.MustChangePassword, &user.FailedLoginAttempts, &user.LockedUntil, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return user, nil
}

// GetAllUsers returns all registered users (admin only)
func (s *Service) GetAllUsers() ([]models.User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, email, role, mfa_enabled, must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.MFAEnabled, &u.MustChangePassword, &u.FailedLoginAttempts, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}

	return users, nil
}

// HasUsers checks if any users exist in the database
func (s *Service) HasUsers() (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// EnsureAdmin creates a default owner user if no users exist.
// It auto-generates a secure password and returns (created, generatedPassword, error).
// A persistent flag ("initial_setup_complete") is stored in the settings table
// so that an admin account is never re-created after the initial setup, even
// if the users table is unexpectedly empty (e.g. due to a misconfigured volume).
func (s *Service) EnsureAdmin(username, email string) (bool, string, error) {
	// Defence-in-depth: if the initial setup was already completed once,
	// never auto-create another admin – even when the users table is empty.
	if s.isInitialSetupComplete() {
		return false, "", nil
	}

	hasUsers, err := s.HasUsers()
	if err != nil {
		return false, "", err
	}
	if hasUsers {
		// Users exist but no flag yet (upgrade path) – set the flag now.
		s.markInitialSetupComplete()
		return false, "", nil
	}

	// Generate a secure random password (20 chars, base62)
	password, err := generateSecurePassword(20)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, "", fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO users (username, email, password_hash, role, must_change_password) VALUES (?, ?, ?, ?, 1)`,
		username, email, string(hash), "owner",
	)
	if err != nil {
		return false, "", err
	}

	// Mark initial setup as complete so the password is never regenerated.
	s.markInitialSetupComplete()

	return true, password, nil
}

// isInitialSetupComplete checks whether the initial admin setup has already
// been performed by looking for a flag in the settings table.
func (s *Service) isInitialSetupComplete() bool {
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'initial_setup_complete'`).Scan(&val)
	return err == nil && val == "true"
}

// markInitialSetupComplete persists the initial-setup flag in the settings table.
func (s *Service) markInitialSetupComplete() {
	s.db.Exec(
		`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('initial_setup_complete', 'true', CURRENT_TIMESTAMP)`,
	)
}

// generateSecurePassword creates a cryptographically secure random password
func generateSecurePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// UpdateUser updates user details (admin function)
func (s *Service) UpdateUser(id int64, username, email, role string) error {
	_, err := s.db.Exec(
		`UPDATE users SET username = ?, email = ?, role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		username, email, role, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// UpdatePassword changes a user's password
func (s *Service) UpdatePassword(id int64, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = s.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(hash), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

// DeleteUser removes a user
func (s *Service) DeleteUser(id int64) error {
	result, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

// CountByRole counts how many users have the given role
func (s *Service) CountByRole(role string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, role).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users by role: %w", err)
	}
	return count, nil
}

// GenerateMFASecret generates a random TOTP secret
func (s *Service) GenerateMFASecret() string {
	secret := make([]byte, 20)
	rand.Read(secret)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// EnableMFA stores the MFA secret for a user
func (s *Service) EnableMFA(userID int64, secret string) error {
	_, err := s.db.Exec(
		`UPDATE users SET mfa_enabled = 1, mfa_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		secret, userID,
	)
	return err
}

// DisableMFA removes MFA for a user
func (s *Service) DisableMFA(userID int64) error {
	_, err := s.db.Exec(
		`UPDATE users SET mfa_enabled = 0, mfa_secret = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		userID,
	)
	return err
}

// UpdateTheme updates the user's theme preference (auto, light, dark)
func (s *Service) UpdateTheme(id int64, theme string) error {
	if theme != "auto" && theme != "light" && theme != "dark" {
		theme = "auto"
	}
	_, err := s.db.Exec(
		`UPDATE users SET theme = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		theme, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update theme: %w", err)
	}
	return nil
}

// UpdateEmailNotifyLogin updates the user's login email notification setting
func (s *Service) UpdateEmailNotifyLogin(id int64, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	_, err := s.db.Exec(
		`UPDATE users SET email_notify_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		val, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update email notification setting: %w", err)
	}
	return nil
}

// UpdateAvatar updates the user's profile picture (base64-encoded data URI)
func (s *Service) UpdateAvatar(id int64, avatarBase64 string) error {
	_, err := s.db.Exec(
		`UPDATE users SET avatar_base64 = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		avatarBase64, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update avatar: %w", err)
	}
	return nil
}

// LegacyAvatar holds the minimal info needed for avatar migration
type LegacyAvatar struct {
	ID           int64
	AvatarBase64 string
}

// GetUsersWithLegacyAvatars returns users whose avatar_base64 contains a data URI (legacy format)
func (s *Service) GetUsersWithLegacyAvatars() ([]LegacyAvatar, error) {
	rows, err := s.db.Query(`SELECT id, avatar_base64 FROM users WHERE avatar_base64 LIKE 'data:%'`)
	if err != nil {
		return nil, fmt.Errorf("failed to query legacy avatars: %w", err)
	}
	defer rows.Close()

	var results []LegacyAvatar
	for rows.Next() {
		var la LegacyAvatar
		if err := rows.Scan(&la.ID, &la.AvatarBase64); err != nil {
			return nil, fmt.Errorf("failed to scan legacy avatar: %w", err)
		}
		results = append(results, la)
	}
	return results, nil
}

// GetSetting reads a setting value
func (s *Service) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting writes a setting value
func (s *Service) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
		key, value,
	)
	return err
}

// SetSettingsBatch writes multiple settings in a single transaction
func (s *Service) SetSettingsBatch(settings map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
	)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for k, v := range settings {
		if _, err := stmt.Exec(k, v); err != nil {
			return fmt.Errorf("failed to save setting %s: %w", k, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit settings: %w", err)
	}
	return nil
}

// GetAllSettings returns all settings as a map
func (s *Service) GetAllSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, nil
}

// --- Password Policy ---

// GetPasswordPolicy returns the current password policy from settings.
// Missing settings default to sensible values.
func (s *Service) GetPasswordPolicy() models.PasswordPolicy {
	policy := models.PasswordPolicy{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: false,
	}
	if v, _ := s.GetSetting("pw_min_length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4 {
			policy.MinLength = n
		}
	}
	if v, _ := s.GetSetting("pw_require_upper"); v == "false" {
		policy.RequireUpper = false
	}
	if v, _ := s.GetSetting("pw_require_lower"); v == "false" {
		policy.RequireLower = false
	}
	if v, _ := s.GetSetting("pw_require_digit"); v == "false" {
		policy.RequireDigit = false
	}
	if v, _ := s.GetSetting("pw_require_special"); v == "true" {
		policy.RequireSpecial = true
	}
	return policy
}

// ValidatePasswordPolicy checks a password against the configured policy.
// Returns nil if the password is compliant, otherwise a descriptive error.
func (s *Service) ValidatePasswordPolicy(password string) error {
	policy := s.GetPasswordPolicy()
	var violations []string

	if len(password) < policy.MinLength {
		violations = append(violations, fmt.Sprintf("at least %d characters", policy.MinLength))
	}
	if policy.RequireUpper {
		hasUpper := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			violations = append(violations, "at least one uppercase letter")
		}
	}
	if policy.RequireLower {
		hasLower := false
		for _, r := range password {
			if unicode.IsLower(r) {
				hasLower = true
				break
			}
		}
		if !hasLower {
			violations = append(violations, "at least one lowercase letter")
		}
	}
	if policy.RequireDigit {
		hasDigit := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			violations = append(violations, "at least one digit")
		}
	}
	if policy.RequireSpecial {
		hasSpecial := false
		for _, r := range password {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			violations = append(violations, "at least one special character")
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("Password must contain: %s.", strings.Join(violations, ", "))
	}
	return nil
}

// --- Account Lockout ---

// RecordFailedLogin increments the failed login counter for a username
// and locks the account if the threshold is reached.
func (s *Service) RecordFailedLogin(username string) {
	maxAttempts := 5
	lockDuration := 15 // minutes

	if v, _ := s.GetSetting("lockout_attempts"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxAttempts = n
		}
	}
	if v, _ := s.GetSetting("lockout_duration"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lockDuration = n
		}
	}

	// lockout_attempts == 0 means lockout is disabled
	if maxAttempts == 0 {
		return
	}

	// Increment counter
	s.db.Exec(`UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?`, username)

	// Check if threshold reached
	var attempts int
	err := s.db.QueryRow(`SELECT failed_login_attempts FROM users WHERE username = ?`, username).Scan(&attempts)
	if err != nil {
		return
	}
	if attempts >= maxAttempts {
		lockUntil := time.Now().Add(time.Duration(lockDuration) * time.Minute)
		s.db.Exec(`UPDATE users SET locked_until = ? WHERE username = ?`, lockUntil, username)
	}
}

// ResetFailedLogins clears the failed login counter and lock for a user
func (s *Service) ResetFailedLogins(userID int64) {
	s.db.Exec(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`, userID)
}

// UnlockAccount clears the lock for a user (admin action)
func (s *Service) UnlockAccount(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, userID)
	return err
}

// --- Force Password Change ---

// SetMustChangePassword sets or clears the must_change_password flag
func (s *Service) SetMustChangePassword(userID int64, must bool) error {
	val := 0
	if must {
		val = 1
	}
	_, err := s.db.Exec(
		`UPDATE users SET must_change_password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		val, userID,
	)
	return err
}

// --- Last Login Tracking ---

// UpdateLastLogin records the current time as the user's last login
func (s *Service) UpdateLastLogin(userID int64) {
	s.db.Exec(`UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?`, userID)
}

// --- Invitation Tokens ---

// CreateInvitationToken generates a secure random token for a user invitation.
// The token expires after the given duration.
func (s *Service) CreateInvitationToken(userID int64, expiry time.Duration) (string, error) {
	// Generate a 32-byte random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(expiry)
	_, err := s.db.Exec(
		`INSERT INTO invitation_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`,
		userID, token, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("failed to store invitation token: %w", err)
	}
	return token, nil
}

// GetInvitationByToken retrieves a valid (unused, not expired) invitation.
func (s *Service) GetInvitationByToken(token string) (*models.InvitationToken, error) {
	inv := &models.InvitationToken{}
	err := s.db.QueryRow(
		`SELECT id, user_id, token, expires_at, used, created_at FROM invitation_tokens WHERE token = ?`,
		token,
	).Scan(&inv.ID, &inv.UserID, &inv.Token, &inv.ExpiresAt, &inv.Used, &inv.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invitation not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query invitation: %w", err)
	}
	return inv, nil
}

// CompleteInvitation sets the user's password and marks the invitation as used.
func (s *Service) CompleteInvitation(token string, newPassword string) (*models.User, error) {
	inv, err := s.GetInvitationByToken(token)
	if err != nil {
		return nil, err
	}
	if inv.Used {
		return nil, fmt.Errorf("invitation has already been used")
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, fmt.Errorf("invitation has expired")
	}

	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the user's password and clear must_change_password flag
	_, err = s.db.Exec(
		`UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(hash), inv.UserID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user password: %w", err)
	}

	// Mark the invitation as used
	_, err = s.db.Exec(`UPDATE invitation_tokens SET used = 1 WHERE id = ?`, inv.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark invitation as used: %w", err)
	}

	// Return the user
	return s.GetUserByID(inv.UserID)
}
