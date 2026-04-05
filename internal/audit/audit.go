// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"database/sql"
	"fmt"

	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
	"git.techniverse.net/scriptos/keywarden/internal/models"
)

// Action constants for audit logging
const (
	// Authentication
	ActionLoginSuccess = "login_success"
	ActionLoginFailed  = "login_failed"
	ActionLogout       = "logout"
	ActionMFASuccess   = "mfa_verified"
	ActionMFAFailed    = "mfa_failed"
	ActionMFAEnabled   = "mfa_enabled"
	ActionMFADisabled  = "mfa_disabled"

	// SSH Keys
	ActionKeyGenerated = "key_generated"
	ActionKeyImported  = "key_imported"
	ActionKeyDeleted   = "key_deleted"
	ActionKeyDownload  = "key_downloaded"

	// Servers
	ActionServerAdded   = "server_added"
	ActionServerUpdated = "server_updated"
	ActionServerDeleted = "server_deleted"
	ActionServerTest    = "server_test"
	ActionServerAuth    = "server_auth_test"

	// Server Groups
	ActionGroupCreated       = "group_created"
	ActionGroupUpdated       = "group_updated"
	ActionGroupDeleted       = "group_deleted"
	ActionGroupServerAdded   = "group_server_added"
	ActionGroupServerRemoved = "group_server_removed"
	ActionGroupDeploy        = "group_deploy"

	// Deployments
	ActionDeploySuccess = "deploy_success"
	ActionDeployFailed  = "deploy_failed"

	// User Management (admin)
	ActionUserCreated = "user_created"
	ActionUserUpdated = "user_updated"
	ActionUserDeleted = "user_deleted"

	// Settings
	ActionSettingsChanged      = "settings_changed"
	ActionPasswordChanged      = "password_changed"
	ActionMasterKeyRegen       = "masterkey_regenerated"
	ActionMasterKeyRegenerated = "masterkey_regenerated"
	ActionMasterKeyRegenFailed = "masterkey_regen_failed"
	ActionAvatarChanged        = "avatar_changed"

	// Email
	ActionEmailNotifyChanged = "email_notify_changed"
	ActionEmailTestSent      = "email_test_sent"
	ActionEmailTestFailed    = "email_test_failed"
	ActionEmailLoginSent     = "email_login_sent"
	ActionEmailLoginFailed   = "email_login_failed"

	// Access Assignments
	ActionAssignmentCreated     = "assignment_created"
	ActionAssignmentUpdated     = "assignment_updated"
	ActionAssignmentDeleted     = "assignment_deleted"
	ActionAssignmentSynced      = "assignment_synced"
	ActionAssignmentSyncFailed  = "assignment_sync_failed"
	ActionAssignmentKeyRemoved  = "assignment_key_removed"
	ActionAssignmentUserDeleted = "assignment_user_deleted"
	ActionAssignmentCleanFailed = "assignment_cleanup_failed"

	// Cron Jobs
	ActionCronJobCreated    = "cron_job_created"
	ActionCronJobUpdated    = "cron_job_updated"
	ActionCronJobDeleted    = "cron_job_deleted"
	ActionCronJobPaused     = "cron_job_paused"
	ActionCronJobResumed    = "cron_job_resumed"
	ActionCronJobExecuted   = "cron_job_executed"
	ActionCronJobFailed     = "cron_job_failed"
	ActionCronJobKeyRemoved = "cron_job_key_removed"

	// Account Security
	ActionAccountLocked         = "account_locked"
	ActionAccountUnlocked       = "account_unlocked"
	ActionForcePasswordChange   = "force_password_change"
	ActionMFAEnforced           = "mfa_enforced"
	ActionPasswordPolicyChanged = "password_policy_changed"

	// Backup & Restore
	ActionBackupExported     = "backup_exported"
	ActionBackupExportFailed = "backup_export_failed"
	ActionBackupImported     = "backup_imported"
	ActionBackupImportFailed = "backup_import_failed"

	// Invitations
	ActionInvitationSent       = "invitation_sent"
	ActionInvitationSendFailed = "invitation_send_failed"
	ActionInvitationAccepted   = "invitation_accepted"
	ActionInvitationFailed     = "invitation_failed"
)

// AuditEntry extends AuditLog with the username for display
type AuditEntry struct {
	models.AuditLog
	Username string
}

// Service handles audit log operations
type Service struct {
	db *database.DB
}

// NewService creates a new audit service
func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Log records an audit event. Errors are logged but never returned to avoid
// disrupting the main application flow.
func (s *Service) Log(userID int64, action, details, ipAddress string) {
	var uid interface{}
	if userID == 0 {
		uid = sql.NullInt64{Valid: false}
	} else {
		uid = userID
	}

	logging.Debug("Audit: action=%s user_id=%d ip=%s details=%s", action, userID, ipAddress, details)

	_, err := s.db.Exec(
		`INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)`,
		uid, action, details, ipAddress,
	)
	if err != nil {
		logging.Warn("Failed to write audit log: %v", err)
	}
}

// GetAll returns paginated audit entries for all users (admin view).
// Returns entries, total count, and error.
func (s *Service) GetAll(page, perPage int) ([]AuditEntry, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.db.Query(
		`SELECT a.id, COALESCE(a.user_id, 0), COALESCE(u.username, '(system)') AS username,
		        a.action, COALESCE(a.details, ''), COALESCE(a.ip_address, ''),
		        a.created_at
		 FROM audit_log a
		 LEFT JOIN users u ON u.id = a.user_id
		 ORDER BY a.created_at DESC
		 LIMIT ? OFFSET ?`,
		perPage, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}

// GetAllExceptOwners returns paginated audit entries excluding entries from
// users with the "owner" role. This is the admin view.
func (s *Service) GetAllExceptOwners(page, perPage int) ([]AuditEntry, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	var total int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM audit_log a
		 LEFT JOIN users u ON u.id = a.user_id
		 WHERE u.role IS NULL OR u.role != 'owner'`,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.db.Query(
		`SELECT a.id, COALESCE(a.user_id, 0), COALESCE(u.username, '(system)') AS username,
		        a.action, COALESCE(a.details, ''), COALESCE(a.ip_address, ''),
		        a.created_at
		 FROM audit_log a
		 LEFT JOIN users u ON u.id = a.user_id
		 WHERE u.role IS NULL OR u.role != 'owner'
		 ORDER BY a.created_at DESC
		 LIMIT ? OFFSET ?`,
		perPage, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}

// GetByUser returns paginated audit entries for a specific user.
func (s *Service) GetByUser(userID int64, page, perPage int) ([]AuditEntry, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE user_id = ?`, userID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.db.Query(
		`SELECT a.id, COALESCE(a.user_id, 0), COALESCE(u.username, '(deleted)') AS username,
		        a.action, COALESCE(a.details, ''), COALESCE(a.ip_address, ''),
		        a.created_at
		 FROM audit_log a
		 LEFT JOIN users u ON u.id = a.user_id
		 WHERE a.user_id = ?
		 ORDER BY a.created_at DESC
		 LIMIT ? OFFSET ?`,
		userID, perPage, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}
