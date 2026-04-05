// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// User represents a registered user
type User struct {
	ID                  int64      `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	PasswordHash        string     `json:"-"`
	Role                string     `json:"role"`
	MFAEnabled          bool       `json:"mfa_enabled"`
	MFASecret           string     `json:"-"`
	Theme               string     `json:"theme"` // "auto", "light", "dark"
	EmailNotifyLogin    bool       `json:"email_notify_login"`
	AvatarBase64        string     `json:"avatar_base64"`         // base64-encoded profile picture (data URI)
	MustChangePassword  bool       `json:"must_change_password"`  // force password change on next login
	FailedLoginAttempts int        `json:"failed_login_attempts"` // consecutive failed login attempts
	LockedUntil         *time.Time `json:"locked_until"`          // account locked until this time
	LastLoginAt         *time.Time `json:"last_login_at"`         // last successful login
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// PasswordPolicy holds the password complexity requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigit   bool `json:"require_digit"`
	RequireSpecial bool `json:"require_special"`
}

// SSHKey represents a stored SSH key pair
type SSHKey struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id"`
	Name          string    `json:"name"`
	KeyType       string    `json:"key_type"` // "rsa", "ed25519", or "ed448"
	Bits          int       `json:"bits"`     // 2048, 4096 for RSA; 256 for Ed25519; 456 for Ed448
	Fingerprint   string    `json:"fingerprint"`
	PublicKey     string    `json:"public_key"`
	PrivateKeyEnc string    `json:"-"` // encrypted private key
	PassphraseEnc string    `json:"-"` // encrypted passphrase (optional)
	CreatedAt     time.Time `json:"created_at"`
}

// SSHKeyWithOwner extends SSHKey with the owner's username for admin views
type SSHKeyWithOwner struct {
	SSHKey
	OwnerUsername string `json:"owner_username"`
}

// Server represents a remote SSH server
type Server struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	Name        string    `json:"name"`
	Hostname    string    `json:"hostname"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// KeyDeployment represents a key deployed to a server
type KeyDeployment struct {
	ID         int64     `json:"id"`
	SSHKeyID   int64     `json:"ssh_key_id"`
	ServerID   int64     `json:"server_id"`
	DeployedAt time.Time `json:"deployed_at"`
	Status     string    `json:"status"` // "pending", "success", "failed"
	Message    string    `json:"message"`
}

// ServerGroup represents a group of servers
type ServerGroup struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ServerGroupWithCount extends ServerGroup with the number of member servers
type ServerGroupWithCount struct {
	ServerGroup
	ServerCount int `json:"server_count"`
}

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
}

// CronJob represents a scheduled temporary access job
type CronJob struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	Name            string     `json:"name"`
	SSHKeyID        int64      `json:"ssh_key_id"`
	ServerID        int64      `json:"server_id"` // 0 if targeting a group
	GroupID         int64      `json:"group_id"`  // 0 if targeting a single server
	Schedule        string     `json:"schedule"`  // "once", "hourly", "daily", "weekly", "monthly"
	ScheduledAt     time.Time  `json:"scheduled_at"`
	NextRun         time.Time  `json:"next_run"`
	LastRun         *time.Time `json:"last_run"`
	RemoveAfterMin  int        `json:"remove_after_min"` // 0 = permanent
	Status          string     `json:"status"`           // "active", "paused", "running", "done", "failed"
	Message         string     `json:"message"`
	Timezone        string     `json:"timezone"`         // IANA timezone, e.g. "Europe/Berlin"
	TimeOfDay       string     `json:"time_of_day"`      // "HH:MM" for daily/weekly/monthly
	DayOfWeek       int        `json:"day_of_week"`      // 0=Sunday..6=Saturday (-1=unset)
	DayOfMonth      int        `json:"day_of_month"`     // 1-31 (0=unset)
	MinuteOfHour    int        `json:"minute_of_hour"`   // 0-59 for hourly schedule
	TargetUserID    int64      `json:"target_user_id"`   // KeyWarden user to grant access
	SystemUser      string     `json:"system_user"`      // system user on target host
	Sudo            bool       `json:"sudo"`             // grant sudo rights
	CreateUser      bool       `json:"create_user"`      // create system user if missing
	InitialPassword string     `json:"initial_password"` // encrypted initial password for created user
	ExpiryAction    string     `json:"expiry_action"`    // "remove_key", "disable_user", "delete_user"
	CreatedAt       time.Time  `json:"created_at"`
}

// CronJobDisplay extends CronJob with resolved names for UI display
type CronJobDisplay struct {
	CronJob
	KeyName        string `json:"key_name"`
	TargetName     string `json:"target_name"`
	TargetType     string `json:"target_type"`     // "host" or "group"
	TargetUsername string `json:"target_username"` // KeyWarden username
}

// AccessAssignment represents an access assignment (user+key → host/group)
type AccessAssignment struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`          // Keywarden user
	SSHKeyID        int64      `json:"ssh_key_id"`       // SSH key to deploy
	ServerID        int64      `json:"server_id"`        // target host (0 if group)
	GroupID         int64      `json:"group_id"`         // target group (0 if single host)
	SystemUser      string     `json:"system_user"`      // system user on target host
	DesiredState    string     `json:"desired_state"`    // "present" or "absent"
	Sudo            bool       `json:"sudo"`             // grant sudo rights
	CreateUser      bool       `json:"create_user"`      // create system user if missing
	InitialPassword string     `json:"initial_password"` // encrypted initial password for created user
	Status          string     `json:"status"`           // "pending", "synced", "failed"
	LastSyncAt      *time.Time `json:"last_sync_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AccessAssignmentDisplay extends AccessAssignment with resolved names for UI
type AccessAssignmentDisplay struct {
	AccessAssignment
	Username   string `json:"username"`
	KeyName    string `json:"key_name"`
	TargetName string `json:"target_name"`
	TargetType string `json:"target_type"` // "host" or "group"
}

// InvitationToken represents a one-time invitation link for a new user
type InvitationToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}
