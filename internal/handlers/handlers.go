// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.techniverse.net/scriptos/keywarden/internal/audit"
	"git.techniverse.net/scriptos/keywarden/internal/auth"
	"git.techniverse.net/scriptos/keywarden/internal/cron"
	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/deploy"
	"git.techniverse.net/scriptos/keywarden/internal/keys"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
	"git.techniverse.net/scriptos/keywarden/internal/mail"
	"git.techniverse.net/scriptos/keywarden/internal/models"
	"git.techniverse.net/scriptos/keywarden/internal/security"
	"git.techniverse.net/scriptos/keywarden/internal/servers"
)

// sessionData holds session metadata for timeout tracking
type sessionData struct {
	UserID           int64
	LastActive       time.Time
	MFASetupRequired bool // set at login when admin enforces MFA but user hasn't configured it
}

// Handler holds all dependencies for HTTP handlers
type Handler struct {
	auth          *auth.Service
	keys          *keys.Service
	servers       *servers.Service
	deploy        *deploy.Service
	audit         *audit.Service
	cron          *cron.Service
	mail          *mail.Service
	db            *database.DB // direct database access for backup/restore
	templates     map[string]*template.Template
	sessions      map[string]*sessionData // cookie -> session data with timeout tracking
	mu            sync.RWMutex            // protects sessions and pending maps
	pending       map[string]int64        // pending MFA sessions: cookie -> userID
	staticFS      http.Handler            // serves embedded static assets
	dataDir       string                  // persistent data directory for avatars etc.
	secureCookies bool                    // set Secure flag on cookies (HTTPS mode)
	baseURL       string                  // external base URL for links in emails
}

// Flash represents a flash message
type Flash struct {
	Type    string // "success", "danger", "warning"
	Message string
}

// PageData is passed to every template
type PageData struct {
	Title  string
	Active string
	User   interface{}
	Flash  *Flash
	Data   interface{}

	// Dashboard specific
	KeyCount        int
	ServerCount     int
	DeployCount     int
	UserCount       int
	GroupCount      int
	AssignmentCount int
	RecentKeys      interface{}
	RecentDeploys   interface{}
	RecentAudit     []audit.AuditEntry
	UserRole        string

	// Keys
	Keys interface{}
	Key  interface{}

	// Servers
	Servers interface{}
	Server  interface{}

	// Server Groups
	Groups       interface{}
	Group        interface{}
	GroupServers interface{}
	AllServers   interface{}

	// Deploy
	Deployments interface{}

	// User management
	Users    []models.User
	EditUser *models.User

	// Settings
	Settings map[string]string

	// MFA
	MFASecret string
	MFAUri    string

	// Admin Settings: user list
	AdminUsers []AdminUserInfo

	// Audit Log
	AuditEntries    []audit.AuditEntry
	AuditTotal      int
	AuditPage       int
	AuditTotalPages int
	AuditPrevPage   int
	AuditNextPage   int
	AuditIsAdmin    bool
	AuditFilterUser bool

	// Cron Jobs
	CronJobs    []models.CronJobDisplay
	CronJob     *models.CronJob
	CronCount   int
	DaysOfMonth []int

	// Access Assignments
	Assignments     []models.AccessAssignmentDisplay
	Assignment      *models.AccessAssignment
	AssignAllUsers  []models.User
	AssignAllKeys   []models.SSHKey
	AssignAllHosts  []models.Server
	AssignAllGroups []models.ServerGroupWithCount

	// Error (login page)
	Error      string
	MFAPending bool
	MFAToken   string

	// Email
	EmailEnabled bool

	// Password Policy
	PasswordPolicy *models.PasswordPolicy

	// MFA enforcement
	MFARequired bool

	// System Master Key
	MasterKeyPublic      string
	MasterKeyFingerprint string

	// System Information
	SystemInfo *SystemInfo
}

// SystemInfo holds runtime system information for the settings page
type SystemInfo struct {
	GoVersion    string
	OS           string
	Arch         string
	NumCPU       int
	NumGoroutine int
	MemAlloc     string
	MemSys       string
	Runtime      string // e.g. "Docker" or "Native"
	Hostname     string
	Uptime       string
}

// AdminUserInfo holds user info for the admin settings page
type AdminUserInfo struct {
	ID       int64
	Username string
	Role     string
}

// GroupOption represents a group option for server add/edit forms
type GroupOption struct {
	ID          int64
	Name        string
	Description string
	Selected    bool
}

// startTime records when the application started
var startTime = time.Now()

// daysOfMonth returns a slice [1..31] for template dropdowns
func daysOfMonth() []int {
	days := make([]int, 31)
	for i := range days {
		days[i] = i + 1
	}
	return days
}

// formatBytes converts bytes to a human-readable string
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), []string{"KB", "MB", "GB", "TB"}[exp])
}

// formatUptime returns a human-readable uptime string
func formatUptime(start time.Time) string {
	d := time.Since(start)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// New creates a new Handler
func New(authSvc *auth.Service, keysSvc *keys.Service, serversSvc *servers.Service, deploySvc *deploy.Service, auditSvc *audit.Service, cronSvc *cron.Service, mailSvc *mail.Service, db *database.DB, templateFS embed.FS, staticFS embed.FS, dataDir string, secureCookies bool, baseURL string) *Handler {
	// Create sub-FS so /static/css/... maps to static/css/... in embed
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		logging.Fatal("Failed to create static sub-FS: %v", err)
	}

	// Ensure avatars directory exists
	avatarsDir := filepath.Join(dataDir, "avatars")
	if err := os.MkdirAll(avatarsDir, 0700); err != nil {
		logging.Warn("Failed to create avatars directory %s: %v", avatarsDir, err)
	}

	h := &Handler{
		auth:          authSvc,
		keys:          keysSvc,
		servers:       serversSvc,
		deploy:        deploySvc,
		audit:         auditSvc,
		cron:          cronSvc,
		mail:          mailSvc,
		db:            db,
		sessions:      make(map[string]*sessionData),
		pending:       make(map[string]int64),
		staticFS:      http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))),
		dataDir:       dataDir,
		secureCookies: secureCookies,
		baseURL:       baseURL,
	}

	h.loadTemplates(templateFS)

	// Migrate any legacy base64 avatars to file-based storage
	h.migrateAvatarsToFiles()

	return h
}

func (h *Handler) loadTemplates(templateFS embed.FS) {
	h.templates = make(map[string]*template.Template)

	// Template functions available in all templates
	funcMap := template.FuncMap{
		"appName": func() string {
			name, _ := h.auth.GetSetting("app_name")
			if name == "" {
				return "Keywarden"
			}
			return name
		},
	}

	baseLayout, err := fs.ReadFile(templateFS, "templates/layout/base.html")
	if err != nil {
		logging.Fatal("Failed to read base layout: %v", err)
	}

	pages := []string{
		"dashboard", "keys", "keys_generate", "keys_import", "servers", "servers_add", "servers_edit",
		"server_groups", "server_groups_add", "server_groups_edit",
		"deploy", "audit", "users", "users_add", "users_edit", "settings", "mfa_setup",
		"admin_settings", "system_info",
		"cron", "cron_add", "cron_edit",
		"assignments", "assignments_add", "assignments_edit",
	}
	for _, page := range pages {
		pageContent, err := fs.ReadFile(templateFS, "templates/"+page+".html")
		if err != nil {
			logging.Fatal("Failed to read template %s: %v", page, err)
		}
		tmpl, err := template.New("base").Funcs(funcMap).Parse(string(baseLayout))
		if err != nil {
			logging.Fatal("Failed to parse base for %s: %v", page, err)
		}
		tmpl, err = tmpl.Parse(string(pageContent))
		if err != nil {
			logging.Fatal("Failed to parse page %s: %v", page, err)
		}
		h.templates[page] = tmpl
	}

	// Login has its own layout
	loginContent, err := fs.ReadFile(templateFS, "templates/login.html")
	if err != nil {
		logging.Fatal("Failed to read login template: %v", err)
	}
	loginTmpl, err := template.New("login").Funcs(funcMap).Parse(string(loginContent))
	if err != nil {
		logging.Fatal("Failed to parse login: %v", err)
	}
	h.templates["login"] = loginTmpl

	// Force password change page has its own layout (standalone, no sidebar)
	fpcContent, err := fs.ReadFile(templateFS, "templates/force_password_change.html")
	if err != nil {
		logging.Fatal("Failed to read force_password_change template: %v", err)
	}
	fpcTmpl, err := template.New("force_password_change").Funcs(funcMap).Parse(string(fpcContent))
	if err != nil {
		logging.Fatal("Failed to parse force_password_change: %v", err)
	}
	h.templates["force_password_change"] = fpcTmpl

	// MFA required page has its own layout (standalone, no sidebar)
	mfaReqContent, err := fs.ReadFile(templateFS, "templates/mfa_required.html")
	if err != nil {
		logging.Fatal("Failed to read mfa_required template: %v", err)
	}
	mfaReqTmpl, err := template.New("mfa_required").Funcs(funcMap).Parse(string(mfaReqContent))
	if err != nil {
		logging.Fatal("Failed to parse mfa_required: %v", err)
	}
	h.templates["mfa_required"] = mfaReqTmpl

	// Invitation acceptance page has its own layout (standalone, no sidebar)
	inviteContent, err := fs.ReadFile(templateFS, "templates/invite_accept.html")
	if err != nil {
		logging.Fatal("Failed to read invite_accept template: %v", err)
	}
	inviteTmpl, err := template.New("invite_accept").Funcs(funcMap).Parse(string(inviteContent))
	if err != nil {
		logging.Fatal("Failed to parse invite_accept: %v", err)
	}
	h.templates["invite_accept"] = inviteTmpl
}

// RegisterRoutes sets up all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Static assets (CSS, JS, fonts) – served with long cache headers
	mux.HandleFunc("/static/", h.handleStatic)

	// Public routes
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/login/mfa", h.handleLoginMFA)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc("/invite/", h.handleInviteAccept)

	// MFA enforcement (requires auth but shown without sidebar)
	mux.HandleFunc("/mfa/setup", h.requireAuth(h.handleMFAEnforce))

	// Protected routes (all authenticated users)
	mux.HandleFunc("/", h.requireAuth(h.handleRoot))
	mux.HandleFunc("/dashboard", h.requireAuth(h.handleDashboard))
	mux.HandleFunc("/password/change", h.requireAuth(h.handleForcePasswordChange))
	mux.HandleFunc("/keys", h.requireAuth(h.handleKeys))
	mux.HandleFunc("/keys/generate", h.requireAuth(h.handleKeysGenerate))
	mux.HandleFunc("/keys/import", h.requireAuth(h.handleKeysImport))
	mux.HandleFunc("/keys/", h.requireAuth(h.handleKeyAction))
	mux.HandleFunc("/settings", h.requireAuth(h.handleSettings))
	mux.HandleFunc("/settings/theme", h.requireAuth(h.handleThemeChange))
	mux.HandleFunc("/settings/mfa/setup", h.requireAuth(h.handleMFASetup))
	mux.HandleFunc("/settings/mfa/disable", h.requireAuth(h.handleMFADisable))
	mux.HandleFunc("/settings/email/notify", h.requireAuth(h.handleEmailNotifyToggle))
	mux.HandleFunc("/settings/avatar", h.requireAuth(h.handleAvatarUpload))
	mux.HandleFunc("/avatar/", h.requireAuth(h.handleAvatarServe))
	mux.HandleFunc("/audit", h.requireAuth(h.handleAudit))
	mux.HandleFunc("/my/access", h.requireAuth(h.handleMyAssignments))

	// Admin-only routes (admin + owner)
	mux.HandleFunc("/servers", h.requireAdmin(h.handleServers))
	mux.HandleFunc("/servers/add", h.requireAdmin(h.handleServersAdd))
	mux.HandleFunc("/servers/test", h.requireAdmin(h.handleServerTest))
	mux.HandleFunc("/servers/test-auth", h.requireAdmin(h.handleServerTestAuth))
	mux.HandleFunc("/servers/", h.requireAdmin(h.handleServerAction))
	mux.HandleFunc("/groups", h.requireAdmin(h.handleServerGroups))
	mux.HandleFunc("/groups/add", h.requireAdmin(h.handleServerGroupsAdd))
	mux.HandleFunc("/groups/", h.requireAdmin(h.handleServerGroupAction))
	mux.HandleFunc("/deploy", h.requireAdmin(h.handleDeploy))
	mux.HandleFunc("/deploy/group", h.requireAdmin(h.handleDeployGroup))
	mux.HandleFunc("/cron", h.requireAdmin(h.handleCron))
	mux.HandleFunc("/cron/add", h.requireAdmin(h.handleCronAdd))
	mux.HandleFunc("/cron/", h.requireAdmin(h.handleCronAction))
	mux.HandleFunc("/users", h.requireAdmin(h.handleUsers))
	mux.HandleFunc("/users/add", h.requireAdmin(h.handleUsersAdd))
	mux.HandleFunc("/users/", h.requireAdmin(h.handleUserAction))
	mux.HandleFunc("/assignments", h.requireAdmin(h.handleAssignments))
	mux.HandleFunc("/assignments/add", h.requireAdmin(h.handleAssignmentsAdd))
	mux.HandleFunc("/assignments/", h.requireAdmin(h.handleAssignmentAction))
	mux.HandleFunc("/system", h.requireAdmin(h.handleSystemInfo))
	mux.HandleFunc("/admin/settings/email/test", h.requireOwner(h.handleAdminEmailTest))

	// API endpoints (JSON)
	mux.HandleFunc("/api/health", h.handleAPIHealth)
	mux.HandleFunc("/api/cron/keys", h.requireAdmin(h.handleAPICronKeys))

	// Owner-only routes
	mux.HandleFunc("/admin/settings", h.requireOwner(h.handleAdminSettings))
	mux.HandleFunc("/admin/masterkey/regenerate", h.requireOwner(h.handleMasterKeyRegenerate))
	mux.HandleFunc("/admin/backup/export", h.requireOwner(h.handleBackupExport))
	mux.HandleFunc("/admin/backup/import", h.requireOwner(h.handleBackupImport))
}

// handleAPIHealth returns a JSON health status (no auth required).
// Used by Docker HEALTHCHECK and external monitoring.
func (h *Handler) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check database connectivity
	dbOK := true
	if err := h.db.Ping(); err != nil {
		dbOK = false
	}

	status := "healthy"
	httpCode := http.StatusOK
	if !dbOK {
		status = "unhealthy"
		httpCode = http.StatusServiceUnavailable
	}

	uptime := time.Since(startTime)

	result := map[string]interface{}{
		"status":         status,
		"uptime":         formatUptime(startTime),
		"uptime_seconds": int(uptime.Seconds()),
		"checks": map[string]interface{}{
			"database": map[string]interface{}{
				"status": boolToStatus(dbOK),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(result)
}

// boolToStatus converts a boolean to "ok" / "fail".
func boolToStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

// getSessionTimeout returns the configured session timeout duration.
// Falls back to 60 minutes if not configured or invalid.
func (h *Handler) getSessionTimeout() time.Duration {
	val, err := h.auth.GetSetting("session_timeout")
	if err != nil || val == "" {
		return 60 * time.Minute
	}
	minutes, err := strconv.Atoi(val)
	if err != nil || minutes < 1 {
		return 60 * time.Minute
	}
	return time.Duration(minutes) * time.Minute
}

// StartSessionCleanup starts a background goroutine that periodically
// removes expired sessions from the in-memory map.
func (h *Handler) StartSessionCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			timeout := h.getSessionTimeout()
			now := time.Now()
			h.mu.Lock()
			for token, sess := range h.sessions {
				if now.Sub(sess.LastActive) > timeout {
					logging.Debug("Session expired for user ID %d (inactive for %v)", sess.UserID, now.Sub(sess.LastActive).Round(time.Second))
					delete(h.sessions, token)
				}
			}
			h.mu.Unlock()
		}
	}()
}

// Middleware: require authentication
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("keywarden_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		h.mu.RLock()
		sess, ok := h.sessions[cookie.Value]
		h.mu.RUnlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check session timeout (inactivity based)
		timeout := h.getSessionTimeout()
		if time.Since(sess.LastActive) > timeout {
			h.mu.Lock()
			delete(h.sessions, cookie.Value)
			h.mu.Unlock()
			logging.Info("Session expired for user ID %d due to inactivity (%v timeout)", sess.UserID, timeout)
			http.SetCookie(w, &http.Cookie{
				Name:   "keywarden_session",
				Value:  "",
				Path:   "/",
				Secure: h.secureCookies,
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Update last activity (sliding window)
		h.mu.Lock()
		sess.LastActive = time.Now()
		h.mu.Unlock()

		// Refresh cookie expiry (sliding cookie) so the browser keeps
		// the cookie alive as long as the user is active.
		http.SetCookie(w, &http.Cookie{
			Name:     "keywarden_session",
			Value:    cookie.Value,
			Path:     "/",
			HttpOnly: true,
			Secure:   h.secureCookies,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(timeout.Seconds()),
		})

		user, err := h.auth.GetUserByID(sess.UserID)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Store user in request context via header (simple approach)
		r.Header.Set("X-User-ID", strconv.FormatInt(user.ID, 10))
		r.Header.Set("X-User-Name", user.Username)
		r.Header.Set("X-User-Role", user.Role)

		// Force password change: redirect to /password/change unless already there
		if user.MustChangePassword && r.URL.Path != "/password/change" {
			http.Redirect(w, r, "/password/change", http.StatusSeeOther)
			return
		}

		// MFA enforcement: only redirect if the session was flagged at login time
		// This ensures already-logged-in users are not disrupted; enforcement
		// takes effect on the next login.
		if !user.MustChangePassword && sess.MFASetupRequired {
			// If the user has since enabled MFA, clear the flag
			if user.MFAEnabled {
				h.mu.Lock()
				sess.MFASetupRequired = false
				h.mu.Unlock()
			} else if r.URL.Path != "/mfa/setup" &&
				!(user.Role == "owner" && strings.HasPrefix(r.URL.Path, "/admin/")) {
				http.Redirect(w, r, "/mfa/setup", http.StatusSeeOther)
				return
			}
		}

		next(w, r)
	}
}

// handleStatic serves embedded static assets with cache headers
func (h *Handler) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Cache static assets for 1 year (immutable – version pinned in filenames)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	h.staticFS.ServeHTTP(w, r)
}

// Middleware: require admin or owner role
func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		if role != "admin" && role != "owner" {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// Middleware: require owner role exclusively
func (h *Handler) requireOwner(next http.HandlerFunc) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		if role != "owner" {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// isAdmin returns true if the role is admin or owner
func isAdmin(role string) bool {
	return role == "admin" || role == "owner"
}

// isOwner returns true if the role is owner
func isOwner(role string) bool {
	return role == "owner"
}

func (h *Handler) getUserID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
	return id
}

// clientIP delegates to the security package for trusted-proxy-aware IP extraction.
func clientIP(r *http.Request) string {
	return security.ClientIP(r)
}

// GetUserName returns the username from the request (for request logging middleware).
// Returns empty string if no user is authenticated.
func (h *Handler) GetUserName(r *http.Request) string {
	return r.Header.Get("X-User-Name")
}

// --- Route Handlers ---

func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.templates["login"].Execute(w, &PageData{})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.auth.Login(username, password)
	if err != nil {
		if err == auth.ErrAccountLocked {
			logging.Warn("Login blocked for locked account '%s' from IP %s", username, clientIP(r))
			h.audit.Log(0, audit.ActionLoginFailed, fmt.Sprintf("Login attempt for locked account: %s", username), clientIP(r))
			h.templates["login"].Execute(w, &PageData{Error: "Account is temporarily locked due to too many failed attempts. Please try again later."})
			return
		}
		logging.Warn("Login failed for user '%s' from IP %s: %v", username, clientIP(r), err)
		h.audit.Log(0, audit.ActionLoginFailed, fmt.Sprintf("Failed login attempt for user: %s", username), clientIP(r))

		// Record failed login and potentially lock the account
		h.auth.RecordFailedLogin(username)

		h.templates["login"].Execute(w, &PageData{Error: "Invalid username or password"})
		return
	}

	// Successful login – reset lockout counter and track last login
	h.auth.ResetFailedLogins(user.ID)
	h.auth.UpdateLastLogin(user.ID)

	// Check if MFA is enabled
	if user.MFAEnabled && user.MFASecret != "" {
		// Create a pending MFA session
		logging.Info("Login for user '%s' from IP %s – MFA verification pending", user.Username, clientIP(r))
		token := generateSessionID()
		h.mu.Lock()
		h.pending[token] = user.ID
		h.mu.Unlock()
		h.templates["login"].Execute(w, &PageData{MFAPending: true, MFAToken: token})
		return
	}

	// Create session directly
	sessionID := generateSessionID()
	timeout := h.getSessionTimeout()

	// Check if MFA is required by admin but user hasn't set it up
	mfaRequired, _ := h.auth.GetSetting("mfa_required")
	needsMFASetup := mfaRequired == "true" && !user.MFAEnabled

	h.mu.Lock()
	h.sessions[sessionID] = &sessionData{UserID: user.ID, LastActive: time.Now(), MFASetupRequired: needsMFASetup}
	h.mu.Unlock()

	logging.Info("Login successful for user '%s' from IP %s", user.Username, clientIP(r))
	h.audit.Log(user.ID, audit.ActionLoginSuccess, fmt.Sprintf("User %s logged in", user.Username), clientIP(r))

	// Send login notification email (async)
	h.sendLoginNotification(user, r)

	http.SetCookie(w, &http.Cookie{
		Name:     "keywarden_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(timeout.Seconds()),
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	token := r.FormValue("mfa_token")
	code := r.FormValue("mfa_code")

	h.mu.RLock()
	userID, ok := h.pending[token]
	h.mu.RUnlock()
	if !ok {
		h.templates["login"].Execute(w, &PageData{Error: "MFA session expired. Please login again."})
		return
	}

	user, err := h.auth.GetUserByID(userID)
	if err != nil {
		h.templates["login"].Execute(w, &PageData{Error: "User not found."})
		return
	}

	// Validate TOTP code
	if !validateTOTP(user.MFASecret, code) {
		logging.Warn("MFA verification failed for user '%s' from IP %s", user.Username, clientIP(r))
		h.audit.Log(user.ID, audit.ActionMFAFailed, fmt.Sprintf("Failed MFA attempt for user: %s", user.Username), clientIP(r))
		h.templates["login"].Execute(w, &PageData{MFAPending: true, MFAToken: token, Error: "Invalid MFA code. Please try again."})
		return
	}

	// MFA verified, create session
	h.mu.Lock()
	delete(h.pending, token)
	h.mu.Unlock()

	// Track last login after MFA verification
	h.auth.UpdateLastLogin(user.ID)

	sessionID := generateSessionID()
	timeout := h.getSessionTimeout()
	h.mu.Lock()
	h.sessions[sessionID] = &sessionData{UserID: user.ID, LastActive: time.Now()}
	h.mu.Unlock()

	logging.Info("Login successful for user '%s' from IP %s (MFA verified)", user.Username, clientIP(r))
	h.audit.Log(user.ID, audit.ActionLoginSuccess, fmt.Sprintf("User %s logged in (MFA verified)", user.Username), clientIP(r))

	// Send login notification email (async)
	h.sendLoginNotification(user, r)

	http.SetCookie(w, &http.Cookie{
		Name:     "keywarden_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(timeout.Seconds()),
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("keywarden_session")
	if err == nil {
		h.mu.Lock()
		if sess, ok := h.sessions[cookie.Value]; ok {
			if u, uErr := h.auth.GetUserByID(sess.UserID); uErr == nil {
				logging.Info("User '%s' logged out from IP %s", u.Username, clientIP(r))
			}
			h.audit.Log(sess.UserID, audit.ActionLogout, "User logged out", clientIP(r))
		}
		delete(h.sessions, cookie.Value)
		h.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "keywarden_session",
		Value:  "",
		Path:   "/",
		Secure: h.secureCookies,
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	role := r.Header.Get("X-User-Role")
	deployments, _ := h.deploy.GetDeployments(userID)
	cronCount := h.cron.CountByUser(userID)

	var keyCount, serverCount, groupCount, assignmentCount, userCount int
	var recentKeys interface{}
	var recentAudit []audit.AuditEntry

	if isAdmin(role) {
		allKeys, _ := h.keys.GetAllKeys()
		allServers, _ := h.servers.GetAllServers()
		allGroups, _ := h.servers.GetAllGroups()
		allAssignments, _ := h.servers.GetAllAssignments()
		allUsers, _ := h.auth.GetAllUsers()
		keyCount = len(allKeys)
		serverCount = len(allServers)
		groupCount = len(allGroups)
		assignmentCount = len(allAssignments)
		userCount = len(allUsers)
		recentKeys = allKeys
		entries, _, _ := h.audit.GetAll(1, 5)
		recentAudit = entries
	} else {
		keyList, _ := h.keys.GetKeysByUser(userID)
		userServers, _ := h.servers.GetByUser(userID)
		userGroups, _ := h.servers.GetGroupsByUser(userID)
		userAssignments, _ := h.servers.GetAssignmentsByUser(userID)
		keyCount = len(keyList)
		serverCount = len(userServers)
		groupCount = len(userGroups)
		assignmentCount = len(userAssignments)
		recentKeys = keyList
		entries, _, _ := h.audit.GetByUser(userID, 1, 5)
		recentAudit = entries
	}

	data := &PageData{
		Title:           "Dashboard",
		Active:          "dashboard",
		User:            user,
		UserRole:        role,
		KeyCount:        keyCount,
		ServerCount:     serverCount,
		DeployCount:     len(deployments),
		CronCount:       cronCount,
		UserCount:       userCount,
		GroupCount:      groupCount,
		AssignmentCount: assignmentCount,
		RecentKeys:      recentKeys,
		RecentDeploys:   deployments,
		RecentAudit:     recentAudit,
	}

	h.templates["dashboard"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	role := r.Header.Get("X-User-Role")

	data := &PageData{
		Title:  "SSH Keys",
		Active: "keys",
		User:   user,
	}

	// Admin/Owner see all keys with owner info; User sees only own keys
	if isAdmin(role) {
		allKeys, _ := h.keys.GetAllKeysWithOwner()
		data.Data = allKeys
		data.Keys = allKeys
	} else {
		keyList, _ := h.keys.GetKeysByUser(userID)
		data.Keys = keyList
	}

	h.templates["keys"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleKeysGenerate(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	role := r.Header.Get("X-User-Role")

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:  "Generate SSH Key",
			Active: "keys",
			User:   user,
		}
		// Admin/Owner can generate keys for other users
		if isAdmin(role) {
			allUsers, _ := h.auth.GetAllUsers()
			data.Users = allUsers
		}
		h.templates["keys_generate"].ExecuteTemplate(w, "base", data)
		return
	}

	name := r.FormValue("name")
	keyType := r.FormValue("key_type")
	comment := r.FormValue("comment")
	bits := 4096
	if b := r.FormValue("bits"); b != "" {
		bits, _ = strconv.Atoi(b)
	}

	// Admin/Owner can generate keys for a selected user
	targetUserID := userID
	if isAdmin(role) {
		if tid := r.FormValue("target_user_id"); tid != "" {
			if parsed, err := strconv.ParseInt(tid, 10, 64); err == nil && parsed > 0 {
				targetUserID = parsed
			}
		}
	}

	_, err := h.keys.GenerateKey(targetUserID, name, keyType, bits, comment)
	if err != nil {
		logging.Warn("Key generation failed for user %d: %v", targetUserID, err)
		data := &PageData{
			Title:  "Generate SSH Key",
			Active: "keys",
			User:   user,
			Flash:  &Flash{Type: "danger", Message: "Failed to generate key: " + err.Error()},
		}
		if isAdmin(role) {
			allUsers, _ := h.auth.GetAllUsers()
			data.Users = allUsers
		}
		h.templates["keys_generate"].ExecuteTemplate(w, "base", data)
		return
	}

	if targetUserID != userID {
		targetUser, _ := h.auth.GetUserByID(targetUserID)
		targetName := fmt.Sprintf("user_id=%d", targetUserID)
		if targetUser != nil {
			targetName = targetUser.Username
		}
		logging.Info("SSH key generated: type=%s name='%s' bits=%d for user '%s' by admin user_id=%d", keyType, name, bits, targetName, userID)
		h.audit.Log(userID, audit.ActionKeyGenerated, fmt.Sprintf("Generated %s key: %s (%d bits) for user %s", keyType, name, bits, targetName), clientIP(r))
	} else {
		logging.Info("SSH key generated: type=%s name='%s' bits=%d user_id=%d", keyType, name, bits, userID)
		h.audit.Log(userID, audit.ActionKeyGenerated, fmt.Sprintf("Generated %s key: %s (%d bits)", keyType, name, bits), clientIP(r))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (h *Handler) handleKeysImport(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	role := r.Header.Get("X-User-Role")

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:  "Import SSH Key",
			Active: "keys",
			User:   user,
		}
		if isAdmin(role) {
			allUsers, _ := h.auth.GetAllUsers()
			data.Users = allUsers
		}
		h.templates["keys_import"].ExecuteTemplate(w, "base", data)
		return
	}

	name := r.FormValue("name")
	privateKey := r.FormValue("private_key")

	if name == "" || privateKey == "" {
		data := &PageData{
			Title:  "Import SSH Key",
			Active: "keys",
			User:   user,
			Flash:  &Flash{Type: "danger", Message: "Name and private key are required."},
		}
		if isAdmin(role) {
			allUsers, _ := h.auth.GetAllUsers()
			data.Users = allUsers
		}
		h.templates["keys_import"].ExecuteTemplate(w, "base", data)
		return
	}

	// Admin/Owner can import keys for a selected user
	targetUserID := userID
	if isAdmin(role) {
		if tid := r.FormValue("target_user_id"); tid != "" {
			if parsed, err := strconv.ParseInt(tid, 10, 64); err == nil && parsed > 0 {
				targetUserID = parsed
			}
		}
	}

	_, err := h.keys.ImportKey(targetUserID, name, []byte(privateKey))
	if err != nil {
		logging.Warn("Key import failed for user %d: %v", targetUserID, err)
		data := &PageData{
			Title:  "Import SSH Key",
			Active: "keys",
			User:   user,
			Flash:  &Flash{Type: "danger", Message: "Failed to import key: " + err.Error()},
		}
		if isAdmin(role) {
			allUsers, _ := h.auth.GetAllUsers()
			data.Users = allUsers
		}
		h.templates["keys_import"].ExecuteTemplate(w, "base", data)
		return
	}

	if targetUserID != userID {
		targetUser, _ := h.auth.GetUserByID(targetUserID)
		targetName := fmt.Sprintf("user_id=%d", targetUserID)
		if targetUser != nil {
			targetName = targetUser.Username
		}
		logging.Info("SSH key imported: name='%s' for user '%s' by admin user_id=%d", name, targetName, userID)
		h.audit.Log(userID, audit.ActionKeyImported, fmt.Sprintf("Imported key: %s for user %s", name, targetName), clientIP(r))
	} else {
		logging.Info("SSH key imported: name='%s' user_id=%d", name, userID)
		h.audit.Log(userID, audit.ActionKeyImported, fmt.Sprintf("Imported key: %s", name), clientIP(r))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (h *Handler) handleKeyAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	role := r.Header.Get("X-User-Role")
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	keyID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	switch action {
	case "view":
		// Admin/Owner can view any public key; User can only view own keys
		if isAdmin(role) {
			key, err := h.keys.GetKeyByIDGlobal(keyID)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(key.PublicKey))
		} else {
			key, err := h.keys.GetKeyByID(keyID, userID)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(key.PublicKey))
		}

	case "download":
		// Private key download: only the key owner can download their own private key
		key, err := h.keys.GetKeyByID(keyID, userID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		logging.Info("Private key downloaded: name='%s' id=%d user_id=%d", key.Name, key.ID, userID)
		h.audit.Log(userID, audit.ActionKeyDownload, fmt.Sprintf("Downloaded private key: %s (ID %d)", key.Name, key.ID), clientIP(r))
		w.Header().Set("Content-Disposition", "attachment; filename="+key.Name+"_private.pem")
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write([]byte(key.PrivateKeyEnc))

	case "delete":
		if r.Method == http.MethodPost {
			logging.Info("SSH key deleted: id=%d by_user_id=%d", keyID, userID)
			h.audit.Log(userID, audit.ActionKeyDeleted, fmt.Sprintf("Deleted SSH key ID %d", keyID), clientIP(r))
			// Admin/Owner can delete any key; User can only delete own keys
			if isAdmin(role) {
				h.keys.DeleteKeyGlobal(keyID)
			} else {
				h.keys.DeleteKey(keyID, userID)
			}
		}
		http.Redirect(w, r, "/keys", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleServers(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	// Admin/Owner see all servers globally
	serverList, _ := h.servers.GetAllServers()

	data := &PageData{
		Title:   "Hosts",
		Active:  "servers",
		User:    user,
		Servers: serverList,
	}
	h.templates["servers"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleServersAdd(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	groups, _ := h.servers.GetAllGroups()

	// Build group options
	groupOptions := make([]GroupOption, len(groups))
	for i, g := range groups {
		groupOptions[i] = GroupOption{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
		}
	}

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:  "Add Host",
			Active: "servers",
			User:   user,
			Data:   groupOptions,
		}
		h.templates["servers_add"].ExecuteTemplate(w, "base", data)
		return
	}

	name := r.FormValue("name")
	hostname := r.FormValue("hostname")
	port, _ := strconv.Atoi(r.FormValue("port"))
	username := r.FormValue("username")
	description := r.FormValue("description")

	srv, err := h.servers.Create(userID, name, hostname, port, username, description)
	if err != nil {
		data := &PageData{
			Title:  "Add Host",
			Active: "servers",
			User:   user,
			Data:   groupOptions,
			Flash:  &Flash{Type: "danger", Message: "Failed to add host: " + err.Error()},
		}
		h.templates["servers_add"].ExecuteTemplate(w, "base", data)
		return
	}

	// Assign server to selected groups
	groupIDStrs := r.Form["group_ids"]
	if len(groupIDStrs) > 0 {
		var groupIDs []int64
		for _, gidStr := range groupIDStrs {
			gid, err := strconv.ParseInt(gidStr, 10, 64)
			if err == nil {
				groupIDs = append(groupIDs, gid)
			}
		}
		h.servers.SetServerGroupsGlobal(srv.ID, groupIDs)
	}

	h.audit.Log(userID, audit.ActionServerAdded, fmt.Sprintf("Added server: %s (%s:%d)", name, hostname, port), clientIP(r))
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (h *Handler) handleServerAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	serverID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	switch action {
	case "delete":
		if r.Method == http.MethodPost {
			h.audit.Log(userID, audit.ActionServerDeleted, fmt.Sprintf("Deleted server ID %d", serverID), clientIP(r))
			h.servers.DeleteGlobal(serverID)
		}
		http.Redirect(w, r, "/servers", http.StatusSeeOther)
	case "edit":
		user, _ := h.auth.GetUserByID(userID)
		srv, err := h.servers.GetByIDGlobal(serverID)
		if err != nil {
			http.Redirect(w, r, "/servers", http.StatusSeeOther)
			return
		}

		groups, _ := h.servers.GetAllGroups()
		currentGroupIDs, _ := h.servers.GetGroupIDsForServerGlobal(serverID)
		currentGroupMap := make(map[int64]bool)
		for _, gid := range currentGroupIDs {
			currentGroupMap[gid] = true
		}

		groupOptions := make([]GroupOption, len(groups))
		for i, g := range groups {
			groupOptions[i] = GroupOption{
				ID:          g.ID,
				Name:        g.Name,
				Description: g.Description,
				Selected:    currentGroupMap[g.ID],
			}
		}

		if r.Method == http.MethodGet {
			data := &PageData{
				Title:  "Edit Host",
				Active: "servers",
				User:   user,
				Server: srv,
				Data:   groupOptions,
			}
			h.templates["servers_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// POST: update server
		name := r.FormValue("name")
		hostname := r.FormValue("hostname")
		port, _ := strconv.Atoi(r.FormValue("port"))
		username := r.FormValue("username")
		description := r.FormValue("description")

		if err := h.servers.UpdateGlobal(serverID, name, hostname, port, username, description); err != nil {
			data := &PageData{
				Title:  "Edit Host",
				Active: "servers",
				User:   user,
				Server: srv,
				Data:   groupOptions,
				Flash:  &Flash{Type: "danger", Message: "Failed to update host: " + err.Error()},
			}
			h.templates["servers_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// Update group assignments
		groupIDStrs := r.Form["group_ids"]
		var groupIDs []int64
		for _, gidStr := range groupIDStrs {
			gid, err := strconv.ParseInt(gidStr, 10, 64)
			if err == nil {
				groupIDs = append(groupIDs, gid)
			}
		}
		h.servers.SetServerGroupsGlobal(serverID, groupIDs)

		h.audit.Log(userID, audit.ActionServerUpdated, fmt.Sprintf("Updated server: %s (%s:%d)", name, hostname, port), clientIP(r))
		http.Redirect(w, r, "/servers", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleServerTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := h.getUserID(r)
	serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)

	server, err := h.servers.GetByIDGlobal(serverID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Server not found.",
		})
		return
	}

	// Test TCP connectivity
	err = h.deploy.TestConnection(server.Hostname, server.Port)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		h.audit.Log(userID, audit.ActionServerTest, fmt.Sprintf("Connection test failed for %s:%d: %v", server.Hostname, server.Port, err), clientIP(r))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Connection failed: %v", err),
		})
	} else {
		h.audit.Log(userID, audit.ActionServerTest, fmt.Sprintf("Connection test OK for %s:%d", server.Hostname, server.Port), clientIP(r))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Connection to %s:%d successful (SSH port reachable).", server.Hostname, server.Port),
		})
	}
}

func (h *Handler) handleServerTestAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := h.getUserID(r)
	serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)

	server, err := h.servers.GetByIDGlobal(serverID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Server not found.",
		})
		return
	}

	// Use system master key for auth test
	masterKeyPEM, err := h.keys.GetSystemMasterKeyPrivate()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "System master key not available. Check Admin Settings.",
		})
		return
	}

	// Test actual SSH authentication with system master key
	err = h.deploy.TestSSHAuth(server.Hostname, server.Port, server.Username, masterKeyPEM)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		h.audit.Log(userID, audit.ActionServerAuth, fmt.Sprintf("SSH auth test failed for %s@%s:%d: %v", server.Username, server.Hostname, server.Port, err), clientIP(r))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("SSH authentication failed: %v", err),
		})
	} else {
		h.audit.Log(userID, audit.ActionServerAuth, fmt.Sprintf("SSH auth test OK for %s@%s:%d", server.Username, server.Hostname, server.Port), clientIP(r))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("SSH login to %s@%s:%d successful!", server.Username, server.Hostname, server.Port),
		})
	}
}

func (h *Handler) handleDeploy(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	keyList, _ := h.keys.GetAllKeys()
	serverList, _ := h.servers.GetAllServers()
	groups, _ := h.servers.GetAllGroups()
	deployments, _ := h.deploy.GetDeployments(userID)

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:       "Deploy Keys",
			Active:      "deploy",
			User:        user,
			Keys:        keyList,
			Servers:     serverList,
			Groups:      groups,
			Deployments: deployments,
		}
		h.templates["deploy"].ExecuteTemplate(w, "base", data)
		return
	}

	// Handle POST: deploy key
	keyID, _ := strconv.ParseInt(r.FormValue("key_id"), 10, 64)
	serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
	authMethod := r.FormValue("auth_method")

	key, err := h.keys.GetKeyByID(keyID, userID)
	if err != nil {
		// Try global access for admin/owner deploying other users' keys
		key, err = h.keys.GetKeyByIDGlobal(keyID)
		if err != nil {
			http.Redirect(w, r, "/deploy", http.StatusSeeOther)
			return
		}
	}

	server, err := h.servers.GetByIDGlobal(serverID)
	if err != nil {
		http.Redirect(w, r, "/deploy", http.StatusSeeOther)
		return
	}

	switch authMethod {
	case "password":
		password := r.FormValue("password")
		err = h.deploy.DeployKeyWithPassword(key, server, password)
	case "key":
		authKeyID, _ := strconv.ParseInt(r.FormValue("auth_key_id"), 10, 64)
		authKey, kerr := h.keys.GetKeyByID(authKeyID, userID)
		if kerr != nil {
			http.Redirect(w, r, "/deploy", http.StatusSeeOther)
			return
		}
		err = h.deploy.DeployKey(key, server, []byte(authKey.PrivateKeyEnc))
	}

	if err != nil {
		// Reload with error
		logging.Warn("Deploy failed: key='%s' target=%s@%s:%d error=%v", key.Name, server.Username, server.Hostname, server.Port, err)
		h.audit.Log(userID, audit.ActionDeployFailed, fmt.Sprintf("Deploy key '%s' to %s@%s:%d failed: %v", key.Name, server.Username, server.Hostname, server.Port, err), clientIP(r))
		deployments, _ = h.deploy.GetDeployments(userID)
		data := &PageData{
			Title:       "Deploy Keys",
			Active:      "deploy",
			User:        user,
			Keys:        keyList,
			Servers:     serverList,
			Groups:      groups,
			Deployments: deployments,
			Flash:       &Flash{Type: "danger", Message: "Deployment failed: " + err.Error()},
		}
		h.templates["deploy"].ExecuteTemplate(w, "base", data)
		return
	}

	logging.Info("Deploy successful: key='%s' target=%s@%s:%d", key.Name, server.Username, server.Hostname, server.Port)
	h.audit.Log(userID, audit.ActionDeploySuccess, fmt.Sprintf("Deployed key '%s' to %s@%s:%d", key.Name, server.Username, server.Hostname, server.Port), clientIP(r))
	http.Redirect(w, r, "/deploy", http.StatusSeeOther)
}

func (h *Handler) handleDeployGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/deploy", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	keyID, _ := strconv.ParseInt(r.FormValue("key_id"), 10, 64)
	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)
	authMethod := r.FormValue("auth_method")

	key, err := h.keys.GetKeyByID(keyID, userID)
	if err != nil {
		// Try global access for admin/owner deploying other users' keys
		key, err = h.keys.GetKeyByIDGlobal(keyID)
		if err != nil {
			http.Redirect(w, r, "/deploy", http.StatusSeeOther)
			return
		}
	}

	group, err := h.servers.GetGroupByIDGlobal(groupID)
	if err != nil {
		http.Redirect(w, r, "/deploy", http.StatusSeeOther)
		return
	}

	members, err := h.servers.GetGroupMembersGlobal(groupID)
	if err != nil || len(members) == 0 {
		keyList, _ := h.keys.GetAllKeys()
		serverList, _ := h.servers.GetAllServers()
		groups, _ := h.servers.GetAllGroups()
		deployments, _ := h.deploy.GetDeployments(userID)
		data := &PageData{
			Title:       "Deploy Keys",
			Active:      "deploy",
			User:        user,
			Keys:        keyList,
			Servers:     serverList,
			Groups:      groups,
			Deployments: deployments,
			Flash:       &Flash{Type: "warning", Message: "Group has no members."},
		}
		h.templates["deploy"].ExecuteTemplate(w, "base", data)
		return
	}

	var successCount, failCount int
	for _, server := range members {
		srv := server // capture loop var
		var deployErr error
		switch authMethod {
		case "password":
			password := r.FormValue("password")
			deployErr = h.deploy.DeployKeyWithPassword(key, &srv, password)
		case "key":
			authKeyID, _ := strconv.ParseInt(r.FormValue("auth_key_id"), 10, 64)
			authKey, kerr := h.keys.GetKeyByID(authKeyID, userID)
			if kerr != nil {
				deployErr = fmt.Errorf("auth key not found")
			} else {
				deployErr = h.deploy.DeployKey(key, &srv, []byte(authKey.PrivateKeyEnc))
			}
		}
		if deployErr != nil {
			failCount++
			h.audit.Log(userID, audit.ActionDeployFailed, fmt.Sprintf("Group deploy key '%s' to %s@%s:%d failed: %v", key.Name, srv.Username, srv.Hostname, srv.Port, deployErr), clientIP(r))
		} else {
			successCount++
			h.audit.Log(userID, audit.ActionDeploySuccess, fmt.Sprintf("Group deploy key '%s' to %s@%s:%d", key.Name, srv.Username, srv.Hostname, srv.Port), clientIP(r))
		}
	}

	h.audit.Log(userID, audit.ActionGroupDeploy, fmt.Sprintf("Group deploy '%s' to group '%s': %d success, %d failed", key.Name, group.Name, successCount, failCount), clientIP(r))

	flashType := "success"
	flashMsg := fmt.Sprintf("Deployed key to group '%s': %d/%d servers successful.", group.Name, successCount, len(members))
	if failCount > 0 && successCount > 0 {
		flashType = "warning"
	} else if failCount > 0 && successCount == 0 {
		flashType = "danger"
		flashMsg = fmt.Sprintf("Deploy to group '%s' failed on all %d servers.", group.Name, failCount)
	}

	keyList, _ := h.keys.GetAllKeys()
	serverList, _ := h.servers.GetAllServers()
	groups, _ := h.servers.GetAllGroups()
	deployments, _ := h.deploy.GetDeployments(userID)

	data := &PageData{
		Title:       "Deploy Keys",
		Active:      "deploy",
		User:        user,
		Keys:        keyList,
		Servers:     serverList,
		Groups:      groups,
		Deployments: deployments,
		Flash:       &Flash{Type: flashType, Message: flashMsg},
	}
	h.templates["deploy"].ExecuteTemplate(w, "base", data)
}

// --- Server Group Handlers ---

func (h *Handler) handleServerGroups(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	groups, _ := h.servers.GetAllGroups()

	data := &PageData{
		Title:  "Groups",
		Active: "groups",
		User:   user,
		Groups: groups,
	}
	h.templates["server_groups"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleServerGroupsAdd(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:  "Create Group",
			Active: "groups",
			User:   user,
		}
		h.templates["server_groups_add"].ExecuteTemplate(w, "base", data)
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")

	_, err := h.servers.CreateGroup(userID, name, description)
	if err != nil {
		data := &PageData{
			Title:  "Create Group",
			Active: "groups",
			User:   user,
			Flash:  &Flash{Type: "danger", Message: "Failed to create group: " + err.Error()},
		}
		h.templates["server_groups_add"].ExecuteTemplate(w, "base", data)
		return
	}

	h.audit.Log(userID, audit.ActionGroupCreated, fmt.Sprintf("Created server group: %s", name), clientIP(r))
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (h *Handler) handleServerGroupAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	groupID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	switch action {
	case "edit":
		group, err := h.servers.GetGroupByIDGlobal(groupID)
		if err != nil {
			http.Redirect(w, r, "/groups", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			members, _ := h.servers.GetGroupMembersGlobal(groupID)
			allServers, _ := h.servers.GetAllServers()

			data := &PageData{
				Title:        "Edit Group",
				Active:       "groups",
				User:         user,
				Group:        group,
				GroupServers: members,
				AllServers:   allServers,
			}
			h.templates["server_groups_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// POST: update group info
		name := r.FormValue("name")
		description := r.FormValue("description")
		if err := h.servers.UpdateGroupGlobal(groupID, name, description); err != nil {
			members, _ := h.servers.GetGroupMembersGlobal(groupID)
			allServers, _ := h.servers.GetAllServers()
			data := &PageData{
				Title:        "Edit Group",
				Active:       "groups",
				User:         user,
				Group:        group,
				GroupServers: members,
				AllServers:   allServers,
				Flash:        &Flash{Type: "danger", Message: "Failed to update group: " + err.Error()},
			}
			h.templates["server_groups_edit"].ExecuteTemplate(w, "base", data)
			return
		}
		h.audit.Log(userID, audit.ActionGroupUpdated, fmt.Sprintf("Updated server group: %s (ID %d)", name, groupID), clientIP(r))
		http.Redirect(w, r, fmt.Sprintf("/groups/%d/edit", groupID), http.StatusSeeOther)

	case "delete":
		if r.Method == http.MethodPost {
			group, _ := h.servers.GetGroupByIDGlobal(groupID)
			gname := "unknown"
			if group != nil {
				gname = group.Name
			}
			h.audit.Log(userID, audit.ActionGroupDeleted, fmt.Sprintf("Deleted server group: %s (ID %d)", gname, groupID), clientIP(r))
			h.servers.DeleteGroupGlobal(groupID)
		}
		http.Redirect(w, r, "/groups", http.StatusSeeOther)

	case "add-server":
		if r.Method == http.MethodPost {
			serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
			if err := h.servers.AddServerToGroupGlobal(groupID, serverID); err != nil {
				logging.Error("Failed to add server to group: %v", err)
			} else {
				h.audit.Log(userID, audit.ActionGroupServerAdded, fmt.Sprintf("Added server ID %d to group ID %d", serverID, groupID), clientIP(r))
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/groups/%d/edit", groupID), http.StatusSeeOther)

	case "remove-server":
		if r.Method == http.MethodPost {
			serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
			if err := h.servers.RemoveServerFromGroupGlobal(groupID, serverID); err != nil {
				logging.Error("Failed to remove server from group: %v", err)
			} else {
				h.audit.Log(userID, audit.ActionGroupServerRemoved, fmt.Sprintf("Removed server ID %d from group ID %d", serverID, groupID), clientIP(r))
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/groups/%d/edit", groupID), http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	filterMine := r.URL.Query().Get("filter") == "mine"

	var entries []audit.AuditEntry
	var total int
	var err error

	switch {
	case isOwner(user.Role) && !filterMine:
		// Owner sees everything
		entries, total, err = h.audit.GetAll(page, perPage)
	case isAdmin(user.Role) && !filterMine:
		// Admin sees all except owner entries
		entries, total, err = h.audit.GetAllExceptOwners(page, perPage)
	default:
		// User sees only own entries; also used when admin/owner filters "mine"
		entries, total, err = h.audit.GetByUser(userID, page, perPage)
		if !isAdmin(user.Role) {
			filterMine = true
		}
	}

	if err != nil {
		logging.Error("Failed to load audit log: %v", err)
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}

	prevPage := page - 1
	if prevPage < 1 {
		prevPage = 1
	}
	nextPage := page + 1
	if nextPage > totalPages {
		nextPage = totalPages
	}

	data := &PageData{
		Title:           "Audit Log",
		Active:          "audit",
		User:            user,
		AuditEntries:    entries,
		AuditTotal:      total,
		AuditPage:       page,
		AuditTotalPages: totalPages,
		AuditPrevPage:   prevPage,
		AuditNextPage:   nextPage,
		AuditIsAdmin:    isAdmin(user.Role),
		AuditFilterUser: filterMine,
	}
	h.templates["audit"].ExecuteTemplate(w, "base", data)
}

// --- User Management Handlers (Admin/Owner Only) ---

func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	allUsers, _ := h.auth.GetAllUsers()

	// Admins only see users with role "user"; owners see all
	var users []models.User
	if isOwner(user.Role) {
		users = allUsers
	} else {
		for _, u := range allUsers {
			if u.Role == "user" || u.ID == userID {
				users = append(users, u)
			}
		}
	}

	data := &PageData{
		Title:  "User Management",
		Active: "users",
		User:   user,
		Users:  users,
	}
	h.templates["users"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleUsersAdd(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	if r.Method == http.MethodGet {
		policy := h.auth.GetPasswordPolicy()
		data := &PageData{
			Title:          "Add User",
			Active:         "users",
			User:           user,
			PasswordPolicy: &policy,
			EmailEnabled:   h.mail.IsEnabled(),
		}
		h.templates["users_add"].ExecuteTemplate(w, "base", data)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	mustChangePassword := r.FormValue("must_change_password") == "1"
	sendInvitation := r.FormValue("send_invitation") == "1"

	// Enforce role restrictions: admin can only create "user" role
	if !isOwner(user.Role) && role != "user" {
		role = "user"
	}
	// Only owner can assign "owner" role
	if role == "owner" && !isOwner(user.Role) {
		role = "user"
	}

	// If sending invitation, generate a random temporary password
	if sendInvitation {
		randBytes := make([]byte, 24)
		if _, err := rand.Read(randBytes); err != nil {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Add User",
				Active:         "users",
				User:           user,
				PasswordPolicy: &policy,
				EmailEnabled:   h.mail.IsEnabled(),
				Flash:          &Flash{Type: "danger", Message: "Failed to generate temporary password."},
			}
			h.templates["users_add"].ExecuteTemplate(w, "base", data)
			return
		}
		password = base64.URLEncoding.EncodeToString(randBytes)
		mustChangePassword = true
	} else {
		// Validate password against policy (only when manually set)
		if err := h.auth.ValidatePasswordPolicy(password); err != nil {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Add User",
				Active:         "users",
				User:           user,
				PasswordPolicy: &policy,
				EmailEnabled:   h.mail.IsEnabled(),
				Flash:          &Flash{Type: "danger", Message: err.Error()},
			}
			h.templates["users_add"].ExecuteTemplate(w, "base", data)
			return
		}
	}

	newUser, err := h.auth.Register(username, email, password, role, mustChangePassword)
	if err != nil {
		policy := h.auth.GetPasswordPolicy()
		data := &PageData{
			Title:          "Add User",
			Active:         "users",
			User:           user,
			PasswordPolicy: &policy,
			EmailEnabled:   h.mail.IsEnabled(),
			Flash:          &Flash{Type: "danger", Message: "Failed to create user: " + err.Error()},
		}
		h.templates["users_add"].ExecuteTemplate(w, "base", data)
		return
	}

	logging.Info("User created: username='%s' role='%s' by admin user_id=%d", newUser.Username, role, userID)
	h.audit.Log(userID, audit.ActionUserCreated, fmt.Sprintf("Created user: %s (role: %s)", username, role), clientIP(r))

	// Send invitation email if requested
	if sendInvitation {
		token, err := h.auth.CreateInvitationToken(newUser.ID, 48*time.Hour)
		if err != nil {
			logging.Error("Failed to create invitation token for user '%s': %v", username, err)
			h.audit.Log(userID, audit.ActionInvitationSendFailed, fmt.Sprintf("Failed to create invitation token for user: %s", username), clientIP(r))
			// User was created but invitation failed – redirect with warning
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}

		// Build invite URL – prefer configured BaseURL, fall back to request
		base := h.baseURL
		if base == "" {
			scheme := "http"
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			base = fmt.Sprintf("%s://%s", scheme, r.Host)
			logging.Warn("KEYWARDEN_BASE_URL is not set – deriving invite link from request: %s (set KEYWARDEN_BASE_URL for reliable email links)", base)
		}
		inviteURL := fmt.Sprintf("%s/invite/%s", base, token)
		go func() {
			mailErr := h.mail.SendInvitation(email, mail.InvitationData{
				Username:  username,
				InviteURL: inviteURL,
				ExpiresIn: "48 hours",
			})
			if mailErr != nil {
				logging.Error("Failed to send invitation email to '%s': %v", email, mailErr)
				h.audit.Log(userID, audit.ActionInvitationSendFailed, fmt.Sprintf("Email delivery failed for user: %s (%s)", username, email), clientIP(r))
			} else {
				logging.Info("Invitation email sent to '%s' for user '%s'", email, username)
				h.audit.Log(userID, audit.ActionInvitationSent, fmt.Sprintf("Invitation sent to %s for user: %s", email, username), clientIP(r))
			}
		}()
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *Handler) handleUserAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	targetID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	// Load target user for permission checks
	targetUser, err := h.auth.GetUserByID(targetID)
	if err != nil {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	// Admin can only manage users with role "user"; owner/admin management requires owner role
	if !isOwner(user.Role) && targetUser.Role != "user" && targetID != userID {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	switch action {
	case "edit":
		if r.Method == http.MethodGet {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Edit User",
				Active:         "users",
				User:           user,
				EditUser:       targetUser,
				PasswordPolicy: &policy,
			}
			h.templates["users_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// POST: update user
		username := r.FormValue("username")
		email := r.FormValue("email")
		role := r.FormValue("role")
		newPassword := r.FormValue("password")
		forceChange := r.FormValue("must_change_password") == "1"

		// Enforce role restrictions:
		// - Admin can only assign "user" role
		// - Only owner can assign "admin" or "owner"
		if !isOwner(user.Role) {
			role = "user"
		}
		// Only owner can assign owner role
		if role == "owner" && !isOwner(user.Role) {
			role = "user"
		}

		// Owner protection: cannot degrade self if last owner
		if targetID == userID && isOwner(user.Role) && role != "owner" {
			ownerCount, _ := h.auth.CountByRole("owner")
			if ownerCount <= 1 {
				policy := h.auth.GetPasswordPolicy()
				data := &PageData{
					Title:          "Edit User",
					Active:         "users",
					User:           user,
					EditUser:       targetUser,
					PasswordPolicy: &policy,
					Flash:          &Flash{Type: "danger", Message: "Cannot remove the last owner role. At least one owner must exist."},
				}
				h.templates["users_edit"].ExecuteTemplate(w, "base", data)
				return
			}
		}

		if err := h.auth.UpdateUser(targetID, username, email, role); err != nil {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Edit User",
				Active:         "users",
				User:           user,
				EditUser:       targetUser,
				PasswordPolicy: &policy,
				Flash:          &Flash{Type: "danger", Message: "Failed to update user: " + err.Error()},
			}
			h.templates["users_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// Update password if provided
		if newPassword != "" {
			// Validate against password policy
			if err := h.auth.ValidatePasswordPolicy(newPassword); err != nil {
				policy := h.auth.GetPasswordPolicy()
				data := &PageData{
					Title:          "Edit User",
					Active:         "users",
					User:           user,
					EditUser:       targetUser,
					PasswordPolicy: &policy,
					Flash:          &Flash{Type: "danger", Message: err.Error()},
				}
				h.templates["users_edit"].ExecuteTemplate(w, "base", data)
				return
			}
			if err := h.auth.UpdatePassword(targetID, newPassword); err != nil {
				policy := h.auth.GetPasswordPolicy()
				data := &PageData{
					Title:          "Edit User",
					Active:         "users",
					User:           user,
					EditUser:       targetUser,
					PasswordPolicy: &policy,
					Flash:          &Flash{Type: "danger", Message: "User updated but password change failed: " + err.Error()},
				}
				h.templates["users_edit"].ExecuteTemplate(w, "base", data)
				return
			}
			logging.Info("Password changed for user '%s' (ID %d) by admin user_id=%d", username, targetID, userID)
			h.audit.Log(userID, audit.ActionPasswordChanged, fmt.Sprintf("Admin changed password for user: %s (ID %d)", username, targetID), clientIP(r))
		}

		// Update must_change_password flag
		h.auth.SetMustChangePassword(targetID, forceChange)

		logging.Info("User updated: username='%s' (ID %d) role='%s' by admin user_id=%d", username, targetID, role, userID)
		h.audit.Log(userID, audit.ActionUserUpdated, fmt.Sprintf("Updated user: %s (ID %d, role: %s)", username, targetID, role), clientIP(r))
		http.Redirect(w, r, "/users", http.StatusSeeOther)

	case "unlock":
		if r.Method == http.MethodPost {
			h.auth.UnlockAccount(targetID)
			logging.Info("Account unlocked for user '%s' (ID %d) by admin user_id=%d", targetUser.Username, targetID, userID)
			h.audit.Log(userID, audit.ActionAccountUnlocked, fmt.Sprintf("Unlocked account: %s (ID %d)", targetUser.Username, targetID), clientIP(r))
		}
		http.Redirect(w, r, "/users", http.StatusSeeOther)

	case "delete":
		if r.Method == http.MethodPost {
			// Owner protection: cannot self-delete
			if targetID == userID {
				http.Redirect(w, r, "/users", http.StatusSeeOther)
				return
			}
			// Cannot delete an owner if it would leave zero owners
			if targetUser.Role == "owner" {
				ownerCount, _ := h.auth.CountByRole("owner")
				if ownerCount <= 1 {
					http.Redirect(w, r, "/users", http.StatusSeeOther)
					return
				}
			}
			uname := targetUser.Username
			logging.Info("User deleted: username='%s' (ID %d) by admin user_id=%d", uname, targetID, userID)
			h.audit.Log(userID, audit.ActionUserDeleted, fmt.Sprintf("Deleted user: %s (ID %d)", uname, targetID), clientIP(r))
			h.auth.DeleteUser(targetID)
		}
		http.Redirect(w, r, "/users", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}

// --- Settings Handlers ---

func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	if r.Method == http.MethodGet {
		policy := h.auth.GetPasswordPolicy()
		mfaRequired, _ := h.auth.GetSetting("mfa_required")
		data := &PageData{
			Title:          "Settings",
			Active:         "settings",
			User:           user,
			EmailEnabled:   h.mail.IsEnabled(),
			PasswordPolicy: &policy,
			MFARequired:    mfaRequired == "true",
		}
		h.templates["settings"].ExecuteTemplate(w, "base", data)
		return
	}

	// Handle personal password change
	currentPass := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirmPass := r.FormValue("confirm_password")

	if currentPass != "" && newPass != "" {
		if newPass != confirmPass {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Settings",
				Active:         "settings",
				User:           user,
				PasswordPolicy: &policy,
				Flash:          &Flash{Type: "danger", Message: "New passwords do not match."},
			}
			h.templates["settings"].ExecuteTemplate(w, "base", data)
			return
		}

		// Validate against password policy
		if err := h.auth.ValidatePasswordPolicy(newPass); err != nil {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Settings",
				Active:         "settings",
				User:           user,
				PasswordPolicy: &policy,
				Flash:          &Flash{Type: "danger", Message: err.Error()},
			}
			h.templates["settings"].ExecuteTemplate(w, "base", data)
			return
		}

		// Verify current password
		_, err := h.auth.Login(user.Username, currentPass)
		if err != nil {
			logging.Warn("Password change failed for user '%s': current password incorrect", user.Username)
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Settings",
				Active:         "settings",
				User:           user,
				PasswordPolicy: &policy,
				Flash:          &Flash{Type: "danger", Message: "Current password is incorrect."},
			}
			h.templates["settings"].ExecuteTemplate(w, "base", data)
			return
		}

		if err := h.auth.UpdatePassword(userID, newPass); err != nil {
			policy := h.auth.GetPasswordPolicy()
			data := &PageData{
				Title:          "Settings",
				Active:         "settings",
				User:           user,
				PasswordPolicy: &policy,
				Flash:          &Flash{Type: "danger", Message: "Failed to change password: " + err.Error()},
			}
			h.templates["settings"].ExecuteTemplate(w, "base", data)
			return
		}
		logging.Info("Password changed by user '%s' (ID %d)", user.Username, userID)
		h.audit.Log(userID, audit.ActionPasswordChanged, "User changed their password", clientIP(r))
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleForcePasswordChange handles the mandatory password change page.
// Users with must_change_password flag are redirected here and cannot use
// the application until they set a new password.
func (h *Handler) handleForcePasswordChange(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	// If password change is not required, redirect to dashboard
	if !user.MustChangePassword {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	policy := h.auth.GetPasswordPolicy()

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:          "Change Password",
			User:           user,
			PasswordPolicy: &policy,
		}
		h.templates["force_password_change"].Execute(w, data)
		return
	}

	newPass := r.FormValue("new_password")
	confirmPass := r.FormValue("confirm_password")

	if newPass != confirmPass {
		data := &PageData{
			Title:          "Change Password",
			User:           user,
			PasswordPolicy: &policy,
			Flash:          &Flash{Type: "danger", Message: "Passwords do not match."},
		}
		h.templates["force_password_change"].Execute(w, data)
		return
	}

	if err := h.auth.ValidatePasswordPolicy(newPass); err != nil {
		data := &PageData{
			Title:          "Change Password",
			User:           user,
			PasswordPolicy: &policy,
			Flash:          &Flash{Type: "danger", Message: err.Error()},
		}
		h.templates["force_password_change"].Execute(w, data)
		return
	}

	if err := h.auth.UpdatePassword(userID, newPass); err != nil {
		data := &PageData{
			Title:          "Change Password",
			User:           user,
			PasswordPolicy: &policy,
			Flash:          &Flash{Type: "danger", Message: "Failed to change password: " + err.Error()},
		}
		h.templates["force_password_change"].Execute(w, data)
		return
	}

	// Clear the flag
	h.auth.SetMustChangePassword(userID, false)
	logging.Info("Forced password change completed for user '%s' (ID %d)", user.Username, userID)
	h.audit.Log(userID, audit.ActionForcePasswordChange, "User changed initial password", clientIP(r))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// handleInviteAccept handles the public invitation acceptance page.
// Users reach this via the invitation link in their email.
// GET: shows the registration form (set password)
// POST: completes the registration
func (h *Handler) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	// Extract token from URL: /invite/{token}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[1] == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	token := parts[1]

	// Look up the invitation
	inv, err := h.auth.GetInvitationByToken(token)
	if err != nil {
		data := &PageData{
			Title: "Invalid Invitation",
			Error: "This invitation link is invalid or has already been used.",
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}
	if inv.Used {
		data := &PageData{
			Title: "Invitation Used",
			Error: "This invitation has already been used. Please log in with your credentials.",
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		data := &PageData{
			Title: "Invitation Expired",
			Error: "This invitation has expired. Please contact your administrator for a new invitation.",
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	// Load the user associated with this invitation
	invitedUser, err := h.auth.GetUserByID(inv.UserID)
	if err != nil {
		data := &PageData{
			Title: "Invalid Invitation",
			Error: "The user associated with this invitation could not be found.",
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	policy := h.auth.GetPasswordPolicy()

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:          "Complete Registration",
			EditUser:       invitedUser,
			PasswordPolicy: &policy,
			Data:           token,
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	// POST: complete registration
	newPass := r.FormValue("new_password")
	confirmPass := r.FormValue("confirm_password")

	if newPass != confirmPass {
		data := &PageData{
			Title:          "Complete Registration",
			EditUser:       invitedUser,
			PasswordPolicy: &policy,
			Data:           token,
			Flash:          &Flash{Type: "danger", Message: "Passwords do not match."},
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	if err := h.auth.ValidatePasswordPolicy(newPass); err != nil {
		data := &PageData{
			Title:          "Complete Registration",
			EditUser:       invitedUser,
			PasswordPolicy: &policy,
			Data:           token,
			Flash:          &Flash{Type: "danger", Message: err.Error()},
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	completedUser, err := h.auth.CompleteInvitation(token, newPass)
	if err != nil {
		data := &PageData{
			Title:          "Complete Registration",
			EditUser:       invitedUser,
			PasswordPolicy: &policy,
			Data:           token,
			Flash:          &Flash{Type: "danger", Message: "Registration failed: " + err.Error()},
		}
		h.templates["invite_accept"].Execute(w, data)
		return
	}

	logging.Info("Invitation accepted: user '%s' (ID %d) completed registration", completedUser.Username, completedUser.ID)
	h.audit.Log(completedUser.ID, audit.ActionInvitationAccepted, fmt.Sprintf("User %s completed registration via invitation", completedUser.Username), clientIP(r))

	// Redirect to login page with success indication
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleThemeChange saves the user's theme preference
func (h *Handler) handleThemeChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	theme := r.FormValue("theme")
	h.auth.UpdateTheme(userID, theme)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleAvatarUpload saves the user's profile picture as a file on disk
func (h *Handler) handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	avatarPath := filepath.Join(h.dataDir, "avatars", fmt.Sprintf("%d", userID))

	// Check for avatar removal
	if r.FormValue("remove_avatar") == "1" {
		os.Remove(avatarPath)
		h.auth.UpdateAvatar(userID, "")
		h.audit.Log(userID, audit.ActionAvatarChanged, "Removed profile picture", clientIP(r))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Limit upload to 2MB
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	defer file.Close()

	// Validate content type
	ct := header.Header.Get("Content-Type")
	if ct != "image/png" && ct != "image/jpeg" && ct != "image/gif" && ct != "image/webp" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Save avatar as file on disk (persistent in Docker volume)
	if err := os.WriteFile(avatarPath, data, 0600); err != nil {
		logging.Warn("Failed to save avatar file for user %d: %v", userID, err)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Store marker in DB (not the actual image data)
	if err := h.auth.UpdateAvatar(userID, "file"); err != nil {
		logging.Warn("Failed to update avatar marker for user %d: %v", userID, err)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	h.audit.Log(userID, audit.ActionAvatarChanged, "Updated profile picture", clientIP(r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleAvatarServe serves a user's avatar image from disk
func (h *Handler) handleAvatarServe(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL: /avatar/{id}
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[2] == "" {
		http.NotFound(w, r)
		return
	}
	targetID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	avatarPath := filepath.Join(h.dataDir, "avatars", fmt.Sprintf("%d", targetID))
	data, err := os.ReadFile(avatarPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	contentType := http.DetectContentType(data)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(data)
}

// migrateAvatarsToFiles converts legacy base64 data URI avatars to file-based storage.
// This ensures backwards compatibility when upgrading existing installations.
func (h *Handler) migrateAvatarsToFiles() {
	rows, err := h.auth.GetUsersWithLegacyAvatars()
	if err != nil {
		logging.Warn("Could not check for legacy avatars: %v", err)
		return
	}

	avatarsDir := filepath.Join(h.dataDir, "avatars")
	migrated := 0
	for _, entry := range rows {
		// Parse data URI: "data:image/png;base64,iVBOR..."
		if !strings.HasPrefix(entry.AvatarBase64, "data:") {
			continue
		}
		commaIdx := strings.Index(entry.AvatarBase64, ",")
		if commaIdx < 0 {
			continue
		}
		b64Data := entry.AvatarBase64[commaIdx+1:]
		imgData, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			logging.Warn("Failed to decode legacy avatar for user %d: %v", entry.ID, err)
			continue
		}

		avatarPath := filepath.Join(avatarsDir, fmt.Sprintf("%d", entry.ID))
		if err := os.WriteFile(avatarPath, imgData, 0600); err != nil {
			logging.Warn("Failed to write avatar file for user %d: %v", entry.ID, err)
			continue
		}

		if err := h.auth.UpdateAvatar(entry.ID, "file"); err != nil {
			logging.Warn("Failed to update avatar marker for user %d: %v", entry.ID, err)
			continue
		}
		migrated++
	}
	if migrated > 0 {
		logging.Info("Migrated %d avatar(s) from base64 to file storage", migrated)
	}
}

// --- Access Assignments Handlers ---

func (h *Handler) handleAssignments(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	assignments, _ := h.servers.GetAllAssignments()

	// Decrypt initial passwords for display
	for i := range assignments {
		if assignments[i].InitialPassword != "" {
			if decrypted, err := h.keys.DecryptValue(assignments[i].InitialPassword); err == nil {
				assignments[i].InitialPassword = decrypted
			}
		}
	}

	data := &PageData{
		Title:       "Access Assignments",
		Active:      "assignments",
		User:        user,
		Assignments: assignments,
	}
	h.templates["assignments"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleAssignmentsAdd(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	if r.Method == http.MethodGet {
		allUsers, _ := h.auth.GetAllUsers()
		allKeys, _ := h.keys.GetAllKeys()
		allServers, _ := h.servers.GetAllServers()
		allGroups, _ := h.servers.GetAllGroups()

		data := &PageData{
			Title:           "Create Assignment",
			Active:          "assignments",
			User:            user,
			AssignAllUsers:  allUsers,
			AssignAllKeys:   allKeys,
			AssignAllHosts:  allServers,
			AssignAllGroups: allGroups,
		}
		h.templates["assignments_add"].ExecuteTemplate(w, "base", data)
		return
	}

	// POST: create assignment
	targetUserID, _ := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	sshKeyID, _ := strconv.ParseInt(r.FormValue("ssh_key_id"), 10, 64)
	targetType := r.FormValue("target_type") // "host" or "group"
	var serverID, groupID int64
	if targetType == "host" {
		serverID, _ = strconv.ParseInt(r.FormValue("server_id"), 10, 64)
	} else {
		groupID, _ = strconv.ParseInt(r.FormValue("group_id"), 10, 64)
	}
	systemUser := r.FormValue("system_user")
	desiredState := r.FormValue("desired_state")
	sudo := r.FormValue("sudo") == "on"
	createUser := r.FormValue("create_user") == "on"

	newAssignment, err := h.servers.CreateAssignment(targetUserID, sshKeyID, serverID, groupID, systemUser, desiredState, sudo, createUser)
	if err != nil {
		allUsers, _ := h.auth.GetAllUsers()
		allKeys, _ := h.keys.GetAllKeys()
		allServers, _ := h.servers.GetAllServers()
		allGroups, _ := h.servers.GetAllGroups()
		data := &PageData{
			Title:           "Create Assignment",
			Active:          "assignments",
			User:            user,
			Flash:           &Flash{Type: "danger", Message: "Failed to create assignment: " + err.Error()},
			AssignAllUsers:  allUsers,
			AssignAllKeys:   allKeys,
			AssignAllHosts:  allServers,
			AssignAllGroups: allGroups,
		}
		h.templates["assignments_add"].ExecuteTemplate(w, "base", data)
		return
	}

	targetUser, _ := h.auth.GetUserByID(targetUserID)
	targetName := "unknown"
	if targetUser != nil {
		targetName = targetUser.Username
	}
	h.audit.Log(userID, audit.ActionAssignmentCreated, fmt.Sprintf("Created access assignment for user %s (key ID %d)", targetName, sshKeyID), clientIP(r))

	// Auto-sync: deploy the key immediately after creating the assignment
	h.syncAssignment(w, r, newAssignment.ID, userID)

	http.Redirect(w, r, "/assignments", http.StatusSeeOther)
}

func (h *Handler) handleAssignmentAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	assignID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	switch action {
	case "edit":
		assignment, err := h.servers.GetAssignmentByID(assignID)
		if err != nil {
			http.Redirect(w, r, "/assignments", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			allUsers, _ := h.auth.GetAllUsers()
			allKeys, _ := h.keys.GetAllKeys()
			allServers, _ := h.servers.GetAllServers()
			allGroups, _ := h.servers.GetAllGroups()

			data := &PageData{
				Title:           "Edit Assignment",
				Active:          "assignments",
				User:            user,
				Assignment:      assignment,
				AssignAllUsers:  allUsers,
				AssignAllKeys:   allKeys,
				AssignAllHosts:  allServers,
				AssignAllGroups: allGroups,
			}
			h.templates["assignments_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// POST: update assignment
		targetUserID, _ := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
		sshKeyID, _ := strconv.ParseInt(r.FormValue("ssh_key_id"), 10, 64)
		targetType := r.FormValue("target_type")
		var serverID, groupID int64
		if targetType == "host" {
			serverID, _ = strconv.ParseInt(r.FormValue("server_id"), 10, 64)
		} else {
			groupID, _ = strconv.ParseInt(r.FormValue("group_id"), 10, 64)
		}
		systemUser := r.FormValue("system_user")
		desiredState := r.FormValue("desired_state")
		sudo := r.FormValue("sudo") == "on"
		createUser := r.FormValue("create_user") == "on"

		if err := h.servers.UpdateAssignment(assignID, targetUserID, sshKeyID, serverID, groupID, systemUser, desiredState, sudo, createUser); err != nil {
			allUsers, _ := h.auth.GetAllUsers()
			allKeys, _ := h.keys.GetAllKeys()
			allServers, _ := h.servers.GetAllServers()
			allGroups, _ := h.servers.GetAllGroups()
			data := &PageData{
				Title:           "Edit Assignment",
				Active:          "assignments",
				User:            user,
				Assignment:      assignment,
				Flash:           &Flash{Type: "danger", Message: "Failed to update assignment: " + err.Error()},
				AssignAllUsers:  allUsers,
				AssignAllKeys:   allKeys,
				AssignAllHosts:  allServers,
				AssignAllGroups: allGroups,
			}
			h.templates["assignments_edit"].ExecuteTemplate(w, "base", data)
			return
		}
		h.audit.Log(userID, audit.ActionAssignmentUpdated, fmt.Sprintf("Updated access assignment ID %d", assignID), clientIP(r))

		// Auto-sync: re-deploy after updating the assignment
		h.syncAssignment(w, r, assignID, userID)

		http.Redirect(w, r, "/assignments", http.StatusSeeOther)

	case "delete":
		if r.Method == http.MethodPost {
			// Fetch assignment details before deleting
			assignment, err := h.servers.GetAssignmentByID(assignID)
			if err != nil {
				http.Redirect(w, r, "/assignments", http.StatusSeeOther)
				return
			}

			deleteUser := r.FormValue("delete_user") == "on"

			// Resolve SSH key and target servers for cleanup
			key, keyErr := h.keys.GetKeyByIDGlobal(assignment.SSHKeyID)
			masterKeyPEM, masterKeyErr := h.keys.GetSystemMasterKeyPrivate()

			if keyErr == nil && masterKeyErr == nil {
				// Collect target servers
				var targets []models.Server
				if assignment.ServerID > 0 {
					srv, err := h.servers.GetByIDGlobal(assignment.ServerID)
					if err == nil {
						targets = append(targets, *srv)
					}
				} else if assignment.GroupID > 0 {
					members, err := h.servers.GetGroupMembersGlobal(assignment.GroupID)
					if err == nil {
						targets = members
					}
				}

				for _, server := range targets {
					srv := server

					if deleteUser && assignment.SystemUser != "" && assignment.SystemUser != "root" {
						// Delete system user (includes key removal, sudo removal)
						if err := h.deploy.RemoveSystemUser(key, &srv, masterKeyPEM, assignment.SystemUser); err != nil {
							logging.Warn("Assignment %d cleanup: failed to delete user '%s' on %s: %v", assignID, assignment.SystemUser, srv.Hostname, err)
							h.audit.Log(userID, audit.ActionAssignmentCleanFailed,
								fmt.Sprintf("Failed to delete system user '%s' on %s: %v", assignment.SystemUser, srv.Hostname, err), clientIP(r))
						} else {
							logging.Info("Assignment %d cleanup: deleted system user '%s' on %s", assignID, assignment.SystemUser, srv.Hostname)
							h.audit.Log(userID, audit.ActionAssignmentUserDeleted,
								fmt.Sprintf("Deleted system user '%s' on server %s (assignment %d)", assignment.SystemUser, srv.Hostname, assignID), clientIP(r))
						}
					} else {
						// Only remove the SSH key from the server
						if err := h.deploy.RemoveKeyFromUser(key, &srv, masterKeyPEM, assignment.SystemUser); err != nil {
							logging.Warn("Assignment %d cleanup: failed to remove key from '%s' on %s: %v", assignID, assignment.SystemUser, srv.Hostname, err)
							h.audit.Log(userID, audit.ActionAssignmentCleanFailed,
								fmt.Sprintf("Failed to remove key from '%s' on %s: %v", assignment.SystemUser, srv.Hostname, err), clientIP(r))
						} else {
							logging.Info("Assignment %d cleanup: removed key from '%s' on %s", assignID, assignment.SystemUser, srv.Hostname)
							h.audit.Log(userID, audit.ActionAssignmentKeyRemoved,
								fmt.Sprintf("Removed SSH key from '%s' on server %s (assignment %d)", assignment.SystemUser, srv.Hostname, assignID), clientIP(r))
						}
					}
				}
			} else {
				logging.Warn("Assignment %d cleanup: could not load key or master key, skipping server cleanup (keyErr=%v, masterKeyErr=%v)", assignID, keyErr, masterKeyErr)
				h.audit.Log(userID, audit.ActionAssignmentCleanFailed,
					fmt.Sprintf("Assignment %d cleanup skipped: key or master key unavailable", assignID), clientIP(r))
			}

			h.audit.Log(userID, audit.ActionAssignmentDeleted, fmt.Sprintf("Deleted access assignment ID %d (delete_user=%v)", assignID, deleteUser), clientIP(r))
			h.servers.DeleteAssignment(assignID)
		}
		http.Redirect(w, r, "/assignments", http.StatusSeeOther)

	case "sync":
		// Sync an assignment: deploy or remove the key based on desired_state
		if r.Method == http.MethodPost {
			h.syncAssignment(w, r, assignID, userID)
		}
		http.Redirect(w, r, "/assignments", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}

// syncAssignment executes the deployment/removal for a single access assignment
func (h *Handler) syncAssignment(w http.ResponseWriter, r *http.Request, assignID, actingUserID int64) {
	assignment, err := h.servers.GetAssignmentByID(assignID)
	if err != nil {
		logging.Error("Sync assignment %d: not found: %v", assignID, err)
		return
	}

	// Resolve the SSH key (need private key of the key owner for auth OR use the key's public key)
	// For deployment we need: the public key to deploy and an auth method to connect
	key, err := h.keys.GetKeyByIDGlobal(assignment.SSHKeyID)
	if err != nil {
		h.servers.UpdateAssignmentStatus(assignID, "failed", "SSH key not found")
		h.audit.Log(actingUserID, audit.ActionAssignmentSyncFailed, fmt.Sprintf("Assignment %d sync failed: SSH key not found", assignID), clientIP(r))
		logging.Error("Sync assignment %d: key %d not found: %v", assignID, assignment.SSHKeyID, err)
		return
	}

	// Collect target servers
	var targets []models.Server
	if assignment.ServerID > 0 {
		srv, err := h.servers.GetByIDGlobal(assignment.ServerID)
		if err != nil {
			h.servers.UpdateAssignmentStatus(assignID, "failed", "Target host not found")
			h.audit.Log(actingUserID, audit.ActionAssignmentSyncFailed, fmt.Sprintf("Assignment %d sync failed: host not found", assignID), clientIP(r))
			return
		}
		targets = append(targets, *srv)
	} else if assignment.GroupID > 0 {
		members, err := h.servers.GetGroupMembersGlobal(assignment.GroupID)
		if err != nil || len(members) == 0 {
			h.servers.UpdateAssignmentStatus(assignID, "failed", "Group has no members or not found")
			h.audit.Log(actingUserID, audit.ActionAssignmentSyncFailed, fmt.Sprintf("Assignment %d sync failed: group empty or not found", assignID), clientIP(r))
			return
		}
		targets = members
	} else {
		h.servers.UpdateAssignmentStatus(assignID, "failed", "No target defined")
		return
	}

	// For each target, use the system master key for SSH authentication
	masterKeyPEM, masterKeyErr := h.keys.GetSystemMasterKeyPrivate()
	if masterKeyErr != nil {
		h.servers.UpdateAssignmentStatus(assignID, "failed", "System master key not available")
		h.audit.Log(actingUserID, audit.ActionAssignmentSyncFailed, fmt.Sprintf("Assignment %d sync failed: system master key not available", assignID), clientIP(r))
		logging.Error("Sync assignment %d: system master key not available: %v", assignID, masterKeyErr)
		return
	}

	var successCount, failCount int

	// Generate initial password if createUser is enabled and no password is stored yet
	var initialPassword string
	if assignment.CreateUser && assignment.InitialPassword == "" {
		initialPassword = generateInitialPassword(10)
	}

	for _, server := range targets {
		srv := server

		var deployErr error

		if assignment.DesiredState == "present" {
			// Deploy key – connect as server admin user with system master key, deploy to systemUser
			deployErr = h.deploy.DeployKeyToUser(key, &srv, masterKeyPEM, assignment.SystemUser, assignment.CreateUser, assignment.Sudo, initialPassword)
		} else {
			// Remove key (desired_state == "absent")
			deployErr = h.deploy.RemoveKeyFromUser(key, &srv, masterKeyPEM, assignment.SystemUser)
		}

		if deployErr != nil {
			failCount++
			logging.Warn("Sync assignment %d to %s@%s:%d failed: %v", assignID, assignment.SystemUser, srv.Hostname, srv.Port, deployErr)
		} else {
			successCount++
			logging.Info("Sync assignment %d to %s@%s:%d successful", assignID, assignment.SystemUser, srv.Hostname, srv.Port)
		}
	}

	// Store initial password (encrypted) if it was generated
	if initialPassword != "" && successCount > 0 {
		if encPW, err := h.keys.EncryptValue(initialPassword); err == nil {
			h.servers.UpdateAssignmentInitialPassword(assignID, encPW)
		} else {
			logging.Warn("Failed to encrypt initial password for assignment %d: %v", assignID, err)
		}
	}

	if failCount == 0 {
		h.servers.UpdateAssignmentStatus(assignID, "synced", "")
		h.audit.Log(actingUserID, audit.ActionAssignmentSynced, fmt.Sprintf("Assignment %d synced: %d/%d targets", assignID, successCount, len(targets)), clientIP(r))
	} else {
		h.servers.UpdateAssignmentStatus(assignID, "failed", fmt.Sprintf("%d/%d targets failed", failCount, len(targets)))
		h.audit.Log(actingUserID, audit.ActionAssignmentSyncFailed, fmt.Sprintf("Assignment %d sync: %d success, %d failed of %d targets", assignID, successCount, failCount, len(targets)), clientIP(r))
	}
}

// handleMyAssignments shows the current user's own access assignments (for User role)
func (h *Handler) handleMyAssignments(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	assignments, _ := h.servers.GetAssignmentsByUser(userID)
	assignedHosts, _ := h.servers.GetServersByAssignedUser(userID)

	// Decrypt initial passwords for display
	for i := range assignments {
		if assignments[i].InitialPassword != "" {
			if decrypted, err := h.keys.DecryptValue(assignments[i].InitialPassword); err == nil {
				assignments[i].InitialPassword = decrypted
			}
		}
	}

	data := &PageData{
		Title:       "My Access",
		Active:      "my_access",
		User:        user,
		Assignments: assignments,
		Servers:     assignedHosts,
	}
	h.templates["assignments"].ExecuteTemplate(w, "base", data)
}

// --- Admin Settings Handler ---

// --- System Information Handler ---

func (h *Handler) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Detect runtime environment
	runtimeEnv := "Native"
	if _, err := os.Stat("/.dockerenv"); err == nil {
		runtimeEnv = "Docker"
	}

	hostname, _ := os.Hostname()
	uptimeStr := formatUptime(startTime)

	sysInfo := &SystemInfo{
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     formatBytes(memStats.Alloc),
		MemSys:       formatBytes(memStats.Sys),
		Runtime:      runtimeEnv,
		Hostname:     hostname,
		Uptime:       uptimeStr,
	}

	data := &PageData{
		Title:      "System Information",
		Active:     "system_info",
		User:       user,
		SystemInfo: sysInfo,
	}
	h.templates["system_info"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	settings, _ := h.auth.GetAllSettings()

	// Get system master key info
	masterPub, _ := h.keys.GetSystemMasterKeyPublic()
	masterFP, _ := h.keys.GetSystemMasterKeyFingerprint()

	if r.Method == http.MethodGet {
		adminUsers := h.buildAdminUserList()
		data := &PageData{
			Title:                "Admin Settings",
			Active:               "admin_settings",
			User:                 user,
			Settings:             settings,
			AdminUsers:           adminUsers,
			EmailEnabled:         h.mail.IsEnabled(),
			MasterKeyPublic:      masterPub,
			MasterKeyFingerprint: masterFP,
		}

		// Check for flash message from query parameters (e.g. after backup restore)
		if flashType := r.URL.Query().Get("flash_type"); flashType != "" {
			if flashMsg := r.URL.Query().Get("flash_msg"); flashMsg != "" {
				data.Flash = &Flash{Type: flashType, Message: flashMsg}
			}
		}

		h.templates["admin_settings"].ExecuteTemplate(w, "base", data)
		return
	}

	// POST: save application settings
	r.ParseForm()
	formType := r.FormValue("form_type")
	var changed []string

	logging.Info("Admin settings POST: form_type=%s from user_id=%d", formType, userID)

	switch formType {
	case "security_settings":
		// Collect all settings to save
		batch := make(map[string]string)

		// Number settings
		for _, key := range []string{"pw_min_length", "lockout_attempts", "lockout_duration"} {
			val := r.FormValue(key)
			if val != "" {
				batch[key] = val
				changed = append(changed, key+"="+val)
			}
		}
		// Boolean settings (checkbox: present = true, absent = false)
		for _, key := range []string{"pw_require_upper", "pw_require_lower", "pw_require_digit", "pw_require_special", "mfa_required"} {
			if _, ok := r.PostForm[key]; ok {
				batch[key] = "true"
				changed = append(changed, key+"=true")
			} else {
				batch[key] = "false"
				changed = append(changed, key+"=false")
			}
		}
		logging.Info("Saving security settings: %v", batch)
		// Save all settings in a single transaction
		if err := h.auth.SetSettingsBatch(batch); err != nil {
			logging.Error("Failed to save security settings: %v", err)
			http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg="+url.QueryEscape("Failed to save security settings: "+err.Error()), http.StatusSeeOther)
			return
		}
		logging.Info("Security settings saved successfully")
		if len(changed) > 0 {
			h.audit.Log(userID, audit.ActionPasswordPolicyChanged, fmt.Sprintf("Security settings updated: %s", strings.Join(changed, ", ")), clientIP(r))
		}
	default:
		// Application settings (existing behavior)
		batch := make(map[string]string)
		for _, key := range []string{"app_name", "default_key_type", "default_key_bits", "session_timeout"} {
			val := r.FormValue(key)
			if val != "" || key == "app_name" {
				batch[key] = val
				changed = append(changed, key+"="+val)
			}
		}
		if err := h.auth.SetSettingsBatch(batch); err != nil {
			logging.Error("Failed to save application settings: %v", err)
			http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg="+url.QueryEscape("Failed to save application settings: "+err.Error()), http.StatusSeeOther)
			return
		}
		if len(changed) > 0 {
			h.audit.Log(userID, audit.ActionSettingsChanged, fmt.Sprintf("Changed settings: %s", strings.Join(changed, ", ")), clientIP(r))
		}
	}

	http.Redirect(w, r, "/admin/settings?flash_type=success&flash_msg="+url.QueryEscape("Settings saved successfully."), http.StatusSeeOther)
}

// buildAdminUserList creates the user list for admin settings
func (h *Handler) buildAdminUserList() []AdminUserInfo {
	users, _ := h.auth.GetAllUsers()
	var result []AdminUserInfo
	for _, u := range users {
		info := AdminUserInfo{
			ID:       u.ID,
			Username: u.Username,
			Role:     u.Role,
		}
		result = append(result, info)
	}
	return result
}

// handleMasterKeyRegenerate regenerates the system master key (owner only, requires password confirmation)
func (h *Handler) handleMasterKeyRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	// Require password confirmation
	password := r.FormValue("confirm_password")
	if password == "" {
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg="+url.QueryEscape("Master key regeneration failed: no password provided"), http.StatusSeeOther)
		return
	}

	// Verify the owner's password
	_, err := h.auth.Login(user.Username, password)
	if err != nil {
		logging.Warn("Master key regeneration failed: invalid password for user %s", user.Username)
		h.audit.Log(userID, audit.ActionMasterKeyRegenFailed, "Master key regeneration failed: wrong password", clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg="+url.QueryEscape("Master key regeneration failed: wrong password"), http.StatusSeeOther)
		return
	}

	// Regenerate the system master key
	newPub, err := h.keys.RegenerateSystemMasterKey()
	if err != nil {
		logging.Error("Failed to regenerate system master key: %v", err)
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg="+url.QueryEscape("Master key regeneration failed: "+err.Error()), http.StatusSeeOther)
		return
	}

	logging.Info("System master key regenerated by user %s", user.Username)
	h.audit.Log(userID, audit.ActionMasterKeyRegenerated, fmt.Sprintf("System master key regenerated. New public key: %s", newPub[:40]+"..."), clientIP(r))
	http.Redirect(w, r, "/admin/settings?flash_type=success&flash_msg="+url.QueryEscape("System master key successfully regenerated."), http.StatusSeeOther)
}

// --- Cron Job Handlers ---

// handleAPICronAssignments returns assignments for a given user as JSON (for AJAX).
// GET /api/cron/keys?user_id=X — returns SSH keys for a user
func (h *Handler) handleAPICronKeys(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.URL.Query().Get("user_id")
	targetUserID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || targetUserID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	userKeys, err := h.keys.GetKeysByUser(targetUserID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	type keyJSON struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		KeyType     string `json:"key_type"`
		Fingerprint string `json:"fingerprint"`
	}

	var result []keyJSON
	for _, k := range userKeys {
		result = append(result, keyJSON{
			ID:          k.ID,
			Name:        k.Name,
			KeyType:     k.KeyType,
			Fingerprint: k.Fingerprint,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleCron(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	jobs, _ := h.cron.GetByUser(userID)

	// Decrypt initial passwords for display
	for i := range jobs {
		if jobs[i].InitialPassword != "" {
			if decrypted, err := h.keys.DecryptValue(jobs[i].InitialPassword); err == nil {
				jobs[i].InitialPassword = decrypted
			}
		}
	}

	data := &PageData{
		Title:    "Temporary Access",
		Active:   "cron",
		User:     user,
		CronJobs: jobs,
	}
	h.templates["cron"].ExecuteTemplate(w, "base", data)
}

func (h *Handler) handleCronAdd(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)
	serverList, _ := h.servers.GetAllServers()
	groups, _ := h.servers.GetAllGroups()
	allUsers, _ := h.auth.GetAllUsers()

	if r.Method == http.MethodGet {
		data := &PageData{
			Title:          "New Temporary Access",
			Active:         "cron",
			User:           user,
			Servers:        serverList,
			Groups:         groups,
			DaysOfMonth:    daysOfMonth(),
			AssignAllUsers: allUsers,
		}
		h.templates["cron_add"].ExecuteTemplate(w, "base", data)
		return
	}

	// POST: create temporary access job
	name := r.FormValue("name")
	targetUserID, _ := strconv.ParseInt(r.FormValue("target_user_id"), 10, 64)
	keyID, _ := strconv.ParseInt(r.FormValue("key_id"), 10, 64)

	targetType := r.FormValue("target_type")
	serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)
	if targetType == "group" {
		serverID = 0
	} else {
		groupID = 0
	}

	systemUser := r.FormValue("system_user")
	sudo := r.FormValue("sudo") == "on"
	createUser := r.FormValue("create_user") == "on"
	initialPassword := r.FormValue("initial_password")
	expiryAction := r.FormValue("expiry_action")

	schedule := r.FormValue("schedule")
	scheduledAtStr := r.FormValue("scheduled_at")
	removeAfterMin, _ := strconv.Atoi(r.FormValue("remove_after_min"))
	tz := r.FormValue("timezone")
	timeOfDay := r.FormValue("time_of_day")
	dayOfWeek, _ := strconv.Atoi(r.FormValue("day_of_week"))
	dayOfMonth, _ := strconv.Atoi(r.FormValue("day_of_month"))
	minuteOfHour, _ := strconv.Atoi(r.FormValue("minute_of_hour"))

	if tz == "" {
		tz = "UTC"
	}
	if timeOfDay == "" {
		timeOfDay = "00:00"
	}

	// Parse scheduled_at in the user's timezone for "once" schedule
	var scheduledAt time.Time
	if schedule == "once" && scheduledAtStr != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			loc = time.UTC
		}
		scheduledAt, err = time.ParseInLocation("2006-01-02T15:04", scheduledAtStr, loc)
		if err != nil {
			data := &PageData{
				Title:          "New Temporary Access",
				Active:         "cron",
				User:           user,
				Servers:        serverList,
				Groups:         groups,
				DaysOfMonth:    daysOfMonth(),
				AssignAllUsers: allUsers,
				Flash:          &Flash{Type: "danger", Message: "Invalid date format."},
			}
			h.templates["cron_add"].ExecuteTemplate(w, "base", data)
			return
		}
	} else {
		scheduledAt = time.Now().UTC()
	}

	job, err := h.cron.Create(userID, name, keyID, serverID, groupID, schedule, scheduledAt, removeAfterMin, tz, timeOfDay, dayOfWeek, dayOfMonth, minuteOfHour, targetUserID, systemUser, sudo, createUser, initialPassword, expiryAction)
	if err != nil {
		data := &PageData{
			Title:          "New Temporary Access",
			Active:         "cron",
			User:           user,
			Servers:        serverList,
			Groups:         groups,
			DaysOfMonth:    daysOfMonth(),
			AssignAllUsers: allUsers,
			Flash:          &Flash{Type: "danger", Message: "Failed to create job: " + err.Error()},
		}
		h.templates["cron_add"].ExecuteTemplate(w, "base", data)
		return
	}

	h.audit.Log(userID, audit.ActionCronJobCreated, fmt.Sprintf("Created temporary access: %s (ID %d, schedule: %s)", name, job.ID, schedule), clientIP(r))
	http.Redirect(w, r, "/cron", http.StatusSeeOther)
}

func (h *Handler) handleCronAction(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}

	jobID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	action := parts[2]

	switch action {
	case "edit":
		job, err := h.cron.GetByID(jobID, userID)
		if err != nil {
			http.Redirect(w, r, "/cron", http.StatusSeeOther)
			return
		}

		serverList, _ := h.servers.GetAllServers()
		groups, _ := h.servers.GetAllGroups()
		allUsers, _ := h.auth.GetAllUsers()

		if r.Method == http.MethodGet {
			data := &PageData{
				Title:          "Edit Temporary Access",
				Active:         "cron",
				User:           user,
				CronJob:        job,
				Servers:        serverList,
				Groups:         groups,
				DaysOfMonth:    daysOfMonth(),
				AssignAllUsers: allUsers,
			}
			h.templates["cron_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		// POST: update
		name := r.FormValue("name")
		targetUserID, _ := strconv.ParseInt(r.FormValue("target_user_id"), 10, 64)
		keyID, _ := strconv.ParseInt(r.FormValue("key_id"), 10, 64)

		targetType := r.FormValue("target_type")
		serverID, _ := strconv.ParseInt(r.FormValue("server_id"), 10, 64)
		groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)
		if targetType == "group" {
			serverID = 0
		} else {
			groupID = 0
		}

		systemUser := r.FormValue("system_user")
		sudo := r.FormValue("sudo") == "on"
		createUser := r.FormValue("create_user") == "on"
		initialPassword := r.FormValue("initial_password")
		expiryAction := r.FormValue("expiry_action")

		schedule := r.FormValue("schedule")
		scheduledAtStr := r.FormValue("scheduled_at")
		removeAfterMin, _ := strconv.Atoi(r.FormValue("remove_after_min"))
		tz := r.FormValue("timezone")
		timeOfDay := r.FormValue("time_of_day")
		dayOfWeek, _ := strconv.Atoi(r.FormValue("day_of_week"))
		dayOfMonth, _ := strconv.Atoi(r.FormValue("day_of_month"))
		minuteOfHour, _ := strconv.Atoi(r.FormValue("minute_of_hour"))

		if tz == "" {
			tz = "UTC"
		}
		if timeOfDay == "" {
			timeOfDay = "00:00"
		}

		// Parse scheduled_at in the user's timezone for "once" schedule
		var scheduledAt time.Time
		if schedule == "once" && scheduledAtStr != "" {
			loc, locErr := time.LoadLocation(tz)
			if locErr != nil {
				loc = time.UTC
			}
			var parseErr error
			scheduledAt, parseErr = time.ParseInLocation("2006-01-02T15:04", scheduledAtStr, loc)
			if parseErr != nil {
				data := &PageData{
					Title:          "Edit Temporary Access",
					Active:         "cron",
					User:           user,
					CronJob:        job,
					Servers:        serverList,
					Groups:         groups,
					DaysOfMonth:    daysOfMonth(),
					AssignAllUsers: allUsers,
					Flash:          &Flash{Type: "danger", Message: "Invalid date format."},
				}
				h.templates["cron_edit"].ExecuteTemplate(w, "base", data)
				return
			}
		} else {
			scheduledAt = time.Now().UTC()
		}

		if err := h.cron.Update(jobID, userID, name, keyID, serverID, groupID, schedule, scheduledAt, removeAfterMin, tz, timeOfDay, dayOfWeek, dayOfMonth, minuteOfHour, targetUserID, systemUser, sudo, createUser, initialPassword, expiryAction); err != nil {
			data := &PageData{
				Title:          "Edit Temporary Access",
				Active:         "cron",
				User:           user,
				CronJob:        job,
				Servers:        serverList,
				Groups:         groups,
				DaysOfMonth:    daysOfMonth(),
				AssignAllUsers: allUsers,
				Flash:          &Flash{Type: "danger", Message: "Failed to update job: " + err.Error()},
			}
			h.templates["cron_edit"].ExecuteTemplate(w, "base", data)
			return
		}

		h.audit.Log(userID, audit.ActionCronJobUpdated, fmt.Sprintf("Updated temporary access: %s (ID %d)", name, jobID), clientIP(r))
		http.Redirect(w, r, "/cron", http.StatusSeeOther)

	case "delete":
		if r.Method == http.MethodPost {
			job, _ := h.cron.GetByID(jobID, userID)
			jname := "unknown"
			if job != nil {
				jname = job.Name
			}
			h.audit.Log(userID, audit.ActionCronJobDeleted, fmt.Sprintf("Deleted cron job: %s (ID %d)", jname, jobID), clientIP(r))
			h.cron.Delete(jobID, userID)
		}
		http.Redirect(w, r, "/cron", http.StatusSeeOther)

	case "toggle":
		if r.Method == http.MethodPost {
			job, _ := h.cron.GetByID(jobID, userID)
			if err := h.cron.TogglePause(jobID, userID); err != nil {
				logging.Error("Failed to toggle cron job: %v", err)
			} else if job != nil {
				if job.Status == "paused" {
					h.audit.Log(userID, audit.ActionCronJobResumed, fmt.Sprintf("Resumed cron job: %s (ID %d)", job.Name, jobID), clientIP(r))
				} else {
					h.audit.Log(userID, audit.ActionCronJobPaused, fmt.Sprintf("Paused cron job: %s (ID %d)", job.Name, jobID), clientIP(r))
				}
			}
		}
		http.Redirect(w, r, "/cron", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}
}

// --- MFA Handlers ---

// getSession returns the session data for the current request (requires auth middleware)
func (h *Handler) getSession(r *http.Request) *sessionData {
	cookie, err := r.Cookie("keywarden_session")
	if err != nil {
		return nil
	}
	h.mu.RLock()
	sess := h.sessions[cookie.Value]
	h.mu.RUnlock()
	return sess
}

// handleMFAEnforce shows the standalone MFA setup page (no sidebar) for
// users who are required to enable MFA. This page is shown after login.
func (h *Handler) handleMFAEnforce(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	// If user already has MFA enabled, go to dashboard
	if user.MFAEnabled {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		secret := h.auth.GenerateMFASecret()
		uri := fmt.Sprintf("otpauth://totp/Keywarden:%s?secret=%s&issuer=Keywarden&algorithm=SHA1&digits=6&period=30",
			user.Username, secret)

		data := &PageData{
			Title:     "MFA Setup Required",
			MFASecret: secret,
			MFAUri:    uri,
		}
		h.templates["mfa_required"].Execute(w, data)
		return
	}

	// POST: verify & enable MFA
	secret := r.FormValue("mfa_secret")
	code := r.FormValue("mfa_code")

	if !validateTOTP(secret, code) {
		uri := fmt.Sprintf("otpauth://totp/Keywarden:%s?secret=%s&issuer=Keywarden&algorithm=SHA1&digits=6&period=30",
			user.Username, secret)
		data := &PageData{
			Title:     "MFA Setup Required",
			MFASecret: secret,
			MFAUri:    uri,
			Flash:     &Flash{Type: "danger", Message: "Invalid verification code. Please try again."},
		}
		h.templates["mfa_required"].Execute(w, data)
		return
	}

	if err := h.auth.EnableMFA(userID, secret); err != nil {
		data := &PageData{
			Title: "MFA Setup Required",
			Flash: &Flash{Type: "danger", Message: "Failed to enable MFA: " + err.Error()},
		}
		h.templates["mfa_required"].Execute(w, data)
		return
	}

	// Clear the session flag
	if sess := h.getSession(r); sess != nil {
		h.mu.Lock()
		sess.MFASetupRequired = false
		h.mu.Unlock()
	}

	logging.Info("MFA enabled for user_id=%d (enforcement)", userID)
	h.audit.Log(userID, audit.ActionMFAEnabled, "MFA enabled (enforcement)", clientIP(r))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	// Check if MFA is enforced by admin
	mfaRequired, _ := h.auth.GetSetting("mfa_required")
	isMFARequired := mfaRequired == "true"

	if r.Method == http.MethodGet {
		secret := h.auth.GenerateMFASecret()
		uri := fmt.Sprintf("otpauth://totp/Keywarden:%s?secret=%s&issuer=Keywarden&algorithm=SHA1&digits=6&period=30",
			user.Username, secret)

		data := &PageData{
			Title:       "MFA Setup",
			Active:      "settings",
			User:        user,
			MFASecret:   secret,
			MFAUri:      uri,
			MFARequired: isMFARequired,
		}
		h.templates["mfa_setup"].ExecuteTemplate(w, "base", data)
		return
	}

	// POST: verify & enable MFA
	secret := r.FormValue("mfa_secret")
	code := r.FormValue("mfa_code")

	if !validateTOTP(secret, code) {
		uri := fmt.Sprintf("otpauth://totp/Keywarden:%s?secret=%s&issuer=Keywarden&algorithm=SHA1&digits=6&period=30",
			user.Username, secret)
		data := &PageData{
			Title:     "MFA Setup",
			Active:    "settings",
			User:      user,
			MFASecret: secret,
			MFAUri:    uri,
			Flash:     &Flash{Type: "danger", Message: "Invalid verification code. Please try again."},
		}
		h.templates["mfa_setup"].ExecuteTemplate(w, "base", data)
		return
	}

	if err := h.auth.EnableMFA(userID, secret); err != nil {
		data := &PageData{
			Title:  "MFA Setup",
			Active: "settings",
			User:   user,
			Flash:  &Flash{Type: "danger", Message: "Failed to enable MFA: " + err.Error()},
		}
		h.templates["mfa_setup"].ExecuteTemplate(w, "base", data)
		return
	}

	logging.Info("MFA enabled for user_id=%d", userID)
	h.audit.Log(userID, audit.ActionMFAEnabled, "MFA enabled", clientIP(r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (h *Handler) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Prevent disabling MFA when enforcement is active
	mfaRequired, _ := h.auth.GetSetting("mfa_required")
	if mfaRequired == "true" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	h.auth.DisableMFA(userID)
	logging.Info("MFA disabled for user_id=%d", userID)
	h.audit.Log(userID, audit.ActionMFADisabled, "MFA disabled", clientIP(r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// --- TOTP Helpers (RFC 6238, no external dependency) ---

// sendLoginNotification sends login notification email asynchronously
func (h *Handler) sendLoginNotification(user *models.User, r *http.Request) {
	if !h.mail.IsEnabled() {
		logging.Debug("Login notification skipped: email service not enabled")
		return
	}
	if user.Email == "" {
		logging.Debug("Login notification skipped for %s: no email address configured", user.Username)
		return
	}
	if !user.EmailNotifyLogin {
		logging.Debug("Login notification skipped for %s: notifications disabled", user.Username)
		return
	}
	data := mail.LoginNotificationData{
		Username:  user.Username,
		IPAddress: clientIP(r),
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		UserAgent: r.UserAgent(),
	}
	go func() {
		if err := h.mail.SendLoginNotification(user.Email, data); err != nil {
			logging.Warn("Failed to send login notification to %s: %v", user.Email, err)
			h.audit.Log(user.ID, audit.ActionEmailLoginFailed, fmt.Sprintf("Login notification to %s failed: %v", user.Email, err), data.IPAddress)
		} else {
			logging.Info("Login notification email sent to %s for user '%s'", user.Email, user.Username)
			h.audit.Log(user.ID, audit.ActionEmailLoginSent, fmt.Sprintf("Login notification sent to %s", user.Email), data.IPAddress)
		}
	}()
}

// handleEmailNotifyToggle toggles login email notifications for the current user
func (h *Handler) handleEmailNotifyToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	// The form uses a hidden field (value="0") + checkbox (value="1").
	// When the checkbox is checked, both values are posted.
	// r.FormValue() only returns the first value (always "0"),
	// so we must check all posted values for the field.
	_ = r.ParseForm()
	enabled := false
	for _, v := range r.PostForm["email_notify_login"] {
		if v == "1" {
			enabled = true
			break
		}
	}
	h.auth.UpdateEmailNotifyLogin(userID, enabled)

	action := "disabled"
	if enabled {
		action = "enabled"
	}
	h.audit.Log(userID, audit.ActionEmailNotifyChanged, fmt.Sprintf("Login email notifications %s", action), clientIP(r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleAdminEmailTest sends a test email (admin only)
func (h *Handler) handleAdminEmailTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	user, _ := h.auth.GetUserByID(userID)

	toEmail := r.FormValue("test_email")
	if toEmail == "" {
		toEmail = user.Email
	}

	if err := h.mail.SendTestEmail(toEmail); err != nil {
		logging.Warn("SMTP test email to %s failed: %v", toEmail, err)
		h.audit.Log(userID, audit.ActionEmailTestFailed, fmt.Sprintf("SMTP test to %s failed: %v", toEmail, err), clientIP(r))
	} else {
		logging.Info("SMTP test email sent successfully to %s", toEmail)
		h.audit.Log(userID, audit.ActionEmailTestSent, fmt.Sprintf("SMTP test email sent to %s", toEmail), clientIP(r))
	}

	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// handleBackupExport creates an encrypted backup of the entire database
func (h *Handler) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	password := r.FormValue("backup_password")
	passwordConfirm := r.FormValue("backup_password_confirm")

	if password == "" {
		h.audit.Log(userID, audit.ActionBackupExportFailed, "Empty backup password", clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	if password != passwordConfirm {
		h.audit.Log(userID, audit.ActionBackupExportFailed, "Passwords do not match", clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	// Validate password against the configured password policy
	if err := h.auth.ValidatePasswordPolicy(password); err != nil {
		h.audit.Log(userID, audit.ActionBackupExportFailed, fmt.Sprintf("Backup password does not meet policy: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	// Export all data
	backup, err := h.db.ExportAll()
	if err != nil {
		logging.Error("Backup export failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupExportFailed, fmt.Sprintf("Export failed: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		logging.Error("Backup JSON marshal failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupExportFailed, fmt.Sprintf("JSON marshal failed: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	// Encrypt with user-provided password
	encrypted, err := database.EncryptBackup(jsonData, password)
	if err != nil {
		logging.Error("Backup encryption failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupExportFailed, fmt.Sprintf("Encryption failed: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	h.audit.Log(userID, audit.ActionBackupExported, "Full system backup exported", clientIP(r))

	// Send as download
	filename := fmt.Sprintf("keywarden-backup-%s.kwbak", time.Now().Format("2006-01-02_150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(encrypted)))
	w.Write(encrypted)
}

// handleBackupImport restores an encrypted backup
func (h *Handler) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	userID := h.getUserID(r)
	password := r.FormValue("restore_password")

	if password == "" {
		h.audit.Log(userID, audit.ActionBackupImportFailed, "Empty restore password", clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+no+password+provided", http.StatusSeeOther)
		return
	}

	// Parse multipart form (max 100MB)
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		h.audit.Log(userID, audit.ActionBackupImportFailed, fmt.Sprintf("Failed to parse form: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+could+not+parse+upload", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("backup_file")
	if err != nil {
		h.audit.Log(userID, audit.ActionBackupImportFailed, "No backup file provided", clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+no+backup+file+provided", http.StatusSeeOther)
		return
	}
	defer file.Close()

	// Read file content
	encrypted, err := io.ReadAll(file)
	if err != nil {
		h.audit.Log(userID, audit.ActionBackupImportFailed, fmt.Sprintf("Failed to read file: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+could+not+read+backup+file", http.StatusSeeOther)
		return
	}

	// Decrypt
	jsonData, err := database.DecryptBackup(encrypted, password)
	if err != nil {
		logging.Warn("Backup import decryption failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupImportFailed, fmt.Sprintf("Decryption failed (wrong password or corrupt file): %s", header.Filename), clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+wrong+password+or+corrupt+backup+file", http.StatusSeeOther)
		return
	}

	// Parse JSON
	backup, err := database.ParseBackupJSON(jsonData)
	if err != nil {
		logging.Warn("Backup import parse failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupImportFailed, fmt.Sprintf("Invalid backup format: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+invalid+backup+format", http.StatusSeeOther)
		return
	}

	// Import all data
	if err := h.db.ImportAll(backup); err != nil {
		logging.Error("Backup import failed: %v", err)
		h.audit.Log(userID, audit.ActionBackupImportFailed, fmt.Sprintf("Import failed: %v", err), clientIP(r))
		http.Redirect(w, r, "/admin/settings?flash_type=danger&flash_msg=Restore+failed:+database+import+error", http.StatusSeeOther)
		return
	}

	logging.Info("Backup successfully imported from %s", header.Filename)
	h.audit.Log(userID, audit.ActionBackupImported, fmt.Sprintf("Full system backup restored from %s (created: %s)", header.Filename, backup.CreatedAt), clientIP(r))

	http.Redirect(w, r, "/admin/settings?flash_type=success&flash_msg=Backup+successfully+restored+from+"+url.QueryEscape(header.Filename), http.StatusSeeOther)
}

func validateTOTP(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	// Check current time step and +/- 1 for clock skew tolerance
	now := time.Now().Unix()
	for _, offset := range []int64{-1, 0, 1} {
		t := (now / 30) + offset
		if generateTOTP(secret, t) == code {
			return true
		}
	}
	return false
}

func generateTOTP(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	otp := code % uint32(math.Pow10(6))

	return fmt.Sprintf("%06d", otp)
}

// generateSessionID creates a random session identifier
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// generateInitialPassword creates a random password of the given length
// using uppercase letters, lowercase letters, and digits (no special characters)
func generateInitialPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
