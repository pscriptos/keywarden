// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"git.techniverse.net/scriptos/keywarden/internal/audit"
	"git.techniverse.net/scriptos/keywarden/internal/auth"
	"git.techniverse.net/scriptos/keywarden/internal/config"
	"git.techniverse.net/scriptos/keywarden/internal/cron"
	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/deploy"
	"git.techniverse.net/scriptos/keywarden/internal/encryption"
	"git.techniverse.net/scriptos/keywarden/internal/handlers"
	"git.techniverse.net/scriptos/keywarden/internal/keys"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
	"git.techniverse.net/scriptos/keywarden/internal/mail"
	"git.techniverse.net/scriptos/keywarden/internal/security"
	"git.techniverse.net/scriptos/keywarden/internal/servers"
	"git.techniverse.net/scriptos/keywarden/internal/updater"
	"git.techniverse.net/scriptos/keywarden/internal/version"
	"git.techniverse.net/scriptos/keywarden/internal/worker"
	"git.techniverse.net/scriptos/keywarden/web"
)

func main() {
	// Handle CLI subcommands before starting the server
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-password":
			handleResetPassword(os.Args[2:])
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Load config first (needed for log level)
	cfg := config.Load()

	// Initialize structured logging
	logging.Init(cfg.LogLevel)

	logging.Info("🔑 Keywarden %s - Centralized SSH Key Management and Deployment", version.Version)
	logging.Info("   https://git.techniverse.net/scriptos/keywarden")

	// Validate data paths – relative paths inside a container bypass the
	// persistent volume mount and lead to silent data loss on restart.
	validateDataPaths(cfg)

	// Ensure data directories exist
	for _, dir := range []string{cfg.DataDir, cfg.KeysDir, cfg.MasterDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			logging.Fatal("Failed to create directory %s: %v", dir, err)
		}
	}

	// Initialize database
	db, err := database.New(cfg.DBPath)
	if err != nil {
		logging.Fatal("Failed to initialize database: %v", err)
	}
	defer db.Close()
	logging.Info("Database initialized")

	// Initialize services
	encSvc := encryption.NewService(cfg.EncryptionKey)
	authSvc := auth.NewService(db)
	keysSvc := keys.NewService(db, encSvc)
	serversSvc := servers.NewService(db)
	deploySvc := deploy.NewService(db)
	auditSvc := audit.NewService(db)
	cronSvc := cron.NewService(db, deploySvc, keysSvc, serversSvc, auditSvc)
	workerSvc := worker.NewService(db, deploySvc, keysSvc, serversSvc, auditSvc)
	mailSvc := mail.NewService(cfg)

	// Create default owner if no users exist (password is auto-generated)
	// Support legacy KEYWARDEN_ADMIN_USER / KEYWARDEN_ADMIN_EMAIL for existing installations
	ownerUser := getEnvWithLegacy("KEYWARDEN_OWNER_USER", "KEYWARDEN_ADMIN_USER", "admin")
	ownerEmail := getEnvWithLegacy("KEYWARDEN_OWNER_EMAIL", "KEYWARDEN_ADMIN_EMAIL", "admin@keywarden.local")

	created, generatedPass, err := authSvc.EnsureAdmin(ownerUser, ownerEmail)
	if err != nil {
		logging.Fatal("Failed to create owner user: %v", err)
	}
	if created {
		logging.Info("════════════════════════════════════════════════════════════")
		logging.Info("  Initial owner account created")
		logging.Info("  Username: %s", ownerUser)
		logging.Info("  Password: %s", generatedPass)
		logging.Info("  Please change this password after first login!")
		logging.Info("════════════════════════════════════════════════════════════")
	}

	// Ensure system master key exists (generated on first startup)
	masterPub, err := keysSvc.EnsureSystemMasterKey()
	if err != nil {
		logging.Fatal("Failed to ensure system master key: %v", err)
	}
	logging.Info("System master key ready (deploy this public key to your servers)")
	logging.Info("Master key: %s", masterPub)

	// Initialize security subsystem (trusted proxy IP extraction)
	security.Init(cfg.TrustedProxies)
	if cfg.TrustedProxies != "" {
		logging.Info("Trusted proxies: %s", cfg.TrustedProxies)
	} else {
		logging.Warn("KEYWARDEN_TRUSTED_PROXIES not set – proxy headers (X-Forwarded-For) are trusted unconditionally. Configure trusted proxies for production use.")
	}
	if cfg.BaseURL != "" {
		logging.Info("Base URL: %s", cfg.BaseURL)
	}

	// Initialize update checker
	updaterSvc := updater.NewService(version.Version)

	// Setup HTTP handlers
	handler := handlers.New(authSvc, keysSvc, serversSvc, deploySvc, auditSvc, cronSvc, workerSvc, mailSvc, db, web.TemplateFS, web.StaticFS, cfg.DataDir, cfg.SecureCookies, cfg.BaseURL, updaterSvc)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Start session cleanup (removes expired sessions periodically)
	handler.StartSessionCleanup()

	// Build middleware chain (innermost → outermost)
	var h http.Handler = mux
	h = security.GzipMiddleware()(h)
	h = security.CSRFMiddleware(cfg.SecureCookies)(h)
	h = security.SizeLimitMiddleware(cfg.MaxRequestSize)(h)
	h = security.RateLimitMiddleware(cfg.RateLimitLogin)(h)
	h = security.HeadersMiddleware()(h)
	h = logging.RequestLogger(handler.GetUserName, security.ClientIP)(h)

	logging.Info("Security hardening active: CSRF protection, security headers, rate limiting (%d/min login), request size limit (%d bytes)",
		cfg.RateLimitLogin, cfg.MaxRequestSize)
	if cfg.SecureCookies {
		logging.Info("Secure cookies enabled (HTTPS mode)")
	}

	// Start cron scheduler
	cronSvc.Start()
	defer cronSvc.Stop()

	// Start key enforcement worker
	workerSvc.Start()
	defer workerSvc.Stop()

	// Start update checker
	updaterSvc.Start()
	defer updaterSvc.Stop()

	// Start server
	addr := ":" + cfg.Port
	logging.Info("Server starting on http://0.0.0.0%s", addr)

	if err := http.ListenAndServe(addr, h); err != nil {
		logging.Fatal("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

// getEnvWithLegacy checks the primary key first, then falls back to the
// legacy (deprecated) key, and finally to the default value. This ensures
// existing installations that still use the old variable name keep working.
func getEnvWithLegacy(primary, legacy, fallback string) string {
	if val, ok := os.LookupEnv(primary); ok {
		return val
	}
	if val, ok := os.LookupEnv(legacy); ok {
		logging.Warn("Environment variable %s is deprecated, please rename to %s", legacy, primary)
		return val
	}
	return fallback
}

// validateDataPaths checks for a common misconfiguration: relative paths
// (e.g. ./data/...) that resolve to the container's working directory instead
// of the persistent volume mount. This would cause silent data loss on every
// container restart.
func validateDataPaths(cfg *config.Config) {
	paths := map[string]string{
		"KEYWARDEN_DB_PATH":    cfg.DBPath,
		"KEYWARDEN_DATA_DIR":   cfg.DataDir,
		"KEYWARDEN_KEYS_DIR":   cfg.KeysDir,
		"KEYWARDEN_MASTER_DIR": cfg.MasterDir,
	}

	for envVar, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		// Detect relative paths that resolve outside /data (the expected volume).
		if !filepath.IsAbs(p) || (!strings.HasPrefix(abs, "/data") && !strings.HasPrefix(abs, `\data`)) {
			// Only warn – don't block startup for non-Docker environments.
			if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || (!filepath.IsAbs(p) && p != "") {
				logging.Warn("⚠ %s is a relative path (%s → %s). Inside a Docker container this may bypass the persistent volume and cause DATA LOSS on restart. Use an absolute path like /data/... instead.", envVar, p, abs)
			}
		}
	}
}

// handleResetPassword implements the "reset-password" CLI subcommand.
// Usage: keywarden reset-password --username <name> [--reset-mfa]
func handleResetPassword(args []string) {
	var username string
	var resetMFA bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--username", "-u":
			if i+1 < len(args) {
				i++
				username = args[i]
			} else {
				fmt.Fprintln(os.Stderr, "Error: --username requires a value")
				os.Exit(1)
			}
		case "--reset-mfa":
			resetMFA = true
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown flag '%s'\n", args[i])
			fmt.Fprintln(os.Stderr, "Usage: keywarden reset-password --username <name> [--reset-mfa]")
			os.Exit(1)
		}
	}

	if username == "" {
		fmt.Fprintln(os.Stderr, "Error: --username is required")
		fmt.Fprintln(os.Stderr, "Usage: keywarden reset-password --username <name> [--reset-mfa]")
		os.Exit(1)
	}

	// Load config for DB path
	cfg := config.Load()

	// Open database
	db, err := database.New(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	authSvc := auth.NewService(db)

	// Look up the user
	user, err := authSvc.GetUserByUsername(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: user '%s' not found\n", username)
		os.Exit(1)
	}

	// Reset password
	newPassword, err := authSvc.ResetPassword(user.ID, resetMFA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to reset password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("  Password reset successful for user: %s\n", user.Username)
	fmt.Printf("  New password: %s\n", newPassword)
	if resetMFA {
		fmt.Println("  MFA has been disabled for this account.")
	}
	fmt.Println("  The user must change this password after login.")
	fmt.Println("════════════════════════════════════════════════════════════")
}

// printUsage displays available CLI subcommands
func printUsage() {
	fmt.Printf("Keywarden %s - Centralized SSH Key Management and Deployment\n", version.Version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  keywarden                                         Start the server")
	fmt.Println("  keywarden reset-password --username <name>        Reset a user's password")
	fmt.Println("    --reset-mfa                                     Also disable MFA")
	fmt.Println("  keywarden help                                    Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  docker exec -it keywarden ./keywarden reset-password --username admin")
	fmt.Println("  docker exec -it keywarden ./keywarden reset-password --username admin --reset-mfa")
}
