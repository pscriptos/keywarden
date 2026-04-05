// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"os"

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
	"git.techniverse.net/scriptos/keywarden/web"
)

func main() {
	// Load config first (needed for log level)
	cfg := config.Load()

	// Initialize structured logging
	logging.Init(cfg.LogLevel)

	logging.Info("🔑 Keywarden - Centralized SSH Key Management and Deployment")
	logging.Info("   https://git.techniverse.net/scriptos/keywarden")

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

	// Setup HTTP handlers
	handler := handlers.New(authSvc, keysSvc, serversSvc, deploySvc, auditSvc, cronSvc, mailSvc, db, web.TemplateFS, web.StaticFS, cfg.DataDir, cfg.SecureCookies, cfg.BaseURL)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Start session cleanup (removes expired sessions periodically)
	handler.StartSessionCleanup()

	// Build middleware chain (innermost → outermost)
	var h http.Handler = mux
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
