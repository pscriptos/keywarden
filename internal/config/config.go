// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Port          string
	DBPath        string
	DataDir       string
	KeysDir       string
	MasterDir     string
	SessionKey    string
	EncryptionKey string
	LogLevel      string // ERROR, WARN, INFO (default), DEBUG, TRACE

	// SMTP / Email
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPTLS      bool
	SMTPEnabled  bool

	// Security / Hardening
	BaseURL        string // e.g. "https://keywarden.example.com" (used for emails, cookie config)
	TrustedProxies string // comma-separated CIDRs, e.g. "10.0.0.0/8,172.16.0.0/12"
	SecureCookies  bool   // set Secure flag on cookies (enable when behind HTTPS proxy)
	RateLimitLogin int    // max login POST attempts per IP per minute (0 = disabled)
	MaxRequestSize int64  // max request body in bytes (0 = no limit)
}

// Load reads configuration from environment variables with sensible defaults
func Load() *Config {
	smtpHost := getEnv("KEYWARDEN_SMTP_HOST", "")

	// Parse BaseURL – auto-derive SecureCookies from scheme if not explicitly set
	baseURL := strings.TrimRight(getEnv("KEYWARDEN_BASE_URL", ""), "/")
	secureCookiesExplicit := getEnv("KEYWARDEN_SECURE_COOKIES", "")
	secureCookies := false
	if secureCookiesExplicit != "" {
		secureCookies = secureCookiesExplicit == "true"
	} else if strings.HasPrefix(baseURL, "https://") {
		secureCookies = true
	}

	rateLimitLogin := getEnvInt("KEYWARDEN_RATE_LIMIT_LOGIN", 10)
	maxRequestSize := getEnvInt64("KEYWARDEN_MAX_REQUEST_SIZE", 10*1024*1024) // 10 MB

	return &Config{
		Port:          getEnv("KEYWARDEN_PORT", "8080"),
		DBPath:        getEnv("KEYWARDEN_DB_PATH", "./data/keywarden.db"),
		DataDir:       getEnv("KEYWARDEN_DATA_DIR", "./data"),
		KeysDir:       getEnv("KEYWARDEN_KEYS_DIR", "./data/keys"),
		MasterDir:     getEnv("KEYWARDEN_MASTER_DIR", "./data/master"),
		SessionKey:    getEnv("KEYWARDEN_SESSION_KEY", "change-me-in-production-please"),
		EncryptionKey: getEnv("KEYWARDEN_ENCRYPTION_KEY", "change-me-encryption-key-32chars"),
		LogLevel:      getEnv("KEYWARDEN_LOG_LEVEL", "INFO"),

		SMTPHost:     smtpHost,
		SMTPPort:     getEnv("KEYWARDEN_SMTP_PORT", "587"),
		SMTPUser:     getEnv("KEYWARDEN_SMTP_USER", ""),
		SMTPPassword: getEnv("KEYWARDEN_SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("KEYWARDEN_SMTP_FROM", "keywarden@localhost"),
		SMTPTLS:      getEnv("KEYWARDEN_SMTP_TLS", "true") == "true",
		SMTPEnabled:  smtpHost != "",

		BaseURL:        baseURL,
		TrustedProxies: getEnv("KEYWARDEN_TRUSTED_PROXIES", ""),
		SecureCookies:  secureCookies,
		RateLimitLogin: rateLimitLogin,
		MaxRequestSize: maxRequestSize,
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	s := getEnv(key, "")
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

func getEnvInt64(key string, fallback int64) int64 {
	s := getEnv(key, "")
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}
