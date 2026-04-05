// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Level represents the severity of a log message
type Level int

const (
	LevelError Level = iota // only errors
	LevelWarn               // errors + warnings
	LevelInfo               // errors + warnings + info (default)
	LevelDebug              // errors + warnings + info + debug
	LevelTrace              // everything, including very verbose trace output
)

// String returns the human-readable name of the log level
func (l Level) String() string {
	switch l {
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// Logger is the application-wide structured logger
type Logger struct {
	level Level
}

// global singleton – initialised via Init()
var global *Logger

func init() {
	// Set log flags for consistent timestamp output (goes to stdout/stderr → Docker logs)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	// Default until Init() is called
	global = &Logger{level: LevelInfo}
}

// Init creates the global logger from the KEYWARDEN_LOG_LEVEL env var.
// Valid values: ERROR, WARN, INFO (default), DEBUG, TRACE
func Init(envValue string) {
	global = &Logger{level: ParseLevel(envValue)}
	global.Info("Log level set to %s", global.level.String())
}

// ParseLevel converts a string to a Level. Defaults to INFO on unknown input.
func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return LevelError
	case "WARN", "WARNING":
		return LevelWarn
	case "INFO", "":
		return LevelInfo
	case "DEBUG":
		return LevelDebug
	case "TRACE":
		return LevelTrace
	default:
		return LevelInfo
	}
}

// GetLevel returns the current global log level
func GetLevel() Level {
	return global.level
}

// ---------------------------------------------------------------------------
// Core logging methods
// ---------------------------------------------------------------------------

func (l *Logger) log(lvl Level, format string, args ...interface{}) {
	if lvl > l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%-5s] %s", lvl.String(), msg)
}

// Error logs at ERROR level (always shown)
func Error(format string, args ...interface{}) { global.log(LevelError, format, args...) }

// Warn logs at WARN level
func Warn(format string, args ...interface{}) { global.log(LevelWarn, format, args...) }

// Info logs at INFO level
func Info(format string, args ...interface{}) { global.log(LevelInfo, format, args...) }

// Debug logs at DEBUG level
func Debug(format string, args ...interface{}) { global.log(LevelDebug, format, args...) }

// Trace logs at TRACE level (very verbose)
func Trace(format string, args ...interface{}) { global.log(LevelTrace, format, args...) }

// Fatal logs at ERROR level and exits the process (like log.Fatalf)
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Fatalf("[ERROR] %s", msg)
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

// Error-returning variant for wrapping + logging in one call
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// ---------------------------------------------------------------------------
// HTTP Request Logging Middleware
// ---------------------------------------------------------------------------

// responseWriter wraps http.ResponseWriter to capture the status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// RequestLogger returns middleware that logs every HTTP request.
// Output format:
//
//	[INFO ] HTTP | 200 |  12.34ms | 192.168.1.1 | GET /dashboard | user=admin | Mozilla/5.0 ...
//
// At DEBUG level it additionally logs request headers.
// At TRACE level it logs everything including cookies (except values).
//
// An optional clientIPFunc can be provided to customise IP extraction
// (e.g. using trusted-proxy-aware logic). If omitted, the built-in
// extractClientIP is used.
func RequestLogger(getUserName func(r *http.Request) string, clientIPFunc ...func(r *http.Request) string) func(http.Handler) http.Handler {
	getIP := extractClientIP
	if len(clientIPFunc) > 0 && clientIPFunc[0] != nil {
		getIP = clientIPFunc[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging for static assets at INFO level to reduce noise
			isStatic := strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/avatar/")

			start := time.Now()
			wrapped := newResponseWriter(w)

			// Process the request
			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			// Determine client IP
			clientIP := getIP(r)

			// Determine username (empty string if not authenticated)
			username := ""
			if getUserName != nil {
				username = getUserName(r)
			}

			userAgent := r.UserAgent()
			if len(userAgent) > 120 {
				userAgent = userAgent[:120] + "…"
			}

			// Build the log line
			userPart := ""
			if username != "" {
				userPart = fmt.Sprintf(" | user=%s", username)
			}

			// Static assets: only log at DEBUG or higher
			if isStatic {
				Debug("HTTP | %d | %10v | %-15s | %s %s%s | %s",
					wrapped.statusCode, duration.Round(time.Microsecond),
					clientIP, r.Method, r.URL.Path, userPart, userAgent)
			} else {
				Info("HTTP | %d | %10v | %-15s | %s %s%s | %s",
					wrapped.statusCode, duration.Round(time.Microsecond),
					clientIP, r.Method, r.URL.Path, userPart, userAgent)
			}

			// At TRACE level, log response size and all request headers
			if GetLevel() >= LevelTrace {
				Trace("HTTP response: %d bytes written for %s %s", wrapped.bytesWritten, r.Method, r.URL.Path)
				Trace("HTTP request headers for %s %s:", r.Method, r.URL.Path)
				for name, values := range r.Header {
					// Redact sensitive headers
					if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Authorization") {
						Trace("  %s: [REDACTED]", name)
					} else {
						Trace("  %s: %s", name, strings.Join(values, ", "))
					}
				}
			}
		})
	}
}

// extractClientIP gets the real client IP, respecting reverse proxy headers
func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}
	// r.RemoteAddr is "ip:port"
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}
