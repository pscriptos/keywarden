// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- CSRF Middleware ----------

func TestCSRFMiddleware_SetsTokenCookie(t *testing.T) {
	handler := CSRFMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "_csrf" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected _csrf cookie to be set on GET request")
	}
	if len(csrfCookie.Value) != 64 {
		t.Fatalf("expected 64-char hex token, got %d chars", len(csrfCookie.Value))
	}
	if csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("expected SameSite=Strict on CSRF cookie")
	}
}

func TestCSRFMiddleware_BlocksPOSTWithoutToken(t *testing.T) {
	handler := CSRFMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: strings.Repeat("a", 64)})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for POST without matching token, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowsPOSTWithValidToken(t *testing.T) {
	token := strings.Repeat("ab", 32) // 64-char hex
	handler := CSRFMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.NewReader("_csrf=" + token)
	req := httptest.NewRequest(http.MethodPost, "/action", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for POST with valid CSRF token, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AllowsGETWithoutToken(t *testing.T) {
	handler := CSRFMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET without CSRF token, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_AcceptsHeaderToken(t *testing.T) {
	token := strings.Repeat("cd", 32) // 64-char hex
	handler := CSRFMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/action", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for POST with X-CSRF-Token header, got %d", rec.Code)
	}
}

// ---------- Security Headers Middleware ----------

func TestHeadersMiddleware_SetsSecurityHeaders(t *testing.T) {
	handler := HeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expected := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("header %s: got %q, want %q", header, got, want)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be set")
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("CSP should contain frame-ancestors 'none'")
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Error("CSP should contain form-action 'self'")
	}
}

func TestHeadersMiddleware_SetsCacheControlForNonStatic(t *testing.T) {
	handler := HeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("expected no-store in Cache-Control for non-static page, got %q", cc)
	}
}

// ---------- Rate Limit Middleware ----------

func TestRateLimitMiddleware_BlocksAfterLimit(t *testing.T) {
	handler := RateLimitMiddleware(3)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 4th request should be blocked
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_DisabledWhenZero(t *testing.T) {
	handler := RateLimitMiddleware(0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 (rate limiting disabled), got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimitMiddleware_AllowsGETLogin(t *testing.T) {
	handler := RateLimitMiddleware(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust POST limit
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// GET should still work
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected GET /login to pass rate limit, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_SeparatesIPs(t *testing.T) {
	handler := RateLimitMiddleware(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust limit for IP 1
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// IP 2 should still be allowed
	req = httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.2:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected different IP to be allowed, got %d", rec.Code)
	}
}

// ---------- Size Limit Middleware ----------

func TestSizeLimitMiddleware_BlocksOversizedBody(t *testing.T) {
	handler := SizeLimitMiddleware(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		_, err := r.Body.Read(buf)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.NewReader(strings.Repeat("x", 100))
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("expected request with body > 10 bytes to be rejected")
	}
}

func TestSizeLimitMiddleware_DisabledWhenZero(t *testing.T) {
	handler := SizeLimitMiddleware(0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.NewReader(strings.Repeat("x", 1000))
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with size limit disabled, got %d", rec.Code)
	}
}

// ---------- Proxy / ClientIP ----------

func TestClientIP_RemoteAddrFallback(t *testing.T) {
	Init("") // no trusted proxies
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"

	ip := ClientIP(req)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestClientIP_XForwardedFor_Legacy(t *testing.T) {
	Init("") // legacy mode, trusts headers
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Fatalf("expected leftmost XFF IP 203.0.113.50, got %s", ip)
	}
}

func TestClientIP_TrustedProxies(t *testing.T) {
	Init("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Fatalf("expected rightmost untrusted IP 203.0.113.50, got %s", ip)
	}
}

func TestClientIP_UntrustedPeerIgnoresHeaders(t *testing.T) {
	Init("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:54321" // not in trusted range
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	ip := ClientIP(req)
	if ip != "203.0.113.99" {
		t.Fatalf("expected direct peer IP when not trusted, got %s", ip)
	}
}

// ---------- isStaticAsset ----------

func TestIsStaticAsset(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/static/css/style.css", true},
		{"/avatar/1.png", true},
		{"/dashboard", false},
		{"/login", false},
		{"", false},
		{"/short", false},
	}
	for _, tt := range tests {
		got := isStaticAsset(tt.path)
		if got != tt.want {
			t.Errorf("isStaticAsset(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
