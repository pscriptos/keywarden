// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net/http"
)

// CSRFMiddleware returns middleware that implements the Double-Submit Cookie
// pattern for CSRF protection.
//
// On every request a _csrf cookie is ensured (generated if absent). On
// state-changing methods (POST, PUT, DELETE, PATCH) the middleware validates
// that the request carries a matching token either as:
//   - a form field named "_csrf", or
//   - an X-CSRF-Token request header (for AJAX / fetch calls).
//
// The cookie is NOT HttpOnly so that client-side JavaScript can read the
// value and inject it into forms / fetch headers automatically.
func CSRFMiddleware(secureCookies bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// --- Ensure CSRF token exists ---
			token := ""
			if c, err := r.Cookie("_csrf"); err == nil && len(c.Value) == 64 {
				token = c.Value
			}
			if token == "" {
				b := make([]byte, 32)
				if _, err := rand.Read(b); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				token = fmt.Sprintf("%x", b)
				http.SetCookie(w, &http.Cookie{
					Name:     "_csrf",
					Value:    token,
					Path:     "/",
					HttpOnly: false, // JS must be able to read it
					Secure:   secureCookies,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   86400, // 24 hours
				})
			}

			// --- Validate on state-changing methods ---
			if r.Method == http.MethodPost || r.Method == http.MethodPut ||
				r.Method == http.MethodDelete || r.Method == http.MethodPatch {

				// Accept the token from either the form body or a request header
				submitted := r.FormValue("_csrf")
				if submitted == "" {
					submitted = r.Header.Get("X-CSRF-Token")
				}

				if subtle.ConstantTimeCompare([]byte(submitted), []byte(token)) != 1 {
					http.Error(w, "Forbidden – invalid or missing CSRF token", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
