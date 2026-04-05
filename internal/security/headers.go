// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net/http"
)

// HeadersMiddleware returns middleware that sets security-relevant HTTP
// response headers on every response.
//
// These headers protect against clickjacking, MIME-sniffing, information
// leakage and other common web attacks. They are set regardless of
// whether TLS is in use.
func HeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// Prevent the page from being embedded in an iframe (clickjacking)
			h.Set("X-Frame-Options", "DENY")

			// Stop browsers from MIME-sniffing the content type
			h.Set("X-Content-Type-Options", "nosniff")

			// Control what information is sent in the Referer header
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Restrict browser features that are not needed
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

			// Content Security Policy – fairly strict but allows inline
			// styles/scripts that Tabler and the app currently use.
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"font-src 'self' data:; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'; "+
					"form-action 'self'; "+
					"base-uri 'self'")

			// Opt out of Google FLoC / Topics
			h.Set("X-Permitted-Cross-Domain-Policies", "none")

			// Cache control for authenticated pages – prevent caching of
			// sensitive data. Static assets set their own cache headers.
			if r.URL.Path != "" && !isStaticAsset(r.URL.Path) {
				h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
				h.Set("Pragma", "no-cache")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isStaticAsset returns true for paths that serve static files.
func isStaticAsset(path string) bool {
	return len(path) > 8 && (path[:8] == "/static/" || path[:8] == "/avatar/")
}
