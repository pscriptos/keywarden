// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net/http"
)

// SizeLimitMiddleware returns middleware that limits the size of incoming
// request bodies to maxBytes. This prevents denial-of-service attacks via
// excessively large uploads. A value of 0 disables the limit.
//
// The limit is enforced with http.MaxBytesReader which causes the server
// to return 413 Request Entity Too Large if the body exceeds the limit.
func SizeLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.ContentLength != 0 {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}
