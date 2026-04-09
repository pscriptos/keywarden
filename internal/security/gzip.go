// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// compressibleTypes lists MIME types that benefit from gzip compression.
// Binary formats like woff2, images, etc. are already compressed.
var compressibleTypes = map[string]bool{
	"text/html":              true,
	"text/css":               true,
	"text/plain":             true,
	"text/javascript":        true,
	"application/javascript": true,
	"application/json":       true,
	"application/xml":        true,
	"image/svg+xml":          true,
}

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return w
	},
}

// GzipMiddleware compresses HTTP responses for clients that accept gzip.
// Only compressible content types (text, CSS, JS, JSON, SVG) are compressed;
// already-compressed formats (woff2, images) are passed through unchanged.
func GzipMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w)

			grw := &gzipResponseWriter{
				ResponseWriter: w,
				gz:             gz,
			}

			next.ServeHTTP(grw, r)

			if grw.compressed {
				gz.Close()
			}
			gzipWriterPool.Put(gz)
		})
	}
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz         *gzip.Writer
	compressed bool
	decided    bool
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	if w.decided {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.decided = true

	// Only compress successful full responses (not 304, 206, redirects, errors)
	if code == http.StatusOK {
		ct := w.Header().Get("Content-Type")
		if idx := strings.Index(ct, ";"); idx >= 0 {
			ct = strings.TrimSpace(ct[:idx])
		}
		if compressibleTypes[ct] {
			w.compressed = true
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Add("Vary", "Accept-Encoding")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.compressed {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming responses.
func (w *gzipResponseWriter) Flush() {
	if w.compressed {
		w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
