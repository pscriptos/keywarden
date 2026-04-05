// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net"
	"net/http"
	"strings"
)

// trustedNets holds the parsed trusted proxy CIDR ranges.
// Set once at startup via Init().
var trustedNets []*net.IPNet

// Init parses the trusted proxy configuration and prepares the package
// for use. Must be called once at startup before any middleware runs.
//
// trustedProxies is a comma-separated list of CIDRs or IPs, e.g.
// "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" or "10.0.1.92".
// An empty string means no trusted proxies are configured (legacy mode:
// proxy headers are trusted unconditionally for backward compatibility).
func Init(trustedProxies string) {
	trustedNets = nil
	if trustedProxies == "" {
		return
	}
	for _, entry := range strings.Split(trustedProxies, ",") {
		cidr := strings.TrimSpace(entry)
		if cidr == "" {
			continue
		}
		// Plain IP → convert to single-host CIDR
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // skip invalid entries silently
		}
		trustedNets = append(trustedNets, ipNet)
	}
}

// ClientIP extracts the real client IP address from the request.
//
// When trusted proxies are configured, X-Forwarded-For is walked from
// right to left and the first non-trusted IP is returned (secure approach).
// When no trusted proxies are configured, the legacy behavior is used
// (leftmost X-Forwarded-For entry, i.e. the value the first proxy saw).
func ClientIP(r *http.Request) string {
	remoteIP := extractRemoteIP(r.RemoteAddr)

	if len(trustedNets) > 0 {
		// Strict mode: only honour proxy headers when the direct peer is trusted
		if !isTrustedIP(remoteIP) {
			return remoteIP
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.Split(fwd, ",")
			// Walk right-to-left: rightmost untrusted IP is the real client
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip != "" && !isTrustedIP(ip) {
					return ip
				}
			}
		}
		if real := r.Header.Get("X-Real-Ip"); real != "" {
			return real
		}
		return remoteIP
	}

	// Legacy mode (no trusted proxies configured): trust headers as before
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}
	return remoteIP
}

// extractRemoteIP strips the port from r.RemoteAddr.
func extractRemoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}

// isTrustedIP checks if an IP is within any of the configured trusted networks.
func isTrustedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trustedNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
