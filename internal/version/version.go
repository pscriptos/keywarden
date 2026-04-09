// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

// Version is the current application version.
// This is the SINGLE SOURCE OF TRUTH for the version number.
// Update this value for each release.
//
// It can still be overridden at build time via:
//
//	go build -ldflags "-X git.techniverse.net/scriptos/keywarden/internal/version.Version=v1.0.0"
var Version = "v0.4.0-alpha"
