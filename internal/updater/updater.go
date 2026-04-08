// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package updater

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.techniverse.net/scriptos/keywarden/internal/logging"
)

const (
	// Gitea API endpoint for releases
	releasesAPI = "https://git.techniverse.net/api/v1/repos/scriptos/keywarden/releases?limit=5"
	// How often to check for updates
	checkInterval = 6 * time.Hour
	// HTTP timeout for API requests
	httpTimeout = 15 * time.Second
)

// giteaRelease represents the relevant fields from the Gitea releases API
type giteaRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Service checks for new releases in the background
type Service struct {
	currentVersion string

	mu            sync.RWMutex
	latestVersion string
	releaseURL    string
	hasUpdate     bool

	stopCh chan struct{}
}

// NewService creates an update checker. Pass the current application version
// (e.g. "v1.0.0" or "dev"). The checker runs in the background and queries
// the Gitea releases API periodically.
func NewService(currentVersion string) *Service {
	return &Service{
		currentVersion: currentVersion,
		stopCh:         make(chan struct{}),
	}
}

// Start begins periodic update checks in the background.
func (s *Service) Start() {
	// Don't check if running a dev build
	if s.currentVersion == "" || s.currentVersion == "dev" {
		logging.Info("Update checker disabled (development build)")
		return
	}
	logging.Info("Update checker started (current version: %s, checking every %s)", s.currentVersion, checkInterval)

	go s.run()
}

// Stop signals the background goroutine to exit.
func (s *Service) Stop() {
	close(s.stopCh)
}

// HasUpdate returns true if a newer version is available.
func (s *Service) HasUpdate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasUpdate
}

// LatestVersion returns the tag name of the latest release (e.g. "v1.2.0").
func (s *Service) LatestVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latestVersion
}

// ReleaseURL returns the HTML link to the latest release page on Gitea.
func (s *Service) ReleaseURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.releaseURL
}

// CurrentVersion returns the running application version.
func (s *Service) CurrentVersion() string {
	return s.currentVersion
}

func (s *Service) run() {
	// Initial check shortly after startup
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			s.check()
			timer.Reset(checkInterval)
		}
	}
}

func (s *Service) check() {
	client := &http.Client{Timeout: httpTimeout}

	resp, err := client.Get(releasesAPI)
	if err != nil {
		logging.Warn("Update check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logging.Warn("Update check: Gitea API returned status %d", resp.StatusCode)
		return
	}

	var releases []giteaRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		logging.Warn("Update check: failed to parse response: %v", err)
		return
	}

	// Find the latest stable release (not draft, not prerelease)
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease || rel.TagName == "" {
			continue
		}

		s.mu.Lock()
		s.latestVersion = rel.TagName
		s.releaseURL = rel.HTMLURL
		s.hasUpdate = isNewer(rel.TagName, s.currentVersion)
		s.mu.Unlock()

		if s.HasUpdate() {
			logging.Info("New version available: %s (current: %s)", rel.TagName, s.currentVersion)
		}
		return
	}
}

// isNewer returns true if latest is a higher version than current.
// Both may optionally have a "v" prefix (e.g. "v1.2.3").
func isNewer(latest, current string) bool {
	latestParts := parseVersion(latest)
	currentParts := parseVersion(current)

	for i := 0; i < len(latestParts) || i < len(currentParts); i++ {
		l, c := 0, 0
		if i < len(latestParts) {
			l = latestParts[i]
		}
		if i < len(currentParts) {
			c = currentParts[i]
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	return false
}

// parseVersion strips the "v" prefix and splits "1.2.3" into [1, 2, 3].
func parseVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		nums = append(nums, n)
	}
	return nums
}
