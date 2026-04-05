// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"git.techniverse.net/scriptos/keywarden/internal/audit"
	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/deploy"
	"git.techniverse.net/scriptos/keywarden/internal/keys"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
	"git.techniverse.net/scriptos/keywarden/internal/models"
	"git.techniverse.net/scriptos/keywarden/internal/servers"
)

// Mode defines the enforcement behavior
const (
	ModeDisabled = "disabled" // no enforcement
	ModeMonitor  = "monitor"  // detect unauthorized keys, log only
	ModeEnforce  = "enforce"  // detect + remove unauthorized keys
)

// DefaultInterval is the default enforcement check interval in minutes
const DefaultInterval = 15

// Service handles the background key enforcement worker
type Service struct {
	db      *database.DB
	deploy  *deploy.Service
	keys    *keys.Service
	servers *servers.Service
	audit   *audit.Service
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	running bool
}

// NewService creates a new enforcement worker service
func NewService(db *database.DB, deploySvc *deploy.Service, keysSvc *keys.Service, serversSvc *servers.Service, auditSvc *audit.Service) *Service {
	return &Service{
		db:      db,
		deploy:  deploySvc,
		keys:    keysSvc,
		servers: serversSvc,
		audit:   auditSvc,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the enforcement worker loop
func (s *Service) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Check settings every 60 seconds to see if enforcement is enabled
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		var lastRun time.Time

		for {
			select {
			case <-ticker.C:
				mode := s.getMode()
				if mode == ModeDisabled {
					continue
				}
				interval := s.getInterval()
				if time.Since(lastRun) >= time.Duration(interval)*time.Minute {
					s.runEnforcement(mode)
					lastRun = time.Now()
				}
			case <-s.stopCh:
				return
			}
		}
	}()
	logging.Info("Key enforcement worker started (checks settings every 60s)")
}

// Stop gracefully stops the enforcement worker
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()
	close(s.stopCh)
	s.wg.Wait()
}

// RunNow triggers an immediate enforcement run (e.g. from admin UI)
func (s *Service) RunNow() {
	mode := s.getMode()
	if mode == ModeDisabled {
		logging.Warn("Key enforcement: manual run requested but enforcement is disabled")
		return
	}
	go s.runEnforcement(mode)
}

// getMode reads the enforcement mode from settings
func (s *Service) getMode() string {
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_mode'`).Scan(&val)
	if err != nil || val == "" {
		return ModeDisabled
	}
	switch val {
	case ModeMonitor, ModeEnforce:
		return val
	default:
		return ModeDisabled
	}
}

// getInterval reads the enforcement interval from settings (in minutes)
func (s *Service) getInterval() int {
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_interval'`).Scan(&val)
	if err != nil || val == "" {
		return DefaultInterval
	}
	var interval int
	fmt.Sscanf(val, "%d", &interval)
	if interval < 1 {
		return DefaultInterval
	}
	return interval
}

// runEnforcement performs one enforcement cycle across all managed servers
func (s *Service) runEnforcement(mode string) {
	logging.Info("Key enforcement: starting run (mode=%s)", mode)

	// Get system master key
	masterKeyPEM, err := s.keys.GetSystemMasterKeyPrivate()
	if err != nil {
		logging.Error("Key enforcement: cannot get system master key: %v", err)
		return
	}
	masterKeyPub, err := s.keys.GetSystemMasterKeyPublic()
	if err != nil {
		logging.Error("Key enforcement: cannot get system master key public: %v", err)
		return
	}

	// Get all servers
	allServers, err := s.servers.GetAllServers()
	if err != nil {
		logging.Error("Key enforcement: failed to get servers: %v", err)
		return
	}

	if len(allServers) == 0 {
		logging.Debug("Key enforcement: no servers configured, skipping")
		return
	}

	// Build desired-state map: server_id -> system_user -> []public_key
	desiredKeys := s.buildDesiredState(masterKeyPub)

	var totalChecked, totalUnauthorized, totalRemoved, totalErrors int

	for _, srv := range allServers {
		server := srv
		// For each server, determine which system users to check
		usersToCheck := s.getSystemUsersForServer(server.ID)
		// Always check the server's default admin user
		if _, exists := usersToCheck[server.Username]; !exists {
			usersToCheck[server.Username] = true
		}

		for systemUser := range usersToCheck {
			checked, unauthorized, removed, errs := s.enforceServer(&server, systemUser, masterKeyPEM, masterKeyPub, desiredKeys, mode)
			totalChecked += checked
			totalUnauthorized += unauthorized
			totalRemoved += removed
			totalErrors += errs
		}
	}

	// Log summary
	summary := fmt.Sprintf("Key enforcement run completed (mode=%s): %d servers checked, %d unauthorized keys found, %d removed, %d errors",
		mode, totalChecked, totalUnauthorized, totalRemoved, totalErrors)
	logging.Info("%s", summary)

	if totalUnauthorized > 0 || totalErrors > 0 {
		s.audit.Log(0, audit.ActionEnforcementRun, summary, "worker")
	}

	// Store last run info in settings
	s.setSetting("enforce_last_run", time.Now().UTC().Format(time.RFC3339))
	s.setSetting("enforce_last_result", summary)
}

// buildDesiredState builds the complete desired-state map:
//
//	server_id -> system_user -> []public_key
//
// Sources of truth (a key is "authorized" if it comes from any of these):
//  1. Access Assignments with desired_state = "present"
//  2. Active Cron Jobs (temporary access) whose keys haven't expired yet
//  3. Direct deployments (via /deploy page) tracked in key_deployments
//  4. The system master key (always authorized on every server+user)
func (s *Service) buildDesiredState(masterKeyPub string) map[int64]map[string][]string {
	desired := make(map[int64]map[string][]string)

	// Helper to add a key to the desired state (with deduplication)
	addKey := func(serverID int64, systemUser, pubKey string) {
		if serverID == 0 || systemUser == "" || pubKey == "" {
			return
		}
		if _, ok := desired[serverID]; !ok {
			desired[serverID] = make(map[string][]string)
		}
		pubKey = strings.TrimSpace(pubKey)
		for _, existing := range desired[serverID][systemUser] {
			if existing == pubKey {
				return
			}
		}
		desired[serverID][systemUser] = append(desired[serverID][systemUser], pubKey)
	}

	// --- Build key lookup: key_id -> public_key ---
	allKeys, err := s.keys.GetAllKeys()
	if err != nil {
		logging.Error("Key enforcement: failed to get all keys: %v", err)
		return desired
	}
	keyMap := make(map[int64]string)
	for _, k := range allKeys {
		keyMap[k.ID] = strings.TrimSpace(k.PublicKey)
	}

	// --- Build server lookup: server_id -> Server ---
	allSrvs, _ := s.servers.GetAllServers()
	srvMap := make(map[int64]*models.Server)
	for i := range allSrvs {
		srvMap[allSrvs[i].ID] = &allSrvs[i]
	}

	// --- 1) Access Assignments (desired_state = "present") ---
	assignments, err := s.servers.GetAllAssignments()
	if err != nil {
		logging.Error("Key enforcement: failed to get assignments: %v", err)
	} else {
		for _, a := range assignments {
			if a.DesiredState != "present" {
				continue
			}
			pubKey := keyMap[a.SSHKeyID]
			if pubKey == "" {
				continue
			}
			if a.ServerID > 0 {
				addKey(a.ServerID, a.SystemUser, pubKey)
			}
			if a.GroupID > 0 {
				members, err := s.servers.GetGroupMembersGlobal(a.GroupID)
				if err != nil {
					logging.Warn("Key enforcement: failed to resolve group %d: %v", a.GroupID, err)
					continue
				}
				for _, m := range members {
					addKey(m.ID, a.SystemUser, pubKey)
				}
			}
		}
		logging.Debug("Key enforcement: loaded %d access assignments into desired state", len(assignments))
	}

	// --- 2) Active Cron Jobs (temporary access, not yet expired) ---
	// A cron-deployed key is authorized if:
	//   - remove_after_min = 0 (permanent) AND the job has executed (last_run IS NOT NULL)
	//   - remove_after_min > 0 AND last_run + remove_after_min > NOW() (not yet expired)
	cronCount := s.addCronJobKeys(addKey, keyMap, srvMap)
	logging.Debug("Key enforcement: loaded %d active cron job deployments into desired state", cronCount)

	// --- 3) Direct deployments (via /deploy page) ---
	// These are tracked in key_deployments. For each key+server pair, the latest
	// successful deploy (not removal) authorizes the key for the server's admin user.
	deployCount := s.addDirectDeployKeys(addKey, keyMap, srvMap)
	logging.Debug("Key enforcement: loaded %d direct deployments into desired state", deployCount)

	// --- 4) System master key (always authorized everywhere) ---
	masterPub := strings.TrimSpace(masterKeyPub)
	for _, srv := range allSrvs {
		// Master key on every server's admin user
		addKey(srv.ID, srv.Username, masterPub)
		// Master key on every system user that has desired keys
		if users, ok := desired[srv.ID]; ok {
			for sysUser := range users {
				addKey(srv.ID, sysUser, masterPub)
			}
		}
	}

	return desired
}

// addCronJobKeys queries cron_jobs for active temporary deployments and adds
// their keys to the desired state. Returns the number of active cron deployments found.
func (s *Service) addCronJobKeys(addKey func(int64, string, string), keyMap map[int64]string, srvMap map[int64]*models.Server) int {
	// Query cron jobs whose deployed keys should still be on the server:
	//  - Job has executed at least once (last_run IS NOT NULL)
	//  - Either permanent (remove_after_min = 0) or not yet expired
	//  - Job status indicates it has executed (not just created)
	rows, err := s.db.Query(
		`SELECT cj.ssh_key_id, cj.server_id, cj.group_id, cj.system_user
		 FROM cron_jobs cj
		 WHERE cj.last_run IS NOT NULL
		   AND cj.status IN ('done', 'active', 'running')
		   AND (
		     cj.remove_after_min = 0
		     OR datetime(cj.last_run, '+' || cj.remove_after_min || ' minutes') > datetime('now')
		   )`)
	if err != nil {
		logging.Warn("Key enforcement: failed to query active cron jobs: %v", err)
		return 0
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var keyID, serverID, groupID int64
		var systemUser string
		if err := rows.Scan(&keyID, &serverID, &groupID, &systemUser); err != nil {
			continue
		}
		pubKey := keyMap[keyID]
		if pubKey == "" {
			continue
		}

		if serverID > 0 {
			if systemUser != "" {
				addKey(serverID, systemUser, pubKey)
			} else if srv, ok := srvMap[serverID]; ok {
				// No system user specified → deployed to server's admin user
				addKey(serverID, srv.Username, pubKey)
			}
			count++
		}
		if groupID > 0 {
			members, err := s.servers.GetGroupMembersGlobal(groupID)
			if err != nil {
				continue
			}
			for _, m := range members {
				if systemUser != "" {
					addKey(m.ID, systemUser, pubKey)
				} else {
					addKey(m.ID, m.Username, pubKey)
				}
			}
			count++
		}
	}
	return count
}

// addDirectDeployKeys queries key_deployments for successful direct deployments
// (via /deploy page) and adds their keys to the desired state.
// For each key+server pair, the most recent entry determines if the key is still deployed.
// Direct deploys always target the server's configured admin user.
func (s *Service) addDirectDeployKeys(addKey func(int64, string, string), keyMap map[int64]string, srvMap map[int64]*models.Server) int {
	// Get the latest deployment status for each key+server combination.
	// A key is considered deployed if the latest entry contains "deployed" (not "removed").
	rows, err := s.db.Query(
		`SELECT kd.ssh_key_id, kd.server_id, kd.message
		 FROM key_deployments kd
		 INNER JOIN (
		   SELECT ssh_key_id, server_id, MAX(id) as max_id
		   FROM key_deployments
		   WHERE status = 'success'
		   GROUP BY ssh_key_id, server_id
		 ) latest ON kd.id = latest.max_id
		 WHERE kd.message LIKE '%deployed%'`)
	if err != nil {
		logging.Warn("Key enforcement: failed to query direct deployments: %v", err)
		return 0
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var keyID, serverID int64
		var message string
		if err := rows.Scan(&keyID, &serverID, &message); err != nil {
			continue
		}
		pubKey := keyMap[keyID]
		if pubKey == "" {
			continue
		}
		srv, ok := srvMap[serverID]
		if !ok {
			continue
		}

		// Determine the system user from the deployment message
		// DeployKeyToUser logs: "key deployed to user 'xxx'"
		// DeployKey logs: "key deployed successfully" (→ server's admin user)
		systemUser := srv.Username
		if idx := strings.Index(message, "to user '"); idx >= 0 {
			rest := message[idx+len("to user '"):]
			if endIdx := strings.Index(rest, "'"); endIdx >= 0 {
				systemUser = rest[:endIdx]
			}
		}

		addKey(serverID, systemUser, pubKey)
		count++
	}
	return count
}

// getSystemUsersForServer returns all system users that should be checked on a server.
// This includes users from:
//  1. Access Assignments (direct + group)
//  2. Active Cron Jobs (direct + group)
func (s *Service) getSystemUsersForServer(serverID int64) map[string]bool {
	users := make(map[string]bool)

	// --- 1a) Direct access assignments ---
	rows, err := s.db.Query(
		`SELECT DISTINCT system_user FROM access_assignments WHERE server_id = ? AND desired_state = 'present'`, serverID)
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil && u != "" {
				users[u] = true
			}
		}
		rows.Close()
	}

	// --- 1b) Group access assignments ---
	groupRows, err := s.db.Query(
		`SELECT DISTINCT a.system_user FROM access_assignments a
		 JOIN server_group_members sgm ON a.group_id = sgm.group_id
		 WHERE sgm.server_id = ? AND a.desired_state = 'present' AND a.group_id > 0`, serverID)
	if err == nil {
		for groupRows.Next() {
			var u string
			if groupRows.Scan(&u) == nil && u != "" {
				users[u] = true
			}
		}
		groupRows.Close()
	}

	// --- 2a) Direct cron jobs (active temporary access) ---
	cronRows, err := s.db.Query(
		`SELECT DISTINCT cj.system_user FROM cron_jobs cj
		 WHERE cj.server_id = ?
		   AND cj.last_run IS NOT NULL
		   AND cj.status IN ('done', 'active', 'running')
		   AND cj.system_user != ''
		   AND (
		     cj.remove_after_min = 0
		     OR datetime(cj.last_run, '+' || cj.remove_after_min || ' minutes') > datetime('now')
		   )`, serverID)
	if err == nil {
		for cronRows.Next() {
			var u string
			if cronRows.Scan(&u) == nil && u != "" {
				users[u] = true
			}
		}
		cronRows.Close()
	}

	// --- 2b) Group cron jobs ---
	cronGroupRows, err := s.db.Query(
		`SELECT DISTINCT cj.system_user FROM cron_jobs cj
		 JOIN server_group_members sgm ON cj.group_id = sgm.group_id
		 WHERE sgm.server_id = ?
		   AND cj.last_run IS NOT NULL
		   AND cj.status IN ('done', 'active', 'running')
		   AND cj.system_user != ''
		   AND cj.group_id > 0
		   AND (
		     cj.remove_after_min = 0
		     OR datetime(cj.last_run, '+' || cj.remove_after_min || ' minutes') > datetime('now')
		   )`, serverID)
	if err == nil {
		for cronGroupRows.Next() {
			var u string
			if cronGroupRows.Scan(&u) == nil && u != "" {
				users[u] = true
			}
		}
		cronGroupRows.Close()
	}

	return users
}

// enforceServer checks and optionally enforces key state for one server+user combination
func (s *Service) enforceServer(server *models.Server, systemUser string, masterKeyPEM []byte, masterKeyPub string, desiredKeys map[int64]map[string][]string, mode string) (checked, unauthorized, removed, errors int) {
	checked = 1

	// Read current authorized_keys from the server
	currentKeys, err := s.deploy.ReadAuthorizedKeys(server, masterKeyPEM, systemUser)
	if err != nil {
		logging.Warn("Key enforcement: failed to read keys from %s@%s:%d (user=%s): %v",
			server.Username, server.Hostname, server.Port, systemUser, err)
		errors = 1
		return
	}

	// Get desired keys for this server+user
	var desired []string
	if serverUsers, ok := desiredKeys[server.ID]; ok {
		if keys, ok := serverUsers[systemUser]; ok {
			desired = keys
		}
	}

	// Always include the master key
	masterPub := strings.TrimSpace(masterKeyPub)
	hasMaster := false
	for _, k := range desired {
		if k == masterPub {
			hasMaster = true
			break
		}
	}
	if !hasMaster {
		desired = append(desired, masterPub)
	}

	// Build set of desired key fingerprints/content for comparison
	desiredSet := make(map[string]bool)
	for _, k := range desired {
		desiredSet[normalizeKey(k)] = true
	}

	// Find unauthorized keys
	var unauthorizedKeys []string
	for _, currentKey := range currentKeys {
		normalized := normalizeKey(currentKey)
		if normalized == "" {
			continue
		}
		if !desiredSet[normalized] {
			unauthorizedKeys = append(unauthorizedKeys, currentKey)
		}
	}

	unauthorized = len(unauthorizedKeys)

	if unauthorized == 0 {
		logging.Debug("Key enforcement: %s@%s (user=%s): all %d keys authorized",
			server.Username, server.Hostname, systemUser, len(currentKeys))
		return
	}

	// Log the unauthorized keys
	keySnippets := make([]string, 0, len(unauthorizedKeys))
	for _, k := range unauthorizedKeys {
		snippet := k
		if len(snippet) > 80 {
			snippet = snippet[:80] + "..."
		}
		keySnippets = append(keySnippets, snippet)
	}

	detail := fmt.Sprintf("Server %s (%s:%d), user '%s': %d unauthorized key(s) found: %s",
		server.Name, server.Hostname, server.Port, systemUser,
		unauthorized, strings.Join(keySnippets, "; "))

	if mode == ModeMonitor {
		logging.Warn("Key enforcement [MONITOR]: %s", detail)
		s.audit.Log(0, audit.ActionEnforcementDrift, detail, "worker")
		return
	}

	// Mode: enforce — replace authorized_keys with only desired keys
	logging.Warn("Key enforcement [ENFORCE]: %s — removing unauthorized keys", detail)
	s.audit.Log(0, audit.ActionEnforcementDrift, detail, "worker")

	if err := s.deploy.WriteAuthorizedKeys(server, masterKeyPEM, systemUser, desired); err != nil {
		logging.Error("Key enforcement: failed to write authorized_keys for %s@%s (user=%s): %v",
			server.Username, server.Hostname, systemUser, err)
		s.audit.Log(0, audit.ActionEnforcementFailed,
			fmt.Sprintf("Failed to enforce keys on %s (%s:%d) user '%s': %v", server.Name, server.Hostname, server.Port, systemUser, err),
			"worker")
		errors = 1
		return
	}

	removed = unauthorized
	s.audit.Log(0, audit.ActionEnforcementApplied,
		fmt.Sprintf("Enforced authorized_keys on %s (%s:%d) user '%s': removed %d unauthorized key(s)",
			server.Name, server.Hostname, server.Port, systemUser, removed),
		"worker")

	return
}

// normalizeKey normalizes a public key line for comparison (strips comments and whitespace variations)
func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" || strings.HasPrefix(key, "#") {
		return ""
	}
	// SSH public keys have format: type base64data [comment]
	// We compare type + base64data only (ignore the comment)
	parts := strings.Fields(key)
	if len(parts) >= 2 {
		return parts[0] + " " + parts[1]
	}
	return key
}

// setSetting writes a value to the settings table (upsert)
func (s *Service) setSetting(key, value string) {
	s.db.Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
		key, value,
	)
}

// GetStatus returns the current enforcement worker status for display
func (s *Service) GetStatus() map[string]string {
	status := make(map[string]string)

	var val string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_mode'`).Scan(&val); err == nil {
		status["mode"] = val
	} else {
		status["mode"] = ModeDisabled
	}

	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_interval'`).Scan(&val); err == nil {
		status["interval"] = val
	} else {
		status["interval"] = fmt.Sprintf("%d", DefaultInterval)
	}

	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_last_run'`).Scan(&val); err == nil {
		status["last_run"] = val
	}

	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'enforce_last_result'`).Scan(&val); err == nil {
		status["last_result"] = val
	}

	return status
}
