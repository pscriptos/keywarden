// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/logging"
	"git.techniverse.net/scriptos/keywarden/internal/models"

	"golang.org/x/crypto/ssh"
)

// Service handles deploying SSH keys to remote servers
type Service struct {
	db *database.DB
}

// NewService creates a new deploy service
func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// DeployKey deploys a public key to a remote server's authorized_keys
func (s *Service) DeployKey(key *models.SSHKey, server *models.Server, authPrivateKey []byte) error {
	logging.Debug("Deploy: connecting to %s@%s:%d with key auth for key '%s'", server.Username, server.Hostname, server.Port, key.Name)

	// Parse the private key used for authentication
	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: implement known_hosts
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("session failed: %v", err))
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Clean the public key (remove trailing newline)
	pubKey := strings.TrimSpace(key.PublicKey)

	// Append to authorized_keys
	cmd := fmt.Sprintf(
		`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys`,
		pubKey,
	)

	if err := session.Run(cmd); err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("command failed: %v", err))
		return fmt.Errorf("failed to deploy key: %w", err)
	}

	s.logDeployment(key.ID, server.ID, "success", "key deployed successfully")
	return nil
}

// DeployKeyWithPassword deploys a public key using password authentication
func (s *Service) DeployKeyWithPassword(key *models.SSHKey, server *models.Server, password string) error {
	logging.Debug("Deploy: connecting to %s@%s:%d with password auth for key '%s'", server.Username, server.Hostname, server.Port, key.Name)

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("session failed: %v", err))
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	pubKey := strings.TrimSpace(key.PublicKey)
	cmd := fmt.Sprintf(
		`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys`,
		pubKey,
	)

	if err := session.Run(cmd); err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("command failed: %v", err))
		return fmt.Errorf("failed to deploy key: %w", err)
	}

	s.logDeployment(key.ID, server.ID, "success", "key deployed successfully")
	return nil
}

// RemoveKey removes a public key from a remote server's authorized_keys
func (s *Service) RemoveKey(key *models.SSHKey, server *models.Server, authPrivateKey []byte) error {
	logging.Debug("Deploy: removing key '%s' from %s@%s:%d", key.Name, server.Username, server.Hostname, server.Port)

	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server for key removal: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for key removal: %w", err)
	}
	defer session.Close()

	pubKey := strings.TrimSpace(key.PublicKey)
	// Escape single quotes in the key for safe sed usage
	escapedKey := strings.ReplaceAll(pubKey, "'", "'\\''")

	cmd := fmt.Sprintf(
		`grep -v '%s' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys || true`,
		escapedKey,
	)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to remove key: %w", err)
	}

	s.logDeployment(key.ID, server.ID, "success", "key removed successfully")
	return nil
}

// DeployKeyToUser deploys a public key to a specific system user's authorized_keys.
// It connects to the server as the server's admin user and manages the target systemUser.
// If createUser is true, the system user will be created if it doesn't exist.
// If sudo is true, a sudoers.d entry with NOPASSWD will be created.
// If initialPassword is set and createUser is true, the password will be set on the system user.
func (s *Service) DeployKeyToUser(key *models.SSHKey, server *models.Server, authPrivateKey []byte, systemUser string, createUser, sudo bool, initialPassword string) error {
	logging.Debug("Deploy: connecting to %s@%s:%d to deploy key '%s' for system user '%s' (createUser=%v, sudo=%v)",
		server.Username, server.Hostname, server.Port, key.Name, systemUser, createUser, sudo)

	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	// If createUser is true, ensure the system user exists
	if createUser {
		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session for user creation: %w", err)
		}
		// Create user if not exists; use -m for home directory, -s for shell
		createCmd := fmt.Sprintf(
			`id '%s' >/dev/null 2>&1 || useradd -m -s /bin/bash '%s'`,
			systemUser, systemUser,
		)
		if cerr := session.Run(createCmd); cerr != nil {
			session.Close()
			return fmt.Errorf("failed to create system user '%s': %w", systemUser, cerr)
		}
		session.Close()
		logging.Info("Deploy: ensured system user '%s' exists on %s", systemUser, server.Hostname)

		// Set initial password if provided
		if initialPassword != "" {
			pwSession, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create session for password setup: %w", err)
			}
			pwCmd := fmt.Sprintf(`echo '%s:%s' | chpasswd`, systemUser, initialPassword)
			if perr := pwSession.Run(pwCmd); perr != nil {
				pwSession.Close()
				logging.Warn("Deploy: failed to set initial password for user '%s' on %s: %v", systemUser, server.Hostname, perr)
			} else {
				pwSession.Close()
				logging.Info("Deploy: set initial password for user '%s' on %s", systemUser, server.Hostname)
			}
		}
	}

	// If sudo is true, create a sudoers.d entry with NOPASSWD
	if sudo {
		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session for sudo setup: %w", err)
		}
		sudoCmd := fmt.Sprintf(
			`echo '%s ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/%s && chmod 440 /etc/sudoers.d/%s`,
			systemUser, systemUser, systemUser,
		)
		if serr := session.Run(sudoCmd); serr != nil {
			session.Close()
			logging.Warn("Deploy: failed to add sudo for user '%s' on %s: %v", systemUser, server.Hostname, serr)
		} else {
			session.Close()
			logging.Info("Deploy: ensured NOPASSWD sudo for user '%s' on %s", systemUser, server.Hostname)
		}
	}

	// Deploy the key to the system user's authorized_keys
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for key deployment: %w", err)
	}
	defer session.Close()

	pubKey := strings.TrimSpace(key.PublicKey)
	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}

	cmd := fmt.Sprintf(
		`mkdir -p %s/.ssh && chmod 700 %s/.ssh && echo '%s' >> %s/.ssh/authorized_keys && chmod 600 %s/.ssh/authorized_keys && chown -R '%s':'%s' %s/.ssh && sort -u -o %s/.ssh/authorized_keys %s/.ssh/authorized_keys`,
		homeDir, homeDir, pubKey, homeDir, homeDir, systemUser, systemUser, homeDir, homeDir, homeDir,
	)

	if err := session.Run(cmd); err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("command failed: %v", err))
		return fmt.Errorf("failed to deploy key for user '%s': %w", systemUser, err)
	}

	s.logDeployment(key.ID, server.ID, "success", fmt.Sprintf("key deployed to user '%s'", systemUser))
	return nil
}

// DeployKeyToUserWithPassword is like DeployKeyToUser but uses password authentication
func (s *Service) DeployKeyToUserWithPassword(key *models.SSHKey, server *models.Server, password string, systemUser string, createUser, sudo bool, initialPassword string) error {
	logging.Debug("Deploy: connecting to %s@%s:%d with password to deploy key '%s' for system user '%s'",
		server.Username, server.Hostname, server.Port, key.Name, systemUser)

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	if createUser {
		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session for user creation: %w", err)
		}
		createCmd := fmt.Sprintf(
			`id '%s' >/dev/null 2>&1 || useradd -m -s /bin/bash '%s'`,
			systemUser, systemUser,
		)
		if cerr := session.Run(createCmd); cerr != nil {
			session.Close()
			return fmt.Errorf("failed to create system user '%s': %w", systemUser, cerr)
		}
		session.Close()
		logging.Info("Deploy: ensured system user '%s' exists on %s", systemUser, server.Hostname)

		// Set initial password if provided
		if initialPassword != "" {
			pwSession, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create session for password setup: %w", err)
			}
			pwCmd := fmt.Sprintf(`echo '%s:%s' | chpasswd`, systemUser, initialPassword)
			if perr := pwSession.Run(pwCmd); perr != nil {
				pwSession.Close()
				logging.Warn("Deploy: failed to set initial password for user '%s' on %s: %v", systemUser, server.Hostname, perr)
			} else {
				pwSession.Close()
				logging.Info("Deploy: set initial password for user '%s' on %s", systemUser, server.Hostname)
			}
		}
	}

	if sudo {
		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session for sudo setup: %w", err)
		}
		sudoCmd := fmt.Sprintf(
			`echo '%s ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/%s && chmod 440 /etc/sudoers.d/%s`,
			systemUser, systemUser, systemUser,
		)
		if serr := session.Run(sudoCmd); serr != nil {
			session.Close()
			logging.Warn("Deploy: failed to add sudo for user '%s' on %s: %v", systemUser, server.Hostname, serr)
		} else {
			session.Close()
			logging.Info("Deploy: ensured NOPASSWD sudo for user '%s' on %s", systemUser, server.Hostname)
		}
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for key deployment: %w", err)
	}
	defer session.Close()

	pubKey := strings.TrimSpace(key.PublicKey)
	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}

	cmd := fmt.Sprintf(
		`mkdir -p %s/.ssh && chmod 700 %s/.ssh && echo '%s' >> %s/.ssh/authorized_keys && chmod 600 %s/.ssh/authorized_keys && chown -R '%s':'%s' %s/.ssh && sort -u -o %s/.ssh/authorized_keys %s/.ssh/authorized_keys`,
		homeDir, homeDir, pubKey, homeDir, homeDir, systemUser, systemUser, homeDir, homeDir, homeDir,
	)

	if err := session.Run(cmd); err != nil {
		s.logDeployment(key.ID, server.ID, "failed", fmt.Sprintf("command failed: %v", err))
		return fmt.Errorf("failed to deploy key for user '%s': %w", systemUser, err)
	}

	s.logDeployment(key.ID, server.ID, "success", fmt.Sprintf("key deployed to user '%s'", systemUser))
	return nil
}

// RemoveKeyFromUser removes a public key from a specific system user's authorized_keys.
// It connects as the server's admin user and manages the target systemUser's keys.
func (s *Service) RemoveKeyFromUser(key *models.SSHKey, server *models.Server, authPrivateKey []byte, systemUser string) error {
	logging.Debug("Deploy: connecting to %s@%s:%d to remove key '%s' from system user '%s'",
		server.Username, server.Hostname, server.Port, key.Name, systemUser)

	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server for key removal: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for key removal: %w", err)
	}
	defer session.Close()

	pubKey := strings.TrimSpace(key.PublicKey)
	escapedKey := strings.ReplaceAll(pubKey, "'", "'\\''")

	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}

	cmd := fmt.Sprintf(
		`grep -v '%s' %s/.ssh/authorized_keys > %s/.ssh/authorized_keys.tmp 2>/dev/null && mv %s/.ssh/authorized_keys.tmp %s/.ssh/authorized_keys && chmod 600 %s/.ssh/authorized_keys && chown '%s':'%s' %s/.ssh/authorized_keys || true`,
		escapedKey, homeDir, homeDir, homeDir, homeDir, homeDir, systemUser, systemUser, homeDir,
	)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to remove key from user '%s': %w", systemUser, err)
	}

	s.logDeployment(key.ID, server.ID, "success", fmt.Sprintf("key removed from user '%s'", systemUser))
	return nil
}

// RemoveSystemUser removes a Linux system user from a server, including:
// - Removing the SSH key from their authorized_keys
// - Removing sudo rights (/etc/sudoers.d/<user>)
// - Deleting the system user account (userdel -r)
func (s *Service) RemoveSystemUser(key *models.SSHKey, server *models.Server, authPrivateKey []byte, systemUser string) error {
	logging.Info("Deploy: removing system user '%s' from %s@%s:%d", systemUser, server.Username, server.Hostname, server.Port)

	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server for user removal: %w", err)
	}
	defer client.Close()

	// Step 1: Remove sudoers entry
	sudoSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for sudo removal: %w", err)
	}
	sudoCmd := fmt.Sprintf(`rm -f /etc/sudoers.d/'%s'`, systemUser)
	if serr := sudoSession.Run(sudoCmd); serr != nil {
		logging.Warn("Deploy: failed to remove sudo for user '%s' on %s: %v", systemUser, server.Hostname, serr)
	} else {
		logging.Info("Deploy: removed sudoers entry for '%s' on %s", systemUser, server.Hostname)
	}
	sudoSession.Close()

	// Step 2: Kill all processes of the user (so userdel doesn't fail)
	killSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for process kill: %w", err)
	}
	killCmd := fmt.Sprintf(`pkill -u '%s' 2>/dev/null || true`, systemUser)
	killSession.Run(killCmd)
	killSession.Close()

	// Small delay to let processes terminate
	time.Sleep(1 * time.Second)

	// Step 3: Delete the system user with home directory
	delSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for user deletion: %w", err)
	}
	defer delSession.Close()

	delCmd := fmt.Sprintf(`userdel -r '%s' 2>/dev/null || userdel '%s' 2>/dev/null`, systemUser, systemUser)
	if derr := delSession.Run(delCmd); derr != nil {
		return fmt.Errorf("failed to delete system user '%s': %w", systemUser, derr)
	}

	logging.Info("Deploy: successfully deleted system user '%s' from %s", systemUser, server.Hostname)
	s.logDeployment(key.ID, server.ID, "success", fmt.Sprintf("system user '%s' deleted", systemUser))
	return nil
}

// DisableSystemUser locks a system user account on a server by:
// - Removing the SSH key from authorized_keys
// - Locking the account (usermod --lock)
// - Setting the shell to /usr/sbin/nologin
func (s *Service) DisableSystemUser(key *models.SSHKey, server *models.Server, authPrivateKey []byte, systemUser string) error {
	logging.Info("Deploy: disabling system user '%s' on %s@%s:%d", systemUser, server.Username, server.Hostname, server.Port)

	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server for user disable: %w", err)
	}
	defer client.Close()

	// Step 1: Remove SSH key from authorized_keys
	removeSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for key removal: %w", err)
	}
	pubKey := strings.TrimSpace(key.PublicKey)
	escapedKey := strings.ReplaceAll(pubKey, "'", "'\\''")
	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}
	removeCmd := fmt.Sprintf(
		`grep -v '%s' %s/.ssh/authorized_keys > %s/.ssh/authorized_keys.tmp 2>/dev/null && mv %s/.ssh/authorized_keys.tmp %s/.ssh/authorized_keys && chmod 600 %s/.ssh/authorized_keys || true`,
		escapedKey, homeDir, homeDir, homeDir, homeDir, homeDir,
	)
	removeSession.Run(removeCmd)
	removeSession.Close()

	// Step 2: Lock the account
	lockSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for user lock: %w", err)
	}
	lockCmd := fmt.Sprintf(`usermod --lock '%s' 2>/dev/null || true`, systemUser)
	lockSession.Run(lockCmd)
	lockSession.Close()

	// Step 3: Set shell to nologin
	shellSession, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for shell change: %w", err)
	}
	defer shellSession.Close()
	shellCmd := fmt.Sprintf(`usermod --shell /usr/sbin/nologin '%s' 2>/dev/null || chsh -s /usr/sbin/nologin '%s' 2>/dev/null || true`, systemUser, systemUser)
	shellSession.Run(shellCmd)

	logging.Info("Deploy: successfully disabled system user '%s' on %s", systemUser, server.Hostname)
	s.logDeployment(key.ID, server.ID, "success", fmt.Sprintf("system user '%s' disabled (locked + nologin)", systemUser))
	return nil
}

// TestConnection tests TCP connectivity to a server (port reachable)
func (s *Service) TestConnection(hostname string, port int) error {
	logging.Debug("Testing TCP connection to %s:%d", hostname, port)
	addr := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", addr, err)
	}
	conn.Close()
	return nil
}

// TestSSHAuth tests actual SSH authentication to a server using a private key
func (s *Service) TestSSHAuth(hostname string, port int, username string, privateKey []byte) error {
	logging.Debug("Testing SSH auth for %s@%s:%d", username, hostname, port)

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse master key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH authentication failed: %w", err)
	}
	client.Close()
	return nil
}

// logDeployment records a deployment attempt
func (s *Service) logDeployment(keyID, serverID int64, status, message string) {
	s.db.Exec(
		`INSERT INTO key_deployments (ssh_key_id, server_id, status, message) VALUES (?, ?, ?, ?)`,
		keyID, serverID, status, message,
	)
}

// GetDeployments returns deployment history for a user's keys
func (s *Service) GetDeployments(userID int64) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(
		`SELECT kd.id, sk.name as key_name, srv.name as server_name, kd.status, kd.message, kd.deployed_at
		 FROM key_deployments kd
		 JOIN ssh_keys sk ON kd.ssh_key_id = sk.id
		 JOIN servers srv ON kd.server_id = srv.id
		 WHERE sk.user_id = ?
		 ORDER BY kd.deployed_at DESC LIMIT 50`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query deployments: %w", err)
	}
	defer rows.Close()

	var deployments []map[string]interface{}
	for rows.Next() {
		var id int64
		var keyName, serverName, status, message string
		var deployedAt time.Time
		if err := rows.Scan(&id, &keyName, &serverName, &status, &message, &deployedAt); err != nil {
			continue
		}
		deployments = append(deployments, map[string]interface{}{
			"id":          id,
			"key_name":    keyName,
			"server_name": serverName,
			"status":      status,
			"message":     message,
			"deployed_at": deployedAt,
		})
	}
	return deployments, nil
}

// ReadAuthorizedKeys reads the current authorized_keys for a system user on a remote server.
// Returns the list of key lines (non-empty, non-comment lines).
func (s *Service) ReadAuthorizedKeys(server *models.Server, authPrivateKey []byte, systemUser string) ([]string, error) {
	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}

	cmd := fmt.Sprintf(`cat %s/.ssh/authorized_keys 2>/dev/null || echo ""`, homeDir)
	output, err := session.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized_keys: %w", err)
	}

	var keys []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys, nil
}

// WriteAuthorizedKeys replaces the entire authorized_keys file for a system user on a remote server
// with the provided set of keys. This is the enforcement function.
func (s *Service) WriteAuthorizedKeys(server *models.Server, authPrivateKey []byte, systemUser string, authorizedKeys []string) error {
	signer, err := ssh.ParsePrivateKey(authPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse authentication key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(server.Hostname, fmt.Sprintf("%d", server.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	homeDir := fmt.Sprintf("/home/%s", systemUser)
	if systemUser == "root" {
		homeDir = "/root"
	}

	// Build the authorized_keys content
	content := strings.Join(authorizedKeys, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	// Use printf to write the content to avoid shell interpretation issues
	// First write to a temp file, then atomically move it
	escapedContent := strings.ReplaceAll(content, "'", "'\\''")
	cmd := fmt.Sprintf(
		`mkdir -p %s/.ssh && chmod 700 %s/.ssh && printf '%%s' '%s' > %s/.ssh/authorized_keys.tmp && mv %s/.ssh/authorized_keys.tmp %s/.ssh/authorized_keys && chmod 600 %s/.ssh/authorized_keys && chown '%s':'%s' %s/.ssh/authorized_keys`,
		homeDir, homeDir, escapedContent, homeDir, homeDir, homeDir, homeDir, systemUser, systemUser, homeDir,
	)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	return nil
}
