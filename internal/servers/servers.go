// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package servers

import (
	"fmt"

	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/models"
)

// Service handles server management
type Service struct {
	db *database.DB
}

// NewService creates a new server service
func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Create adds a new server
func (s *Service) Create(userID int64, name, hostname string, port int, username, description string) (*models.Server, error) {
	if port == 0 {
		port = 22
	}

	result, err := s.db.Exec(
		`INSERT INTO servers (user_id, name, hostname, port, username, description) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, name, hostname, port, username, description,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	id, _ := result.LastInsertId()
	return &models.Server{
		ID:          id,
		UserID:      userID,
		Name:        name,
		Hostname:    hostname,
		Port:        port,
		Username:    username,
		Description: description,
	}, nil
}

// GetByUser returns all servers for a user
func (s *Service) GetByUser(userID int64) ([]models.Server, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, hostname, port, username, description, created_at, updated_at
		 FROM servers WHERE user_id = ? ORDER BY name ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query servers: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// GetByID returns a specific server
func (s *Service) GetByID(serverID, userID int64) (*models.Server, error) {
	srv := &models.Server{}
	err := s.db.QueryRow(
		`SELECT id, user_id, name, hostname, port, username, description, created_at, updated_at
		 FROM servers WHERE id = ? AND user_id = ?`, serverID, userID,
	).Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("server not found: %w", err)
	}
	return srv, nil
}

// Update modifies a server
func (s *Service) Update(serverID, userID int64, name, hostname string, port int, username, description string) error {
	result, err := s.db.Exec(
		`UPDATE servers SET name=?, hostname=?, port=?, username=?, description=?, updated_at=CURRENT_TIMESTAMP
		 WHERE id=? AND user_id=?`,
		name, hostname, port, username, description, serverID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server not found")
	}
	return nil
}

// Delete removes a server
func (s *Service) Delete(serverID, userID int64) error {
	result, err := s.db.Exec(`DELETE FROM servers WHERE id = ? AND user_id = ?`, serverID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server not found")
	}
	return nil
}

// --- Server Groups ---

// CreateGroup creates a new server group
func (s *Service) CreateGroup(userID int64, name, description string) (*models.ServerGroup, error) {
	result, err := s.db.Exec(
		`INSERT INTO server_groups (user_id, name, description) VALUES (?, ?, ?)`,
		userID, name, description,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server group: %w", err)
	}
	id, _ := result.LastInsertId()
	return &models.ServerGroup{
		ID:          id,
		UserID:      userID,
		Name:        name,
		Description: description,
	}, nil
}

// GetGroupsByUser returns all server groups for a user with server counts
func (s *Service) GetGroupsByUser(userID int64) ([]models.ServerGroupWithCount, error) {
	rows, err := s.db.Query(
		`SELECT sg.id, sg.user_id, sg.name, sg.description, sg.created_at, sg.updated_at,
		        COUNT(sgm.server_id) as server_count
		 FROM server_groups sg
		 LEFT JOIN server_group_members sgm ON sg.id = sgm.group_id
		 WHERE sg.user_id = ?
		 GROUP BY sg.id
		 ORDER BY sg.name ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query server groups: %w", err)
	}
	defer rows.Close()

	var groups []models.ServerGroupWithCount
	for rows.Next() {
		var g models.ServerGroupWithCount
		if err := rows.Scan(&g.ID, &g.UserID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.ServerCount); err != nil {
			return nil, fmt.Errorf("failed to scan server group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// GetGroupByID returns a specific server group
func (s *Service) GetGroupByID(groupID, userID int64) (*models.ServerGroup, error) {
	g := &models.ServerGroup{}
	err := s.db.QueryRow(
		`SELECT id, user_id, name, description, created_at, updated_at
		 FROM server_groups WHERE id = ? AND user_id = ?`, groupID, userID,
	).Scan(&g.ID, &g.UserID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("server group not found: %w", err)
	}
	return g, nil
}

// UpdateGroup modifies a server group
func (s *Service) UpdateGroup(groupID, userID int64, name, description string) error {
	result, err := s.db.Exec(
		`UPDATE server_groups SET name=?, description=?, updated_at=CURRENT_TIMESTAMP
		 WHERE id=? AND user_id=?`,
		name, description, groupID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update server group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server group not found")
	}
	return nil
}

// DeleteGroup removes a server group
func (s *Service) DeleteGroup(groupID, userID int64) error {
	result, err := s.db.Exec(`DELETE FROM server_groups WHERE id = ? AND user_id = ?`, groupID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete server group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server group not found")
	}
	return nil
}

// AddServerToGroup adds a server to a group
func (s *Service) AddServerToGroup(groupID, serverID, userID int64) error {
	// Verify group belongs to user
	_, err := s.GetGroupByID(groupID, userID)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	// Verify server belongs to user
	_, err = s.GetByID(serverID, userID)
	if err != nil {
		return fmt.Errorf("server not found: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO server_group_members (group_id, server_id) VALUES (?, ?)`,
		groupID, serverID,
	)
	if err != nil {
		return fmt.Errorf("failed to add server to group: %w", err)
	}
	return nil
}

// RemoveServerFromGroup removes a server from a group
func (s *Service) RemoveServerFromGroup(groupID, serverID, userID int64) error {
	// Verify group belongs to user
	_, err := s.GetGroupByID(groupID, userID)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	_, err = s.db.Exec(
		`DELETE FROM server_group_members WHERE group_id = ? AND server_id = ?`,
		groupID, serverID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove server from group: %w", err)
	}
	return nil
}

// AddServerToGroupGlobal adds a server to a group without user_id check
func (s *Service) AddServerToGroupGlobal(groupID, serverID int64) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO server_group_members (group_id, server_id) VALUES (?, ?)`,
		groupID, serverID,
	)
	if err != nil {
		return fmt.Errorf("failed to add server to group: %w", err)
	}
	return nil
}

// RemoveServerFromGroupGlobal removes a server from a group without user_id check
func (s *Service) RemoveServerFromGroupGlobal(groupID, serverID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM server_group_members WHERE group_id = ? AND server_id = ?`,
		groupID, serverID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove server from group: %w", err)
	}
	return nil
}

// GetGroupMembers returns all servers in a group
func (s *Service) GetGroupMembers(groupID, userID int64) ([]models.Server, error) {
	rows, err := s.db.Query(
		`SELECT s.id, s.user_id, s.name, s.hostname, s.port, s.username, s.description, s.created_at, s.updated_at
		 FROM servers s
		 JOIN server_group_members sgm ON s.id = sgm.server_id
		 WHERE sgm.group_id = ? AND s.user_id = ?
		 ORDER BY s.name ASC`, groupID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// GetGroupIDsForServer returns all group IDs that a server belongs to
func (s *Service) GetGroupIDsForServer(serverID, userID int64) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT sgm.group_id FROM server_group_members sgm
		 JOIN server_groups sg ON sg.id = sgm.group_id
		 WHERE sgm.server_id = ? AND sg.user_id = ?`, serverID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query server groups: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// SetServerGroups replaces all group memberships for a server
func (s *Service) SetServerGroups(serverID, userID int64, groupIDs []int64) error {
	// Verify server belongs to user
	_, err := s.GetByID(serverID, userID)
	if err != nil {
		return fmt.Errorf("server not found: %w", err)
	}

	// Remove all current group memberships for this server
	_, err = s.db.Exec(`DELETE FROM server_group_members WHERE server_id = ?`, serverID)
	if err != nil {
		return fmt.Errorf("failed to clear group memberships: %w", err)
	}

	// Add new memberships
	for _, gid := range groupIDs {
		// Verify group belongs to user
		_, err := s.GetGroupByID(gid, userID)
		if err != nil {
			continue
		}
		_, err = s.db.Exec(
			`INSERT OR IGNORE INTO server_group_members (group_id, server_id) VALUES (?, ?)`,
			gid, serverID,
		)
		if err != nil {
			return fmt.Errorf("failed to add server to group: %w", err)
		}
	}
	return nil
}

// GetGroupMemberIDs returns server IDs in a group
func (s *Service) GetGroupMemberIDs(groupID, userID int64) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT sgm.server_id FROM server_group_members sgm
		 JOIN servers s ON s.id = sgm.server_id
		 WHERE sgm.group_id = ? AND s.user_id = ?`, groupID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query group member IDs: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// --- Global queries (admin/owner) ---

// GetAllServers returns all servers regardless of owner
func (s *Service) GetAllServers() ([]models.Server, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, hostname, port, username, description, created_at, updated_at
		 FROM servers ORDER BY name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all servers: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// GetAllGroups returns all server groups regardless of owner
func (s *Service) GetAllGroups() ([]models.ServerGroupWithCount, error) {
	rows, err := s.db.Query(
		`SELECT sg.id, sg.user_id, sg.name, sg.description, sg.created_at, sg.updated_at,
		        COUNT(sgm.server_id) as server_count
		 FROM server_groups sg
		 LEFT JOIN server_group_members sgm ON sg.id = sgm.group_id
		 GROUP BY sg.id
		 ORDER BY sg.name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all server groups: %w", err)
	}
	defer rows.Close()

	var groups []models.ServerGroupWithCount
	for rows.Next() {
		var g models.ServerGroupWithCount
		if err := rows.Scan(&g.ID, &g.UserID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.ServerCount); err != nil {
			return nil, fmt.Errorf("failed to scan server group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// --- Global access functions (admin/owner) ---

// GetByIDGlobal returns a server without user_id check (admin/owner access)
func (s *Service) GetByIDGlobal(serverID int64) (*models.Server, error) {
	srv := &models.Server{}
	err := s.db.QueryRow(
		`SELECT id, user_id, name, hostname, port, username, description, created_at, updated_at
		 FROM servers WHERE id = ?`, serverID,
	).Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("server not found: %w", err)
	}
	return srv, nil
}

// UpdateGlobal modifies a server without user_id check (admin/owner access)
func (s *Service) UpdateGlobal(serverID int64, name, hostname string, port int, username, description string) error {
	result, err := s.db.Exec(
		`UPDATE servers SET name=?, hostname=?, port=?, username=?, description=?, updated_at=CURRENT_TIMESTAMP
		 WHERE id=?`,
		name, hostname, port, username, description, serverID,
	)
	if err != nil {
		return fmt.Errorf("failed to update server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server not found")
	}
	return nil
}

// DeleteGlobal removes a server without user_id check (admin/owner access)
func (s *Service) DeleteGlobal(serverID int64) error {
	result, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, serverID)
	if err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server not found")
	}
	return nil
}

// GetGroupByIDGlobal returns a server group without user_id check
func (s *Service) GetGroupByIDGlobal(groupID int64) (*models.ServerGroup, error) {
	g := &models.ServerGroup{}
	err := s.db.QueryRow(
		`SELECT id, user_id, name, description, created_at, updated_at
		 FROM server_groups WHERE id = ?`, groupID,
	).Scan(&g.ID, &g.UserID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("server group not found: %w", err)
	}
	return g, nil
}

// UpdateGroupGlobal modifies a server group without user_id check
func (s *Service) UpdateGroupGlobal(groupID int64, name, description string) error {
	result, err := s.db.Exec(
		`UPDATE server_groups SET name=?, description=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		name, description, groupID,
	)
	if err != nil {
		return fmt.Errorf("failed to update server group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server group not found")
	}
	return nil
}

// DeleteGroupGlobal removes a server group without user_id check
func (s *Service) DeleteGroupGlobal(groupID int64) error {
	result, err := s.db.Exec(`DELETE FROM server_groups WHERE id = ?`, groupID)
	if err != nil {
		return fmt.Errorf("failed to delete server group: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("server group not found")
	}
	return nil
}

// GetGroupMembersGlobal returns all servers in a group without user_id check
func (s *Service) GetGroupMembersGlobal(groupID int64) ([]models.Server, error) {
	rows, err := s.db.Query(
		`SELECT s.id, s.user_id, s.name, s.hostname, s.port, s.username, s.description, s.created_at, s.updated_at
		 FROM servers s
		 JOIN server_group_members sgm ON s.id = sgm.server_id
		 WHERE sgm.group_id = ?
		 ORDER BY s.name ASC`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query group members: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// GetGroupIDsForServerGlobal returns all group IDs that a server belongs to (without user_id check)
func (s *Service) GetGroupIDsForServerGlobal(serverID int64) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT sgm.group_id FROM server_group_members sgm WHERE sgm.server_id = ?`, serverID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query server groups: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// SetServerGroupsGlobal replaces all group memberships for a server (without user_id check)
func (s *Service) SetServerGroupsGlobal(serverID int64, groupIDs []int64) error {
	_, err := s.db.Exec(`DELETE FROM server_group_members WHERE server_id = ?`, serverID)
	if err != nil {
		return fmt.Errorf("failed to clear group memberships: %w", err)
	}

	for _, gid := range groupIDs {
		_, err = s.db.Exec(
			`INSERT OR IGNORE INTO server_group_members (group_id, server_id) VALUES (?, ?)`,
			gid, serverID,
		)
		if err != nil {
			return fmt.Errorf("failed to add server to group: %w", err)
		}
	}
	return nil
}

// GetServersByAssignedUser returns hosts that a user has access to via assignments
func (s *Service) GetServersByAssignedUser(userID int64) ([]models.Server, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT s.id, s.user_id, s.name, s.hostname, s.port, s.username, s.description, s.created_at, s.updated_at
		 FROM servers s
		 WHERE s.id IN (
		   SELECT a.server_id FROM access_assignments a WHERE a.user_id = ? AND a.server_id > 0
		   UNION
		   SELECT sgm.server_id FROM access_assignments a
		   JOIN server_group_members sgm ON a.group_id = sgm.group_id
		   WHERE a.user_id = ? AND a.group_id > 0
		 )
		 ORDER BY s.name ASC`, userID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query assigned servers: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		var srv models.Server
		if err := rows.Scan(&srv.ID, &srv.UserID, &srv.Name, &srv.Hostname, &srv.Port, &srv.Username, &srv.Description, &srv.CreatedAt, &srv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan server: %w", err)
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// UpdateAssignmentStatus updates the sync status of an assignment
func (s *Service) UpdateAssignmentStatus(id int64, status, message string) error {
	_, err := s.db.Exec(
		`UPDATE access_assignments SET status=?, last_sync_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		status, id,
	)
	return err
}

// --- Access Assignments ---

// CreateAssignment creates a new access assignment
func (s *Service) CreateAssignment(userID, sshKeyID, serverID, groupID int64, systemUser, desiredState string, sudo, createUser bool) (*models.AccessAssignment, error) {
	sudoInt := 0
	if sudo {
		sudoInt = 1
	}
	createUserInt := 0
	if createUser {
		createUserInt = 1
	}
	if desiredState == "" {
		desiredState = "present"
	}
	result, err := s.db.Exec(
		`INSERT INTO access_assignments (user_id, ssh_key_id, server_id, group_id, system_user, desired_state, sudo, create_user)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, sshKeyID, serverID, groupID, systemUser, desiredState, sudoInt, createUserInt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create assignment: %w", err)
	}
	id, _ := result.LastInsertId()
	return &models.AccessAssignment{
		ID:           id,
		UserID:       userID,
		SSHKeyID:     sshKeyID,
		ServerID:     serverID,
		GroupID:      groupID,
		SystemUser:   systemUser,
		DesiredState: desiredState,
		Sudo:         sudo,
		CreateUser:   createUser,
		Status:       "pending",
	}, nil
}

// GetAllAssignments returns all access assignments with resolved display names
func (s *Service) GetAllAssignments() ([]models.AccessAssignmentDisplay, error) {
	rows, err := s.db.Query(
		`SELECT a.id, a.user_id, a.ssh_key_id, a.server_id, a.group_id,
		        a.system_user, a.desired_state, a.sudo, a.create_user,
		        a.status, a.initial_password, a.last_sync_at, a.created_at, a.updated_at,
		        u.username,
		        COALESCE(k.name, '(deleted)'),
		        CASE
		          WHEN a.server_id > 0 THEN COALESCE(s.name, '(deleted)')
		          WHEN a.group_id > 0 THEN COALESCE(sg.name, '(deleted)')
		          ELSE '(none)'
		        END,
		        CASE
		          WHEN a.server_id > 0 THEN 'host'
		          WHEN a.group_id > 0 THEN 'group'
		          ELSE 'none'
		        END
		 FROM access_assignments a
		 LEFT JOIN users u ON a.user_id = u.id
		 LEFT JOIN ssh_keys k ON a.ssh_key_id = k.id
		 LEFT JOIN servers s ON a.server_id = s.id AND a.server_id > 0
		 LEFT JOIN server_groups sg ON a.group_id = sg.id AND a.group_id > 0
		 ORDER BY a.created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query assignments: %w", err)
	}
	defer rows.Close()

	var assignments []models.AccessAssignmentDisplay
	for rows.Next() {
		var a models.AccessAssignmentDisplay
		var sudo, createUser int
		if err := rows.Scan(&a.ID, &a.UserID, &a.SSHKeyID, &a.ServerID, &a.GroupID,
			&a.SystemUser, &a.DesiredState, &sudo, &createUser,
			&a.Status, &a.InitialPassword, &a.LastSyncAt, &a.CreatedAt, &a.UpdatedAt,
			&a.Username, &a.KeyName, &a.TargetName, &a.TargetType); err != nil {
			return nil, fmt.Errorf("failed to scan assignment: %w", err)
		}
		a.Sudo = sudo == 1
		a.CreateUser = createUser == 1
		assignments = append(assignments, a)
	}
	return assignments, nil
}

// GetAssignmentsByUser returns access assignments for a specific user
func (s *Service) GetAssignmentsByUser(userID int64) ([]models.AccessAssignmentDisplay, error) {
	all, err := s.GetAllAssignments()
	if err != nil {
		return nil, err
	}
	var filtered []models.AccessAssignmentDisplay
	for _, a := range all {
		if a.UserID == userID {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

// GetAssignmentByID returns a single access assignment
func (s *Service) GetAssignmentByID(id int64) (*models.AccessAssignment, error) {
	a := &models.AccessAssignment{}
	var sudo, createUser int
	err := s.db.QueryRow(
		`SELECT id, user_id, ssh_key_id, server_id, group_id, system_user, desired_state,
		        sudo, create_user, initial_password, status, last_sync_at, created_at, updated_at
		 FROM access_assignments WHERE id = ?`, id,
	).Scan(&a.ID, &a.UserID, &a.SSHKeyID, &a.ServerID, &a.GroupID, &a.SystemUser, &a.DesiredState,
		&sudo, &createUser, &a.InitialPassword, &a.Status, &a.LastSyncAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("assignment not found: %w", err)
	}
	a.Sudo = sudo == 1
	a.CreateUser = createUser == 1
	return a, nil
}

// UpdateAssignment updates an existing access assignment
func (s *Service) UpdateAssignment(id, userID, sshKeyID, serverID, groupID int64, systemUser, desiredState string, sudo, createUser bool) error {
	sudoInt := 0
	if sudo {
		sudoInt = 1
	}
	createUserInt := 0
	if createUser {
		createUserInt = 1
	}
	result, err := s.db.Exec(
		`UPDATE access_assignments SET user_id=?, ssh_key_id=?, server_id=?, group_id=?,
		        system_user=?, desired_state=?, sudo=?, create_user=?, status='pending', updated_at=CURRENT_TIMESTAMP
		 WHERE id=?`,
		userID, sshKeyID, serverID, groupID, systemUser, desiredState, sudoInt, createUserInt, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update assignment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("assignment not found")
	}
	return nil
}

// DeleteAssignment removes an access assignment
func (s *Service) DeleteAssignment(id int64) error {
	result, err := s.db.Exec(`DELETE FROM access_assignments WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete assignment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("assignment not found")
	}
	return nil
}

// UpdateAssignmentInitialPassword stores the encrypted initial password for an assignment
func (s *Service) UpdateAssignmentInitialPassword(id int64, encryptedPassword string) error {
	_, err := s.db.Exec(
		`UPDATE access_assignments SET initial_password=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		encryptedPassword, id,
	)
	return err
}
