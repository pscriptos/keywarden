// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package cron

import (
	"crypto/rand"
	"fmt"
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

// Service handles scheduled key deployments
type Service struct {
	db      *database.DB
	deploy  *deploy.Service
	keys    *keys.Service
	servers *servers.Service
	audit   *audit.Service
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewService creates a new cron service
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

// Start begins the cron scheduler loop (checks every 30 seconds)
func (s *Service) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		// Run once immediately at startup
		s.tick()

		for {
			select {
			case <-ticker.C:
				s.tick()
			case <-s.stopCh:
				return
			}
		}
	}()
	logging.Info("Cron scheduler started")
}

// Stop gracefully stops the cron scheduler
func (s *Service) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// tick checks for jobs that need to run
func (s *Service) tick() {
	now := time.Now().UTC()
	jobs, err := s.GetPendingJobs(now)
	if err != nil {
		logging.Error("Cron: failed to get pending jobs: %v", err)
		return
	}

	for _, job := range jobs {
		s.executeJob(job)
	}
}

// executeJob runs a single cron job
func (s *Service) executeJob(job models.CronJob) {
	logging.Info("Cron: executing job '%s' (ID %d)", job.Name, job.ID)

	// Mark as running
	s.db.Exec(`UPDATE cron_jobs SET status = 'running', last_run = ? WHERE id = ?`, time.Now().UTC(), job.ID)

	// Use TargetUserID (the key owner) instead of UserID (the admin who created the job)
	key, err := s.keys.GetKeyByID(job.SSHKeyID, job.TargetUserID)
	if err != nil {
		s.failJob(job, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Use system master key for SSH authentication
	masterKeyPEM, err := s.keys.GetSystemMasterKeyPrivate()
	if err != nil {
		s.failJob(job, fmt.Sprintf("system master key not available: %v", err))
		return
	}

	// Read access config directly from the job
	systemUser := job.SystemUser
	createUser := job.CreateUser
	sudo := job.Sudo
	initialPassword := job.InitialPassword

	// Auto-generate initial password if createUser is enabled and no password is set
	if createUser && initialPassword == "" {
		initialPassword = generateInitialPassword(10)
		logging.Debug("Cron job '%s': auto-generated initial password for system user '%s'", job.Name, systemUser)
	}

	var targetServers []models.Server

	if job.ServerID > 0 {
		// Single server — use Global lookup since cron jobs are admin-created
		srv, err := s.servers.GetByIDGlobal(job.ServerID)
		if err != nil {
			s.failJob(job, fmt.Sprintf("server not found: %v", err))
			return
		}
		targetServers = append(targetServers, *srv)
	} else if job.GroupID > 0 {
		// Server group — use Global lookup since cron jobs are admin-created
		members, err := s.servers.GetGroupMembersGlobal(job.GroupID)
		if err != nil || len(members) == 0 {
			s.failJob(job, fmt.Sprintf("group members not found: %v", err))
			return
		}
		targetServers = members
	} else {
		s.failJob(job, "no target server or group specified")
		return
	}

	var successCount, failCount int
	for _, srv := range targetServers {
		server := srv
		var deployErr error
		if systemUser != "" {
			// Deploy to specific system user (from assignment)
			deployErr = s.deploy.DeployKeyToUser(key, &server, masterKeyPEM, systemUser, createUser, sudo, initialPassword)
		} else {
			// Legacy: deploy to server's default user (root)
			deployErr = s.deploy.DeployKey(key, &server, masterKeyPEM)
		}
		if deployErr != nil {
			failCount++
			logging.Error("Cron job '%s': deploy to %s@%s:%d failed: %v", job.Name, server.Username, server.Hostname, server.Port, deployErr)
		} else {
			successCount++
		}
	}

	// Log result
	targetInfo := ""
	if systemUser != "" {
		targetInfo = fmt.Sprintf(" (system user: %s)", systemUser)
	}
	details := fmt.Sprintf("Cron job '%s': deployed key '%s'%s — %d success, %d failed", job.Name, key.Name, targetInfo, successCount, failCount)
	if failCount > 0 && successCount == 0 {
		s.audit.Log(job.UserID, audit.ActionCronJobFailed, details, "cron")
	} else {
		s.audit.Log(job.UserID, audit.ActionCronJobExecuted, details, "cron")
	}

	// Store auto-generated initial password (encrypted) if it was generated and deploy succeeded
	if initialPassword != "" && job.InitialPassword == "" && successCount > 0 {
		if encPW, encErr := s.keys.EncryptValue(initialPassword); encErr == nil {
			s.db.Exec(`UPDATE cron_jobs SET initial_password = ? WHERE id = ?`, encPW, job.ID)
		} else {
			logging.Warn("Cron job '%s': failed to encrypt initial password: %v", job.Name, encErr)
		}
	}

	// Update job status
	if job.Schedule == "once" {
		// One-time job: mark as done
		s.db.Exec(`UPDATE cron_jobs SET status = 'done', last_run = ?, message = ? WHERE id = ?`,
			time.Now().UTC(), details, job.ID)
	} else {
		// Recurring job: calculate next run and stay active
		nextRun := CalculateNextRun(job)
		s.db.Exec(`UPDATE cron_jobs SET status = 'active', last_run = ?, next_run = ?, message = ? WHERE id = ?`,
			time.Now().UTC(), nextRun, details, job.ID)
	}

	// Handle auto-removal after expiry (for temporary deployments)
	if job.RemoveAfterMin > 0 {
		s.wg.Add(1)
		go func(j models.CronJob, serverList []models.Server, sshKey *models.SSHKey, masterPEM []byte) {
			defer s.wg.Done()
			timer := time.NewTimer(time.Duration(j.RemoveAfterMin) * time.Minute)
			select {
			case <-timer.C:
				s.handleExpiry(j, serverList, sshKey, masterPEM)
			case <-s.stopCh:
				timer.Stop()
				return
			}
		}(job, targetServers, key, masterKeyPEM)
	}
}

// handleExpiry handles the expiry action for a temporary access job
func (s *Service) handleExpiry(job models.CronJob, serverList []models.Server, key *models.SSHKey, masterKeyPEM []byte) {
	expiryAction := job.ExpiryAction
	if expiryAction == "" {
		expiryAction = "remove_key"
	}
	systemUser := job.SystemUser

	logging.Info("Cron: expiry action '%s' for key '%s' after %d minutes (job '%s')", expiryAction, key.Name, job.RemoveAfterMin, job.Name)

	for _, srv := range serverList {
		server := srv
		var err error
		switch expiryAction {
		case "disable_user":
			if systemUser != "" {
				err = s.deploy.DisableSystemUser(key, &server, masterKeyPEM, systemUser)
			} else {
				err = s.deploy.RemoveKey(key, &server, masterKeyPEM)
			}
		case "delete_user":
			if systemUser != "" {
				err = s.deploy.RemoveSystemUser(key, &server, masterKeyPEM, systemUser)
			} else {
				err = s.deploy.RemoveKey(key, &server, masterKeyPEM)
			}
		default: // "remove_key"
			if systemUser != "" {
				err = s.deploy.RemoveKeyFromUser(key, &server, masterKeyPEM, systemUser)
			} else {
				err = s.deploy.RemoveKey(key, &server, masterKeyPEM)
			}
		}
		if err != nil {
			logging.Error("Cron job '%s': expiry action '%s' on %s@%s:%d failed: %v", job.Name, expiryAction, server.Username, server.Hostname, server.Port, err)
		}
	}

	actionLabel := map[string]string{"remove_key": "removed key", "disable_user": "disabled user", "delete_user": "deleted user"}[expiryAction]
	details := fmt.Sprintf("Cron job '%s': %s '%s' on %d server(s) after %d min", job.Name, actionLabel, key.Name, len(serverList), job.RemoveAfterMin)
	s.audit.Log(job.UserID, audit.ActionCronJobKeyRemoved, details, "cron")
}

// failJob marks a job as failed
func (s *Service) failJob(job models.CronJob, msg string) {
	logging.Error("Cron job '%s' failed: %s", job.Name, msg)
	status := "failed"
	if job.Schedule != "once" {
		// Recurring jobs stay active but log the failure
		status = "active"
		nextRun := CalculateNextRun(job)
		s.db.Exec(`UPDATE cron_jobs SET status = ?, last_run = ?, next_run = ?, message = ? WHERE id = ?`,
			status, time.Now().UTC(), nextRun, msg, job.ID)
	} else {
		s.db.Exec(`UPDATE cron_jobs SET status = ?, last_run = ?, message = ? WHERE id = ?`,
			status, time.Now().UTC(), msg, job.ID)
	}
	s.audit.Log(job.UserID, audit.ActionCronJobFailed, fmt.Sprintf("Cron job '%s' failed: %s", job.Name, msg), "cron")
}

// CalculateNextRun computes the next execution time for recurring jobs.
// It uses the job's timezone and schedule parameters to ensure the execution
// time stays aligned (no drift). All returned times are in UTC.
func CalculateNextRun(job models.CronJob) time.Time {
	loc, err := time.LoadLocation(job.Timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)

	switch job.Schedule {
	case "hourly":
		// Next occurrence of the specified minute
		next := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), job.MinuteOfHour, 0, 0, loc)
		if !next.After(now) {
			next = next.Add(1 * time.Hour)
		}
		return next.UTC()

	case "daily":
		// Next occurrence of the specified time of day
		hour, minute := parseTimeOfDay(job.TimeOfDay)
		next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		return next.UTC()

	case "weekly":
		// Next occurrence of the specified weekday at the specified time
		hour, minute := parseTimeOfDay(job.TimeOfDay)
		targetDay := time.Weekday(job.DayOfWeek)
		next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, loc)
		daysUntil := int(targetDay) - int(now.Weekday())
		if daysUntil < 0 {
			daysUntil += 7
		}
		next = next.AddDate(0, 0, daysUntil)
		if !next.After(now) {
			next = next.AddDate(0, 0, 7)
		}
		return next.UTC()

	case "monthly":
		// Next occurrence of the specified day of month at the specified time
		hour, minute := parseTimeOfDay(job.TimeOfDay)
		day := job.DayOfMonth
		if day < 1 {
			day = 1
		}
		next := safeDate(now.Year(), now.Month(), day, hour, minute, loc)
		if !next.After(now) {
			next = safeDate(now.Year(), now.Month()+1, day, hour, minute, loc)
		}
		return next.UTC()

	default:
		return now.Add(24 * time.Hour).UTC()
	}
}

// CalculateFirstRun computes the initial next_run time for a new job.
// For "once", it uses the scheduled_at time directly.
// For recurring schedules, it finds the next matching time from now.
func CalculateFirstRun(job models.CronJob) time.Time {
	if job.Schedule == "once" {
		return job.ScheduledAt.UTC()
	}
	return CalculateNextRun(job)
}

// parseTimeOfDay parses "HH:MM" format and returns hour, minute
func parseTimeOfDay(tod string) (int, int) {
	var hour, minute int
	fmt.Sscanf(tod, "%d:%d", &hour, &minute)
	if hour < 0 || hour > 23 {
		hour = 0
	}
	if minute < 0 || minute > 59 {
		minute = 0
	}
	return hour, minute
}

// safeDate creates a date, clamping the day to the last day of the month
func safeDate(year int, month time.Month, day, hour, minute int, loc *time.Location) time.Time {
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
	if day > lastDay {
		day = lastDay
	}
	return time.Date(year, month, day, hour, minute, 0, 0, loc)
}

// --- Database Operations ---

// Create creates a new temporary access job
func (s *Service) Create(userID int64, name string, keyID, serverID, groupID int64, schedule string, scheduledAt time.Time, removeAfterMin int, tz, timeOfDay string, dayOfWeek, dayOfMonth, minuteOfHour int, targetUserID int64, systemUser string, sudo, createUser bool, initialPassword, expiryAction string) (*models.CronJob, error) {
	if expiryAction == "" {
		expiryAction = "remove_key"
	}
	job := models.CronJob{
		UserID:          userID,
		Name:            name,
		SSHKeyID:        keyID,
		ServerID:        serverID,
		GroupID:         groupID,
		Schedule:        schedule,
		ScheduledAt:     scheduledAt.UTC(),
		RemoveAfterMin:  removeAfterMin,
		Timezone:        tz,
		TimeOfDay:       timeOfDay,
		DayOfWeek:       dayOfWeek,
		DayOfMonth:      dayOfMonth,
		MinuteOfHour:    minuteOfHour,
		TargetUserID:    targetUserID,
		SystemUser:      systemUser,
		Sudo:            sudo,
		CreateUser:      createUser,
		InitialPassword: initialPassword,
		ExpiryAction:    expiryAction,
		Status:          "active",
	}

	nextRun := CalculateFirstRun(job)
	job.NextRun = nextRun

	result, err := s.db.Exec(
		`INSERT INTO cron_jobs (user_id, name, ssh_key_id, server_id, group_id, schedule, scheduled_at, next_run, remove_after_min, status, timezone, time_of_day, day_of_week, day_of_month, minute_of_hour, target_user_id, system_user, sudo, create_user, initial_password, expiry_action)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, name, keyID, serverID, groupID, schedule, scheduledAt.UTC(), nextRun, removeAfterMin,
		tz, timeOfDay, dayOfWeek, dayOfMonth, minuteOfHour, targetUserID, systemUser, sudo, createUser, initialPassword, expiryAction,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron job: %w", err)
	}

	id, _ := result.LastInsertId()
	job.ID = id
	return &job, nil
}

// GetByUser returns all cron jobs for a user
func (s *Service) GetByUser(userID int64) ([]models.CronJobDisplay, error) {
	rows, err := s.db.Query(
		`SELECT cj.id, cj.user_id, cj.name, cj.ssh_key_id, cj.server_id, cj.group_id,
		        cj.schedule, cj.scheduled_at, cj.next_run, cj.last_run, cj.remove_after_min,
		        cj.status, cj.message, cj.created_at,
		        cj.timezone, cj.time_of_day, cj.day_of_week, cj.day_of_month, cj.minute_of_hour,
		        cj.target_user_id, cj.system_user, cj.sudo, cj.create_user, cj.initial_password, cj.expiry_action,
		        COALESCE(sk.name, '(deleted)') as key_name,
		        COALESCE(srv.name, '') as server_name,
		        COALESCE(sg.name, '') as group_name,
		        COALESCE(tu.username, '') as target_username
		 FROM cron_jobs cj
		 LEFT JOIN ssh_keys sk ON cj.ssh_key_id = sk.id
		 LEFT JOIN servers srv ON cj.server_id = srv.id
		 LEFT JOIN server_groups sg ON cj.group_id = sg.id
		 LEFT JOIN users tu ON cj.target_user_id = tu.id
		 WHERE cj.user_id = ?
		 ORDER BY cj.created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query cron jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.CronJobDisplay
	for rows.Next() {
		var j models.CronJobDisplay
		var lastRun, message *string
		var serverName, groupName string
		if err := rows.Scan(
			&j.ID, &j.UserID, &j.Name, &j.SSHKeyID, &j.ServerID, &j.GroupID,
			&j.Schedule, &j.ScheduledAt, &j.NextRun, &lastRun, &j.RemoveAfterMin,
			&j.Status, &message, &j.CreatedAt,
			&j.Timezone, &j.TimeOfDay, &j.DayOfWeek, &j.DayOfMonth, &j.MinuteOfHour,
			&j.TargetUserID, &j.SystemUser, &j.Sudo, &j.CreateUser, &j.InitialPassword, &j.ExpiryAction,
			&j.KeyName, &serverName, &groupName,
			&j.TargetUsername,
		); err != nil {
			continue
		}
		if lastRun != nil {
			if t, ok := parseTimeString(*lastRun); ok {
				j.LastRun = &t
			}
		}
		if message != nil {
			j.Message = *message
		}
		if serverName != "" {
			j.TargetName = serverName
			j.TargetType = "host"
		} else if groupName != "" {
			j.TargetName = groupName
			j.TargetType = "group"
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

// GetByID returns a specific cron job
func (s *Service) GetByID(jobID, userID int64) (*models.CronJob, error) {
	job := &models.CronJob{}
	var lastRun, message *string
	err := s.db.QueryRow(
		`SELECT id, user_id, name, ssh_key_id, server_id, group_id, schedule, scheduled_at, next_run, last_run, remove_after_min, status, message, created_at,
		        timezone, time_of_day, day_of_week, day_of_month, minute_of_hour, target_user_id,
		        system_user, sudo, create_user, initial_password, expiry_action
		 FROM cron_jobs WHERE id = ? AND user_id = ?`, jobID, userID,
	).Scan(&job.ID, &job.UserID, &job.Name, &job.SSHKeyID, &job.ServerID, &job.GroupID,
		&job.Schedule, &job.ScheduledAt, &job.NextRun, &lastRun, &job.RemoveAfterMin,
		&job.Status, &message, &job.CreatedAt,
		&job.Timezone, &job.TimeOfDay, &job.DayOfWeek, &job.DayOfMonth, &job.MinuteOfHour,
		&job.TargetUserID,
		&job.SystemUser, &job.Sudo, &job.CreateUser, &job.InitialPassword, &job.ExpiryAction)
	if err != nil {
		return nil, fmt.Errorf("cron job not found: %w", err)
	}
	if lastRun != nil {
		if t, ok := parseTimeString(*lastRun); ok {
			job.LastRun = &t
		}
	}
	if message != nil {
		job.Message = *message
	}
	return job, nil
}

// Update updates a temporary access job
func (s *Service) Update(jobID, userID int64, name string, keyID, serverID, groupID int64, schedule string, scheduledAt time.Time, removeAfterMin int, tz, timeOfDay string, dayOfWeek, dayOfMonth, minuteOfHour int, targetUserID int64, systemUser string, sudo, createUser bool, initialPassword, expiryAction string) error {
	if expiryAction == "" {
		expiryAction = "remove_key"
	}
	job := models.CronJob{
		UserID:          userID,
		Name:            name,
		SSHKeyID:        keyID,
		ServerID:        serverID,
		GroupID:         groupID,
		Schedule:        schedule,
		ScheduledAt:     scheduledAt.UTC(),
		RemoveAfterMin:  removeAfterMin,
		Timezone:        tz,
		TimeOfDay:       timeOfDay,
		DayOfWeek:       dayOfWeek,
		DayOfMonth:      dayOfMonth,
		MinuteOfHour:    minuteOfHour,
		TargetUserID:    targetUserID,
		SystemUser:      systemUser,
		Sudo:            sudo,
		CreateUser:      createUser,
		InitialPassword: initialPassword,
		ExpiryAction:    expiryAction,
	}

	nextRun := CalculateFirstRun(job)

	result, err := s.db.Exec(
		`UPDATE cron_jobs SET name=?, ssh_key_id=?, server_id=?, group_id=?, schedule=?, scheduled_at=?, next_run=?, remove_after_min=?, status='active',
		        timezone=?, time_of_day=?, day_of_week=?, day_of_month=?, minute_of_hour=?,
		        target_user_id=?, system_user=?, sudo=?, create_user=?, initial_password=?, expiry_action=?
		 WHERE id=? AND user_id=?`,
		name, keyID, serverID, groupID, schedule, scheduledAt.UTC(), nextRun, removeAfterMin,
		tz, timeOfDay, dayOfWeek, dayOfMonth, minuteOfHour,
		targetUserID, systemUser, sudo, createUser, initialPassword, expiryAction,
		jobID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update cron job: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("cron job not found")
	}
	return nil
}

// Delete removes a cron job
func (s *Service) Delete(jobID, userID int64) error {
	result, err := s.db.Exec(`DELETE FROM cron_jobs WHERE id = ? AND user_id = ?`, jobID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete cron job: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("cron job not found")
	}
	return nil
}

// TogglePause pauses or resumes a cron job
func (s *Service) TogglePause(jobID, userID int64) error {
	job, err := s.GetByID(jobID, userID)
	if err != nil {
		return err
	}

	newStatus := "paused"
	if job.Status == "paused" {
		newStatus = "active"
		// Recalculate next run when resuming
		nextRun := CalculateNextRun(*job)
		_, err = s.db.Exec(`UPDATE cron_jobs SET status = ?, next_run = ? WHERE id = ? AND user_id = ?`, newStatus, nextRun, jobID, userID)
		return err
	}

	_, err = s.db.Exec(`UPDATE cron_jobs SET status = ? WHERE id = ? AND user_id = ?`, newStatus, jobID, userID)
	return err
}

// GetPendingJobs returns jobs that are due for execution
func (s *Service) GetPendingJobs(now time.Time) ([]models.CronJob, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, ssh_key_id, server_id, group_id, schedule, scheduled_at, next_run, last_run, remove_after_min, status, message, created_at,
		        timezone, time_of_day, day_of_week, day_of_month, minute_of_hour, target_user_id,
		        system_user, sudo, create_user, initial_password, expiry_action
		 FROM cron_jobs
		 WHERE status = 'active' AND next_run <= ?
		 ORDER BY next_run ASC`, now.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending jobs: %w", err)
	}
	defer rows.Close()

	var jobs []models.CronJob
	for rows.Next() {
		var j models.CronJob
		var lastRun, message *string
		if err := rows.Scan(&j.ID, &j.UserID, &j.Name, &j.SSHKeyID, &j.ServerID, &j.GroupID,
			&j.Schedule, &j.ScheduledAt, &j.NextRun, &lastRun, &j.RemoveAfterMin,
			&j.Status, &message, &j.CreatedAt,
			&j.Timezone, &j.TimeOfDay, &j.DayOfWeek, &j.DayOfMonth, &j.MinuteOfHour,
			&j.TargetUserID,
			&j.SystemUser, &j.Sudo, &j.CreateUser, &j.InitialPassword, &j.ExpiryAction); err != nil {
			continue
		}
		if lastRun != nil {
			if t, ok := parseTimeString(*lastRun); ok {
				j.LastRun = &t
			}
		}
		if message != nil {
			j.Message = *message
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

// CountByUser returns total cron jobs for a user
func (s *Service) CountByUser(userID int64) int {
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM cron_jobs WHERE user_id = ?`, userID).Scan(&count)
	return count
}

// parseTimeString tries multiple time formats to parse a SQLite datetime string
func parseTimeString(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// generateInitialPassword generates a random alphanumeric password
func generateInitialPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
