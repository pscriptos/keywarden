// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"fmt"

	"git.techniverse.net/scriptos/keywarden/internal/database"
	"git.techniverse.net/scriptos/keywarden/internal/encryption"
	"git.techniverse.net/scriptos/keywarden/internal/models"
	"git.techniverse.net/scriptos/keywarden/internal/sshutil"
)

// Service handles SSH key operations
type Service struct {
	db  *database.DB
	enc *encryption.Service
}

// NewService creates a new key service with encryption
func NewService(db *database.DB, enc *encryption.Service) *Service {
	return &Service{db: db, enc: enc}
}

// GenerateKey generates a new SSH key pair and stores it encrypted
func (s *Service) GenerateKey(userID int64, name, keyType string, bits int, comment string) (*models.SSHKey, error) {
	return s.generateKey(userID, name, keyType, bits, comment)
}

// generateKey is the internal key generation function
func (s *Service) generateKey(userID int64, name, keyType string, bits int, comment string) (*models.SSHKey, error) {
	var privPEM, pubKey []byte
	var fingerprint string
	var err error

	switch keyType {
	case "rsa":
		privPEM, pubKey, fingerprint, err = sshutil.GenerateRSAKey(bits, comment)
	case "ed25519":
		privPEM, pubKey, fingerprint, err = sshutil.GenerateEd25519Key(comment)
		bits = 256
	case "ed448":
		privPEM, pubKey, fingerprint, err = sshutil.GenerateEd448Key(comment)
		bits = 456
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt private key before storage
	encPrivKey, err := s.enc.Encrypt(string(privPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	result, err := s.db.Exec(
		`INSERT INTO ssh_keys (user_id, name, key_type, bits, fingerprint, public_key, private_key_enc) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, name, keyType, bits, fingerprint, string(pubKey), encPrivKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	id, _ := result.LastInsertId()
	return &models.SSHKey{
		ID:          id,
		UserID:      userID,
		Name:        name,
		KeyType:     keyType,
		Bits:        bits,
		Fingerprint: fingerprint,
		PublicKey:   string(pubKey),
	}, nil
}

// ImportKey imports an existing key pair (encrypts the private key)
func (s *Service) ImportKey(userID int64, name string, privateKeyPEM []byte) (*models.SSHKey, error) {
	pubKey, fingerprint, keyType, err := sshutil.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Map SSH key type names
	kt := "rsa"
	bits := 0
	switch keyType {
	case "ssh-rsa":
		kt = "rsa"
		bits = 2048 // approximate
	case "ssh-ed25519":
		kt = "ed25519"
		bits = 256
	case "ssh-ed448":
		kt = "ed448"
		bits = 456
	}

	// Encrypt private key before storage
	encPrivKey, err := s.enc.Encrypt(string(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	result, err := s.db.Exec(
		`INSERT INTO ssh_keys (user_id, name, key_type, bits, fingerprint, public_key, private_key_enc)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, name, kt, bits, fingerprint, string(pubKey), encPrivKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	id, _ := result.LastInsertId()
	return &models.SSHKey{
		ID:          id,
		UserID:      userID,
		Name:        name,
		KeyType:     kt,
		Bits:        bits,
		Fingerprint: fingerprint,
		PublicKey:   string(pubKey),
	}, nil
}

// GetKeysByUser returns all keys for a user
func (s *Service) GetKeysByUser(userID int64) ([]models.SSHKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, key_type, bits, fingerprint, public_key, created_at 
		 FROM ssh_keys WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	var keys []models.SSHKey
	for rows.Next() {
		var k models.SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyType, &k.Bits, &k.Fingerprint, &k.PublicKey, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// GetAllKeys returns all SSH keys for all users (admin use)
func (s *Service) GetAllKeys() ([]models.SSHKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, key_type, bits, fingerprint, public_key, created_at 
		 FROM ssh_keys ORDER BY user_id, name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all keys: %w", err)
	}
	defer rows.Close()

	var keys []models.SSHKey
	for rows.Next() {
		var k models.SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyType, &k.Bits, &k.Fingerprint, &k.PublicKey, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// GetKeyByID returns a specific key with decrypted private key
func (s *Service) GetKeyByID(keyID, userID int64) (*models.SSHKey, error) {
	key := &models.SSHKey{}
	var encPrivKey string
	err := s.db.QueryRow(
		`SELECT id, user_id, name, key_type, bits, fingerprint, public_key, private_key_enc, created_at 
		 FROM ssh_keys WHERE id = ? AND user_id = ?`, keyID, userID,
	).Scan(&key.ID, &key.UserID, &key.Name, &key.KeyType, &key.Bits, &key.Fingerprint, &key.PublicKey, &encPrivKey, &key.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Decrypt private key
	decrypted, err := s.enc.Decrypt(encPrivKey)
	if err != nil {
		// Fallback: might be an old unencrypted key
		key.PrivateKeyEnc = encPrivKey
	} else {
		key.PrivateKeyEnc = decrypted
	}

	return key, nil
}

// DeleteKey deletes a key
func (s *Service) DeleteKey(keyID, userID int64) error {
	result, err := s.db.Exec(`DELETE FROM ssh_keys WHERE id = ? AND user_id = ?`, keyID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("key not found")
	}
	return nil
}

// GetAllKeysWithOwner returns all SSH keys with their owner's username (for admin/owner views)
func (s *Service) GetAllKeysWithOwner() ([]models.SSHKeyWithOwner, error) {
	rows, err := s.db.Query(
		`SELECT k.id, k.user_id, k.name, k.key_type, k.bits, k.fingerprint, k.public_key, k.created_at,
		        COALESCE(u.username, '(deleted)')
		 FROM ssh_keys k
		 LEFT JOIN users u ON k.user_id = u.id
		 ORDER BY u.username ASC, k.name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all keys with owner: %w", err)
	}
	defer rows.Close()

	var keys []models.SSHKeyWithOwner
	for rows.Next() {
		var k models.SSHKeyWithOwner
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyType, &k.Bits, &k.Fingerprint, &k.PublicKey, &k.CreatedAt, &k.OwnerUsername); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// GetKeyByIDGlobal returns a specific key without user_id check (admin/owner access)
// Note: Private key is NOT returned decrypted — only metadata and public key
func (s *Service) GetKeyByIDGlobal(keyID int64) (*models.SSHKey, error) {
	key := &models.SSHKey{}
	err := s.db.QueryRow(
		`SELECT id, user_id, name, key_type, bits, fingerprint, public_key, created_at 
		 FROM ssh_keys WHERE id = ?`, keyID,
	).Scan(&key.ID, &key.UserID, &key.Name, &key.KeyType, &key.Bits, &key.Fingerprint, &key.PublicKey, &key.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}
	return key, nil
}

// DeleteKeyGlobal deletes a key without user_id check (admin/owner access)
func (s *Service) DeleteKeyGlobal(keyID int64) error {
	result, err := s.db.Exec(`DELETE FROM ssh_keys WHERE id = ?`, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("key not found")
	}
	return nil
}

// --- System Master Key ---
// The system master key is an Ed25519 key pair used by Keywarden to authenticate
// against remote servers for key deployments. It is generated once on first startup
// and stored encrypted in the settings table. It cannot be deleted, only regenerated.

// EnsureSystemMasterKey generates the system master key if it doesn't exist yet.
// Returns the public key string.
func (s *Service) EnsureSystemMasterKey() (string, error) {
	pub, err := s.getSetting("system_master_key_public")
	if err == nil && pub != "" {
		return pub, nil
	}
	// Generate new master key
	return s.generateSystemMasterKey()
}

// generateSystemMasterKey generates a new Ed25519 key pair and stores it in settings.
func (s *Service) generateSystemMasterKey() (string, error) {
	privPEM, pubKey, fingerprint, err := sshutil.GenerateEd25519Key("keywarden-system-master")
	if err != nil {
		return "", fmt.Errorf("failed to generate system master key: %w", err)
	}

	// Encrypt private key
	encPriv, err := s.enc.Encrypt(string(privPEM))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt system master key: %w", err)
	}

	pubStr := string(pubKey)

	// Store in settings table
	if err := s.setSetting("system_master_key_private", encPriv); err != nil {
		return "", fmt.Errorf("failed to store system master key private: %w", err)
	}
	if err := s.setSetting("system_master_key_public", pubStr); err != nil {
		return "", fmt.Errorf("failed to store system master key public: %w", err)
	}
	if err := s.setSetting("system_master_key_fingerprint", fingerprint); err != nil {
		return "", fmt.Errorf("failed to store system master key fingerprint: %w", err)
	}

	return pubStr, nil
}

// GetSystemMasterKeyPublic returns the public key of the system master key.
func (s *Service) GetSystemMasterKeyPublic() (string, error) {
	pub, err := s.getSetting("system_master_key_public")
	if err != nil || pub == "" {
		return "", fmt.Errorf("system master key not found")
	}
	return pub, nil
}

// GetSystemMasterKeyFingerprint returns the fingerprint of the system master key.
func (s *Service) GetSystemMasterKeyFingerprint() (string, error) {
	fp, err := s.getSetting("system_master_key_fingerprint")
	if err != nil || fp == "" {
		return "", fmt.Errorf("system master key fingerprint not found")
	}
	return fp, nil
}

// GetSystemMasterKeyPrivate returns the decrypted private key PEM of the system master key.
func (s *Service) GetSystemMasterKeyPrivate() ([]byte, error) {
	encPriv, err := s.getSetting("system_master_key_private")
	if err != nil || encPriv == "" {
		return nil, fmt.Errorf("system master key not found")
	}
	decrypted, err := s.enc.Decrypt(encPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt system master key: %w", err)
	}
	return []byte(decrypted), nil
}

// RegenerateSystemMasterKey generates a new system master key, replacing the old one.
// Returns the new public key string.
func (s *Service) RegenerateSystemMasterKey() (string, error) {
	return s.generateSystemMasterKey()
}

// getSetting reads a value from the settings table.
func (s *Service) getSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// setSetting writes a value to the settings table (upsert).
func (s *Service) setSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
		key, value,
	)
	return err
}

// EncryptValue encrypts a plaintext string using the application encryption key
func (s *Service) EncryptValue(plaintext string) (string, error) {
	return s.enc.Encrypt(plaintext)
}

// DecryptValue decrypts an encrypted string using the application encryption key
func (s *Service) DecryptValue(ciphertext string) (string, error) {
	return s.enc.Decrypt(ciphertext)
}
