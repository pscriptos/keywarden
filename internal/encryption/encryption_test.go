// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package encryption

import (
	"strings"
	"testing"
)

func TestNewService(t *testing.T) {
	svc := NewService("test-passphrase")
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if len(svc.key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(svc.key))
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	svc := NewService("my-secret-passphrase-32-chars!!")
	plaintext := "This is a private SSH key content"

	encrypted, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted text should differ from plaintext")
	}

	decrypted, err := svc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	svc := NewService("test-passphrase")
	plaintext := "same input"

	enc1, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}

	enc2, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	if enc1 == enc2 {
		t.Fatal("Two encryptions of the same plaintext should produce different ciphertexts (random nonce)")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	svc1 := NewService("correct-passphrase")
	svc2 := NewService("wrong-passphrase")

	encrypted, err := svc1.Encrypt("secret data")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = svc2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("Decrypt with wrong key should fail")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	svc := NewService("test")
	_, err := svc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Fatal("Decrypt of invalid base64 should fail")
	}
}

func TestDecryptTooShort(t *testing.T) {
	svc := NewService("test")
	// Valid base64 but too short for nonce + ciphertext
	_, err := svc.Decrypt("AQID")
	if err == nil {
		t.Fatal("Decrypt of too-short ciphertext should fail")
	}
}

func TestEncryptEmptyString(t *testing.T) {
	svc := NewService("test")

	encrypted, err := svc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty string failed: %v", err)
	}

	decrypted, err := svc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt empty string failed: %v", err)
	}

	if decrypted != "" {
		t.Fatalf("Expected empty string, got %q", decrypted)
	}
}

func TestEncryptLargePayload(t *testing.T) {
	svc := NewService("test")
	// Simulate a large SSH private key
	large := strings.Repeat("A", 4096)

	encrypted, err := svc.Encrypt(large)
	if err != nil {
		t.Fatalf("Encrypt large payload failed: %v", err)
	}

	decrypted, err := svc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt large payload failed: %v", err)
	}

	if decrypted != large {
		t.Fatal("Large payload roundtrip mismatch")
	}
}
