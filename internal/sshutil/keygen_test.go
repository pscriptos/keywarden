// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package sshutil

import (
	"strings"
	"testing"
)

func TestGenerateEd25519Key(t *testing.T) {
	privPEM, pubKey, fingerprint, err := GenerateEd25519Key("test@keywarden")
	if err != nil {
		t.Fatalf("GenerateEd25519Key failed: %v", err)
	}

	if len(privPEM) == 0 {
		t.Fatal("Private key PEM is empty")
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
	if !strings.Contains(string(pubKey), "ssh-ed25519") {
		t.Fatal("Public key should contain ssh-ed25519")
	}
	if !strings.Contains(string(pubKey), "test@keywarden") {
		t.Fatal("Public key should contain the comment")
	}
	if !strings.Contains(string(privPEM), "PRIVATE KEY") {
		t.Fatal("Private key PEM should contain PRIVATE KEY header")
	}
}

func TestGenerateRSAKey2048(t *testing.T) {
	privPEM, pubKey, fingerprint, err := GenerateRSAKey(2048, "rsa-test")
	if err != nil {
		t.Fatalf("GenerateRSAKey(2048) failed: %v", err)
	}

	if len(privPEM) == 0 {
		t.Fatal("Private key PEM is empty")
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
	if !strings.Contains(string(pubKey), "ssh-rsa") {
		t.Fatal("Public key should contain ssh-rsa")
	}
	if !strings.Contains(string(pubKey), "rsa-test") {
		t.Fatal("Public key should contain the comment")
	}
}

func TestGenerateRSAKey4096(t *testing.T) {
	privPEM, pubKey, fingerprint, err := GenerateRSAKey(4096, "")
	if err != nil {
		t.Fatalf("GenerateRSAKey(4096) failed: %v", err)
	}

	if len(privPEM) == 0 {
		t.Fatal("Private key PEM is empty")
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
}

func TestGenerateRSAKeyInvalidBits(t *testing.T) {
	_, _, _, err := GenerateRSAKey(1024, "")
	if err == nil {
		t.Fatal("GenerateRSAKey(1024) should fail for unsupported key size")
	}

	_, _, _, err = GenerateRSAKey(3072, "")
	if err == nil {
		t.Fatal("GenerateRSAKey(3072) should fail for unsupported key size")
	}
}

func TestParsePrivateKeyEd25519(t *testing.T) {
	privPEM, expectedPub, _, err := GenerateEd25519Key("")
	if err != nil {
		t.Fatalf("GenerateEd25519Key failed: %v", err)
	}

	pubKey, fingerprint, keyType, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	if keyType != "ssh-ed25519" {
		t.Fatalf("Expected key type ssh-ed25519, got %q", keyType)
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
	if strings.TrimSpace(string(pubKey)) != strings.TrimSpace(string(expectedPub)) {
		t.Fatal("Parsed public key does not match generated public key")
	}
}

func TestParsePrivateKeyRSA(t *testing.T) {
	privPEM, _, _, err := GenerateRSAKey(2048, "")
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}

	_, fingerprint, keyType, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	if keyType != "ssh-rsa" {
		t.Fatalf("Expected key type ssh-rsa, got %q", keyType)
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
}

func TestParsePublicKey(t *testing.T) {
	_, pubKey, expectedFP, err := GenerateEd25519Key("")
	if err != nil {
		t.Fatalf("GenerateEd25519Key failed: %v", err)
	}

	fingerprint, keyType, err := ParsePublicKey(pubKey)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if keyType != "ssh-ed25519" {
		t.Fatalf("Expected key type ssh-ed25519, got %q", keyType)
	}
	if fingerprint != expectedFP {
		t.Fatalf("Fingerprint mismatch: got %q, want %q", fingerprint, expectedFP)
	}
}

func TestGenerateEd25519KeyUniqueness(t *testing.T) {
	_, pub1, fp1, err := GenerateEd25519Key("")
	if err != nil {
		t.Fatalf("GenerateEd25519Key 1 failed: %v", err)
	}

	_, pub2, fp2, err := GenerateEd25519Key("")
	if err != nil {
		t.Fatalf("GenerateEd25519Key 2 failed: %v", err)
	}

	if string(pub1) == string(pub2) {
		t.Fatal("Two generated keys should have different public keys")
	}
	if fp1 == fp2 {
		t.Fatal("Two generated keys should have different fingerprints")
	}
}

func TestGenerateEd448Key(t *testing.T) {
	privPEM, pubKey, fingerprint, err := GenerateEd448Key("test@keywarden")
	if err != nil {
		t.Fatalf("GenerateEd448Key failed: %v", err)
	}

	if len(privPEM) == 0 {
		t.Fatal("Private key PEM is empty")
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
	if !strings.Contains(string(pubKey), "ssh-ed448") {
		t.Fatal("Public key should contain ssh-ed448")
	}
	if !strings.Contains(string(pubKey), "test@keywarden") {
		t.Fatal("Public key should contain the comment")
	}
	if !strings.Contains(string(privPEM), "OPENSSH PRIVATE KEY") {
		t.Fatal("Private key PEM should contain OPENSSH PRIVATE KEY header")
	}
}

func TestGenerateEd448KeyUniqueness(t *testing.T) {
	_, pub1, fp1, err := GenerateEd448Key("")
	if err != nil {
		t.Fatalf("GenerateEd448Key 1 failed: %v", err)
	}

	_, pub2, fp2, err := GenerateEd448Key("")
	if err != nil {
		t.Fatalf("GenerateEd448Key 2 failed: %v", err)
	}

	if string(pub1) == string(pub2) {
		t.Fatal("Two generated Ed448 keys should have different public keys")
	}
	if fp1 == fp2 {
		t.Fatal("Two generated Ed448 keys should have different fingerprints")
	}
}

func TestGenerateEd448KeyNoComment(t *testing.T) {
	privPEM, pubKey, fingerprint, err := GenerateEd448Key("")
	if err != nil {
		t.Fatalf("GenerateEd448Key failed: %v", err)
	}

	if len(privPEM) == 0 {
		t.Fatal("Private key PEM is empty")
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint should start with SHA256:, got %q", fingerprint)
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	_, _, _, err := ParsePrivateKey([]byte("not a valid PEM"))
	if err == nil {
		t.Fatal("ParsePrivateKey should fail for invalid PEM")
	}
}

func TestParsePublicKeyInvalid(t *testing.T) {
	_, _, err := ParsePublicKey([]byte("not a valid public key"))
	if err == nil {
		t.Fatal("ParsePublicKey should fail for invalid key")
	}
}
