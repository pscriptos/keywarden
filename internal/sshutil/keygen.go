// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package sshutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"golang.org/x/crypto/ssh"
)

// GenerateRSAKey generates an RSA key pair with the given bit size (2048 or 4096)
func GenerateRSAKey(bits int, comment string) (privateKeyPEM []byte, publicKey []byte, fingerprint string, err error) {
	if bits != 2048 && bits != 4096 {
		return nil, nil, "", fmt.Errorf("unsupported RSA key size: %d (use 2048 or 4096)", bits)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: marshalRSAPrivateKey(privKey),
	})

	// Generate SSH public key
	pub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create SSH public key: %w", err)
	}

	pubBytes := appendComment(ssh.MarshalAuthorizedKey(pub), comment)
	fp := fingerprintSHA256(pub)

	return privPEM, pubBytes, fp, nil
}

// GenerateEd25519Key generates an Ed25519 key pair
func GenerateEd25519Key(comment string) (privateKeyPEM []byte, publicKey []byte, fingerprint string, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Encode private key to PEM using OpenSSH format
	privPEM, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
	}

	privPEMBytes := pem.EncodeToMemory(privPEM)

	// Generate SSH public key
	pub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create SSH public key: %w", err)
	}

	pubBytes := appendComment(ssh.MarshalAuthorizedKey(pub), comment)
	fp := fingerprintSHA256(pub)

	return privPEMBytes, pubBytes, fp, nil
}

// ed448PublicKey wraps an Ed448 public key to implement ssh.PublicKey
type ed448PublicKey []byte

func (k ed448PublicKey) Type() string {
	return "ssh-ed448"
}

func (k ed448PublicKey) Marshal() []byte {
	w := struct {
		KeyType string
		Key     []byte
	}{
		KeyType: k.Type(),
		Key:     []byte(k),
	}
	return ssh.Marshal(&w)
}

func (k ed448PublicKey) Verify(data []byte, sig *ssh.Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	if !ed448.Verify(ed448.PublicKey(k), data, sig.Blob, "") {
		return fmt.Errorf("ssh: ed448 signature verification failed")
	}
	return nil
}

// GenerateEd448Key generates an Ed448 key pair
func GenerateEd448Key(comment string) (privateKeyPEM []byte, publicKey []byte, fingerprint string, err error) {
	pubKey, privKey, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate Ed448 key: %w", err)
	}

	sshPubKey := ed448PublicKey(pubKey)

	privPEM, err := marshalOpenSSHEd448(privKey, pubKey, comment)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal Ed448 private key: %w", err)
	}

	pubBytes := appendComment(ssh.MarshalAuthorizedKey(sshPubKey), comment)
	fp := fingerprintSHA256(sshPubKey)

	return privPEM, pubBytes, fp, nil
}

// marshalOpenSSHEd448 encodes an Ed448 key pair in openssh-key-v1 private key format
func marshalOpenSSHEd448(privKey ed448.PrivateKey, pubKey ed448.PublicKey, comment string) ([]byte, error) {
	// Public key wire format
	pubWire := struct {
		KeyType string
		PubKey  []byte
	}{
		KeyType: "ssh-ed448",
		PubKey:  []byte(pubKey),
	}
	pubWireBytes := ssh.Marshal(&pubWire)

	// Random check value for integrity verification
	var checkBuf [4]byte
	if _, err := rand.Read(checkBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random check: %w", err)
	}
	check := binary.BigEndian.Uint32(checkBuf[:])

	// Build the private key blob (seed + public key, following OpenSSH convention)
	var keyBlob []byte
	if len(privKey) <= ed448.SeedSize {
		keyBlob = make([]byte, 0, ed448.SeedSize+len(pubKey))
		keyBlob = append(keyBlob, privKey...)
		keyBlob = append(keyBlob, pubKey...)
	} else {
		keyBlob = []byte(privKey)
	}

	// Private key section (unencrypted)
	privSection := struct {
		Check1  uint32
		Check2  uint32
		KeyType string
		PubKey  []byte
		PrivKey []byte
		Comment string
	}{
		Check1:  check,
		Check2:  check,
		KeyType: "ssh-ed448",
		PubKey:  []byte(pubKey),
		PrivKey: keyBlob,
		Comment: comment,
	}
	privSectionBytes := ssh.Marshal(&privSection)

	// Pad to block size of 8
	padLen := (8 - len(privSectionBytes)%8) % 8
	for i := 0; i < padLen; i++ {
		privSectionBytes = append(privSectionBytes, byte(i+1))
	}

	// Assemble full openssh-key-v1 format
	var buf bytes.Buffer
	buf.WriteString("openssh-key-v1\x00")

	outer := struct {
		CipherName string
		KdfName    string
		KdfOpts    string
		NumKeys    uint32
		PubKey     []byte
		PrivKey    []byte
	}{
		CipherName: "none",
		KdfName:    "none",
		KdfOpts:    "",
		NumKeys:    1,
		PubKey:     pubWireBytes,
		PrivKey:    privSectionBytes,
	}
	buf.Write(ssh.Marshal(&outer))

	return pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: buf.Bytes(),
	}), nil
}

// ParsePublicKey parses an SSH public key and returns its fingerprint
func ParsePublicKey(pubKeyBytes []byte) (fingerprint string, keyType string, err error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse public key: %w", err)
	}

	return fingerprintSHA256(pub), pub.Type(), nil
}

// ParsePrivateKey parses a PEM-encoded private key and extracts the public key
func ParsePrivateKey(privKeyPEM []byte) (publicKey []byte, fingerprint string, keyType string, err error) {
	signer, err := ssh.ParsePrivateKey(privKeyPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse private key: %w", err)
	}

	pub := signer.PublicKey()
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	fp := fingerprintSHA256(pub)

	return pubBytes, fp, pub.Type(), nil
}

// appendComment appends a comment to an SSH authorized key line
func appendComment(pubBytes []byte, comment string) []byte {
	if comment == "" {
		return pubBytes
	}
	// MarshalAuthorizedKey returns "type base64\n", insert comment before newline
	line := strings.TrimRight(string(pubBytes), "\n")
	return []byte(line + " " + comment + "\n")
}

// fingerprintSHA256 returns the SHA256 fingerprint of an SSH public key
func fingerprintSHA256(pub ssh.PublicKey) string {
	hash := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// marshalRSAPrivateKey marshals an RSA private key to PKCS#1 DER bytes
func marshalRSAPrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}
