// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"strings"
	"testing"
	"unicode"
)

// ---------- generateSecurePassword ----------

func TestGenerateSecurePassword_Length(t *testing.T) {
	for _, length := range []int{8, 16, 20, 32, 64} {
		pw, err := generateSecurePassword(length)
		if err != nil {
			t.Fatalf("generateSecurePassword(%d) error: %v", length, err)
		}
		if len(pw) != length {
			t.Fatalf("generateSecurePassword(%d) returned length %d", length, len(pw))
		}
	}
}

func TestGenerateSecurePassword_CharacterSet(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	pw, err := generateSecurePassword(1000)
	if err != nil {
		t.Fatalf("generateSecurePassword error: %v", err)
	}
	for i, c := range pw {
		if !strings.ContainsRune(charset, c) {
			t.Fatalf("character at position %d (%c) not in allowed charset", i, c)
		}
	}
}

func TestGenerateSecurePassword_Uniqueness(t *testing.T) {
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw, err := generateSecurePassword(20)
		if err != nil {
			t.Fatalf("generateSecurePassword error: %v", err)
		}
		if passwords[pw] {
			t.Fatal("generated duplicate password — insufficient randomness")
		}
		passwords[pw] = true
	}
}

func TestGenerateSecurePassword_NoBias(t *testing.T) {
	// Generate many characters and check that the distribution is roughly
	// uniform. With rejection sampling and charset length 62, each character
	// should appear about 1/62 ≈ 1.6% of the time. We use a generous margin.
	const total = 62000
	pw, err := generateSecurePassword(total)
	if err != nil {
		t.Fatalf("generateSecurePassword error: %v", err)
	}

	freq := make(map[rune]int)
	for _, c := range pw {
		freq[c]++
	}

	expected := float64(total) / 62.0 // ~1000
	for c, count := range freq {
		ratio := float64(count) / expected
		// Allow 20% deviation (generous for 62k samples)
		if ratio < 0.8 || ratio > 1.2 {
			t.Errorf("character %c appeared %d times (expected ~%.0f, ratio %.2f) — possible bias", c, count, expected, ratio)
		}
	}
}

// ---------- dummyHash (timing attack prevention) ----------

func TestDummyHash_IsValid(t *testing.T) {
	if dummyHash == nil {
		t.Fatal("dummyHash should not be nil")
	}
	if len(dummyHash) == 0 {
		t.Fatal("dummyHash should not be empty")
	}
	// It should be a valid bcrypt hash (starts with $2a$ or $2b$)
	s := string(dummyHash)
	if !strings.HasPrefix(s, "$2a$") && !strings.HasPrefix(s, "$2b$") {
		t.Fatalf("dummyHash does not look like a bcrypt hash: %s", s)
	}
}

// ---------- Password character class helpers ----------

func TestPasswordCharacterClasses(t *testing.T) {
	tests := []struct {
		password   string
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	}{
		{"abc", false, true, false, false},
		{"ABC", true, false, false, false},
		{"123", false, false, true, false},
		{"!@#", false, false, false, true},
		{"aB1!", true, true, true, true},
		{"", false, false, false, false},
	}

	for _, tt := range tests {
		var upper, lower, digit, special bool
		for _, r := range tt.password {
			if unicode.IsUpper(r) {
				upper = true
			}
			if unicode.IsLower(r) {
				lower = true
			}
			if unicode.IsDigit(r) {
				digit = true
			}
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				special = true
			}
		}
		if upper != tt.hasUpper || lower != tt.hasLower || digit != tt.hasDigit || special != tt.hasSpecial {
			t.Errorf("password %q: got upper=%v lower=%v digit=%v special=%v, want upper=%v lower=%v digit=%v special=%v",
				tt.password, upper, lower, digit, special, tt.hasUpper, tt.hasLower, tt.hasDigit, tt.hasSpecial)
		}
	}
}
