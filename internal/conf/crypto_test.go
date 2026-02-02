package conf

import (
	"testing"
)

func TestDeriveKeyLength(t *testing.T) {
	key := DeriveKey("test-passphrase")
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	k1 := DeriveKey("same-key")
	k2 := DeriveKey("same-key")
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatal("same passphrase should produce same key")
		}
	}
}

func TestDeriveKeyDifferentInput(t *testing.T) {
	k1 := DeriveKey("key-a")
	k2 := DeriveKey("key-b")
	same := true
	for i := range k1 {
		if k1[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestBlockKeySizeKnown(t *testing.T) {
	cases := map[string]int{
		"aes":         0,
		"aes-128":     16,
		"aes-128-gcm": 16,
		"aes-192":     24,
		"salsa20":     0,
		"cast5":       16,
		"3des":        24,
		"none":        0,
		"null":        0,
	}
	for block, want := range cases {
		got := BlockKeySize(block)
		if got != want {
			t.Errorf("BlockKeySize(%q) = %d, want %d", block, got, want)
		}
	}
}

func TestBlockKeySizeUnknown(t *testing.T) {
	if got := BlockKeySize("invalid-cipher"); got != -1 {
		t.Errorf("expected -1 for unknown block, got %d", got)
	}
}

func TestTrimKeyFixedSize(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	trimmed := TrimKey(key, "aes-128")
	if len(trimmed) != 16 {
		t.Fatalf("expected 16-byte key for aes-128, got %d", len(trimmed))
	}
	for i := range trimmed {
		if trimmed[i] != byte(i) {
			t.Fatal("trimmed key should be prefix of original")
		}
	}
}

func TestTrimKeyFullSize(t *testing.T) {
	key := make([]byte, 32)
	trimmed := TrimKey(key, "aes")
	if len(trimmed) != 32 {
		t.Fatalf("expected full 32-byte key for aes (size 0), got %d", len(trimmed))
	}
}

func TestIsNullBlock(t *testing.T) {
	if !IsNullBlock("none") {
		t.Error("none should be null block")
	}
	if !IsNullBlock("null") {
		t.Error("null should be null block")
	}
	if IsNullBlock("aes") {
		t.Error("aes should not be null block")
	}
}

func TestValidateBlockAndKey(t *testing.T) {
	// Valid block with key
	if err := ValidateBlockAndKey("aes", "my-key"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Null block without key is OK
	if err := ValidateBlockAndKey("none", ""); err != nil {
		t.Errorf("expected no error for none without key, got %v", err)
	}
	if err := ValidateBlockAndKey("null", ""); err != nil {
		t.Errorf("expected no error for null without key, got %v", err)
	}

	// Non-null block without key
	if err := ValidateBlockAndKey("aes", ""); err == nil {
		t.Error("expected error for aes without key")
	}

	// Unknown block
	if err := ValidateBlockAndKey("rc4", "key"); err == nil {
		t.Error("expected error for unknown block")
	}
}
