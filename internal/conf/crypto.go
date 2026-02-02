package conf

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKey derives a 32-byte key from a passphrase using PBKDF2.
func DeriveKey(key string) []byte {
	return pbkdf2.Key([]byte(key), []byte("paqet"), 100_000, 32, sha256.New)
}

// ValidBlocks lists all supported encryption block cipher names.
var ValidBlocks = []string{
	"aes", "aes-128", "aes-128-gcm", "aes-192",
	"salsa20", "blowfish", "twofish", "cast5", "3des",
	"tea", "xtea", "xor", "sm4", "none", "null",
}

// BlockKeySize returns the required key size for a given block cipher name.
// Returns 0 if the full derived key should be used, or -1 if unknown.
func BlockKeySize(block string) int {
	sizes := map[string]int{
		"aes": 0, "aes-128": 16, "aes-128-gcm": 16, "aes-192": 24,
		"salsa20": 0, "blowfish": 0, "twofish": 0, "cast5": 16,
		"3des": 24, "tea": 16, "xtea": 16, "xor": 0, "sm4": 16,
		"none": 0, "null": 0,
	}
	if s, ok := sizes[block]; ok {
		return s
	}
	return -1
}

// TrimKey trims the derived key to the appropriate size for the given block cipher.
func TrimKey(dkey []byte, block string) []byte {
	size := BlockKeySize(block)
	if size > 0 && len(dkey) >= size {
		return dkey[:size]
	}
	return dkey
}

// IsNullBlock returns true if the block cipher name means no encryption.
func IsNullBlock(block string) bool {
	return block == "none" || block == "null"
}

// ValidateBlockAndKey checks that the block cipher name is valid and that
// a key is provided when encryption is enabled.
func ValidateBlockAndKey(block, key string) error {
	if BlockKeySize(block) == -1 {
		return fmt.Errorf("unsupported encryption block: %s (valid: %v)", block, ValidBlocks)
	}
	if !IsNullBlock(block) && len(key) == 0 {
		return fmt.Errorf("encryption key is required for block %q", block)
	}
	return nil
}
