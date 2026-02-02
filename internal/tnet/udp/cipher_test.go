package udp

import (
	"bytes"
	"testing"
)

func TestNewCipherNilKey(t *testing.T) {
	c, err := NewCipher(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil cipher for empty key")
	}
}

func TestNewCipherEmptyKey(t *testing.T) {
	c, err := NewCipher([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil cipher for empty key")
	}
}

func TestNewCipher16Byte(t *testing.T) {
	key := make([]byte, 16)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cipher for 16-byte key")
	}
}

func TestNewCipher32Byte(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cipher for 32-byte key")
	}
}

func TestNewCipherShortKey(t *testing.T) {
	key := []byte("short") // 5 bytes, will be padded to 16
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cipher for short key (padded)")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	plaintext := []byte("hello, this is a test message for encryption")

	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted text does not match original:\n  got:  %q\n  want: %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmptyPayload(t *testing.T) {
	key := make([]byte, 16)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	ciphertext, err := c.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty decrypted, got %d bytes", len(decrypted))
	}
}

func TestEncryptProducesDifferentCiphertext(t *testing.T) {
	key := make([]byte, 32)
	c, _ := NewCipher(key)

	plaintext := []byte("same input")
	ct1, _ := c.Encrypt(plaintext)
	ct2, _ := c.Encrypt(plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestDecryptTamperedData(t *testing.T) {
	key := make([]byte, 32)
	c, _ := NewCipher(key)

	ciphertext, _ := c.Encrypt([]byte("secret data"))

	// Tamper with the ciphertext
	if len(ciphertext) > 0 {
		ciphertext[len(ciphertext)-1] ^= 0xFF
	}

	_, err := c.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting tampered data")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	c, _ := NewCipher(key)

	_, err := c.Decrypt([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for data shorter than nonce")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	c1, _ := NewCipher(key1)
	c2, _ := NewCipher(key2)

	ciphertext, _ := c1.Encrypt([]byte("test"))
	_, err := c2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestNilCipherPassthrough(t *testing.T) {
	var c *Cipher

	plaintext := []byte("passthrough data")
	result, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("nil cipher Encrypt failed: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatal("nil cipher should pass through plaintext")
	}

	result, err = c.Decrypt(plaintext)
	if err != nil {
		t.Fatalf("nil cipher Decrypt failed: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatal("nil cipher should pass through data")
	}
}
