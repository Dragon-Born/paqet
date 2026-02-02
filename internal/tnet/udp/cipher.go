package udp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"
)

// Cipher provides per-packet AEAD encryption/decryption.
type Cipher struct {
	aead     cipher.AEAD
	noncePool sync.Pool
}

// NewCipher creates a new AEAD cipher from the given key.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) == 0 {
		return nil, nil // no encryption
	}

	// Normalize key length to valid AES size
	var k []byte
	switch {
	case len(key) >= 32:
		k = key[:32]
	case len(key) >= 24:
		k = key[:24]
	case len(key) >= 16:
		k = key[:16]
	default:
		// Pad key to 16 bytes
		k = make([]byte, 16)
		copy(k, key)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	return &Cipher{
		aead: aead,
		noncePool: sync.Pool{
			New: func() any {
				b := make([]byte, nonceSize)
				return &b
			},
		},
	}, nil
}

// Encrypt encrypts a plaintext packet and returns ciphertext with prepended nonce.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return plaintext, nil
	}

	np := c.noncePool.Get().(*[]byte)
	nonce := *np
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		c.noncePool.Put(np)
		return nil, err
	}

	// Seal appends to nonce, so result is nonce+ciphertext
	out := c.aead.Seal(nonce, nonce, plaintext, nil)
	c.noncePool.Put(np)
	return out, nil
}

// Decrypt decrypts a packet (nonce prepended to ciphertext).
// It decrypts in-place when possible, returning a slice of the input buffer.
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	if c == nil {
		return data, nil
	}

	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt in-place: use ciphertext[:0] as dst to reuse the buffer
	plain, err := c.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
