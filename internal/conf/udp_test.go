package conf

import (
	"testing"
)

func TestUDPSetDefaults(t *testing.T) {
	u := UDP{}
	u.setDefaults("client")

	if u.Block_ != "aes" {
		t.Errorf("expected Block_=aes, got %s", u.Block_)
	}
	if u.Smuxbuf != 4*1024*1024 {
		t.Errorf("expected Smuxbuf=4MB, got %d", u.Smuxbuf)
	}
	if u.Streambuf != 2*1024*1024 {
		t.Errorf("expected Streambuf=2MB, got %d", u.Streambuf)
	}
}

func TestUDPSetDefaultsPreservesExisting(t *testing.T) {
	u := UDP{Block_: "salsa20", Smuxbuf: 1024 * 1024, Streambuf: 512 * 1024}
	u.setDefaults("server")

	if u.Block_ != "salsa20" {
		t.Errorf("expected Block_=salsa20, got %s", u.Block_)
	}
	if u.Smuxbuf != 1024*1024 {
		t.Errorf("expected Smuxbuf=1MB, got %d", u.Smuxbuf)
	}
}

func TestUDPValidateValid(t *testing.T) {
	u := UDP{
		Key:       "test-key",
		Block_:    "aes",
		Smuxbuf:   4 * 1024 * 1024,
		Streambuf: 2 * 1024 * 1024,
	}
	errs := u.validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(u.Block) == 0 {
		t.Error("expected derived key to be set after validation")
	}
}

func TestUDPValidateInvalidBlock(t *testing.T) {
	u := UDP{Key: "k", Block_: "invalid", Smuxbuf: 4096, Streambuf: 4096}
	errs := u.validate()
	if len(errs) == 0 {
		t.Error("expected error for invalid block cipher")
	}
}

func TestUDPValidateNoKeyWithEncryption(t *testing.T) {
	u := UDP{Key: "", Block_: "aes", Smuxbuf: 4096, Streambuf: 4096}
	errs := u.validate()
	if len(errs) == 0 {
		t.Error("expected error when key is empty with aes block")
	}
}

func TestUDPValidateNullBlockNoKey(t *testing.T) {
	u := UDP{Key: "", Block_: "null", Smuxbuf: 4096, Streambuf: 4096}
	errs := u.validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors for null block without key, got %v", errs)
	}
}

func TestUDPValidateSmuxbufTooSmall(t *testing.T) {
	u := UDP{Key: "k", Block_: "aes", Smuxbuf: 512, Streambuf: 4096}
	errs := u.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "UDP smuxbuf must be >= 1024 bytes" {
			found = true
		}
	}
	if !found {
		t.Error("expected smuxbuf validation error")
	}
}

func TestUDPValidateStreambufTooSmall(t *testing.T) {
	u := UDP{Key: "k", Block_: "aes", Smuxbuf: 4096, Streambuf: 512}
	errs := u.validate()
	found := false
	for _, e := range errs {
		if e.Error() == "UDP streambuf must be >= 1024 bytes" {
			found = true
		}
	}
	if !found {
		t.Error("expected streambuf validation error")
	}
}

func TestUDPDerivedKeyLength(t *testing.T) {
	u := UDP{Key: "test", Block_: "aes", Smuxbuf: 4096, Streambuf: 4096}
	u.validate()
	// "aes" has size 0 meaning full 32-byte key is used
	if len(u.Block) != 32 {
		t.Errorf("expected 32-byte derived key for aes, got %d", len(u.Block))
	}
}

func TestUDPDerivedKeyTrimmed(t *testing.T) {
	u := UDP{Key: "test", Block_: "cast5", Smuxbuf: 4096, Streambuf: 4096}
	u.validate()
	// cast5 has keySize=16
	if len(u.Block) != 16 {
		t.Errorf("expected 16-byte derived key for cast5, got %d", len(u.Block))
	}
}
