package conf

import (
	"fmt"
	"slices"
)

type UDP struct {
	Key    string `yaml:"key"`
	Block_ string `yaml:"block"`
	Block  []byte `yaml:"-"` // derived key bytes

	Smuxbuf   int `yaml:"smuxbuf"`
	Streambuf int `yaml:"streambuf"`
}

func (u *UDP) setDefaults(_ string) {
	if u.Block_ == "" {
		u.Block_ = "aes"
	}
	if u.Smuxbuf == 0 {
		u.Smuxbuf = 8 * 1024 * 1024 // 8 MB session buffer
	}
	if u.Streambuf == 0 {
		u.Streambuf = 4 * 1024 * 1024 // 4 MB per-stream buffer
	}
}

func (u *UDP) validate() []error {
	var errors []error

	if !slices.Contains(ValidBlocks, u.Block_) {
		errors = append(errors, fmt.Errorf("UDP encryption block must be one of: %v", ValidBlocks))
	}

	if err := ValidateBlockAndKey(u.Block_, u.Key); err != nil {
		errors = append(errors, fmt.Errorf("UDP: %w", err))
	}

	// Derive key for runtime use
	if len(u.Key) > 0 {
		dkey := DeriveKey(u.Key)
		u.Block = TrimKey(dkey, u.Block_)
	}

	if u.Smuxbuf < 1024 {
		errors = append(errors, fmt.Errorf("UDP smuxbuf must be >= 1024 bytes"))
	}
	if u.Streambuf < 1024 {
		errors = append(errors, fmt.Errorf("UDP streambuf must be >= 1024 bytes"))
	}

	return errors
}
