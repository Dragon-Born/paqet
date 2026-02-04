package conf

import (
	"fmt"
	"slices"

	"github.com/xtaci/kcp-go/v5"
)

type KCP struct {
	Mode         string `yaml:"mode"`
	NoDelay      int    `yaml:"nodelay"`
	Interval     int    `yaml:"interval"`
	Resend       int    `yaml:"resend"`
	NoCongestion int    `yaml:"nocongestion"`
	WDelay       bool   `yaml:"wdelay"`
	AckNoDelay   bool   `yaml:"acknodelay"`

	MTU    int `yaml:"mtu"`
	Rcvwnd int `yaml:"rcvwnd"`
	Sndwnd int `yaml:"sndwnd"`
	Dshard int `yaml:"dshard"`
	Pshard int `yaml:"pshard"`

	Block_ string `yaml:"block"`
	Key    string `yaml:"key"`

	Smuxbuf   int `yaml:"smuxbuf"`
	Streambuf int `yaml:"streambuf"`

	Block kcp.BlockCrypt `yaml:"-"`
}

func (k *KCP) setDefaults(_ string) {
	if k.Mode == "" {
		k.Mode = "fast3"
	}
	if k.MTU == 0 {
		// MTU calculation for raw TCP packets:
		// Ethernet MTU (1500) - IP header (20 IPv4 / 40 IPv6) - TCP header+opts (32)
		// IPv4: 1500 - 20 - 32 = 1448
		// IPv6: 1500 - 40 - 32 = 1428
		// Using 1400 as safe default that works for both, with margin for edge cases
		k.MTU = 1400
	}

	if k.Rcvwnd == 0 {
		k.Rcvwnd = 2048 // ~55 Mbps at 50ms RTT with 1350 MTU
	}
	if k.Sndwnd == 0 {
		k.Sndwnd = 2048
	}

	// if k.Dshard == 0 {
	// 	k.Dshard = 10
	// }
	// if k.Pshard == 0 {
	// 	k.Pshard = 3
	// }

	if k.Block_ == "" {
		k.Block_ = "aes"
	}

	if k.Smuxbuf == 0 {
		k.Smuxbuf = 8 * 1024 * 1024 // 8 MB session buffer
	}
	if k.Streambuf == 0 {
		k.Streambuf = 4 * 1024 * 1024 // 4 MB per-stream buffer
	}
}

func (k *KCP) validate() []error {
	var errors []error

	validModes := []string{"normal", "fast", "fast2", "fast3", "fast4", "manual"}
	if !slices.Contains(validModes, k.Mode) {
		errors = append(errors, fmt.Errorf("KCP mode must be one of: %v", validModes))
	}

	if k.MTU < 50 || k.MTU > 1500 {
		errors = append(errors, fmt.Errorf("KCP MTU must be between 50-1500 bytes"))
	}

	if k.Rcvwnd < 1 || k.Rcvwnd > 32768 {
		errors = append(errors, fmt.Errorf("KCP rcvwnd must be between 1-32768"))
	}
	if k.Sndwnd < 1 || k.Sndwnd > 32768 {
		errors = append(errors, fmt.Errorf("KCP sndwnd must be between 1-32768"))
	}

	validBlocks := []string{"aes", "aes-128", "aes-128-gcm", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "sm4", "none", "null"}
	if !slices.Contains(validBlocks, k.Block_) {
		errors = append(errors, fmt.Errorf("KCP encryption block must be one of: %v", validBlocks))
	}
	if !slices.Contains([]string{"none", "null"}, k.Block_) && len(k.Key) == 0 {
		errors = append(errors, fmt.Errorf("KCP encryption key is required"))
	}
	b, err := newBlock(k.Block_, k.Key)
	if err != nil {
		errors = append(errors, err)
	}
	k.Block = b

	if k.Smuxbuf < 1024 {
		errors = append(errors, fmt.Errorf("KCP smuxbuf must be >= 1024 bytes"))
	}
	if k.Streambuf < 1024 {
		errors = append(errors, fmt.Errorf("KCP streambuf must be >= 1024 bytes"))
	}

	return errors
}
