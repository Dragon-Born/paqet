package conf

import (
	"fmt"
	"paqet/internal/flog"
	"runtime"
)

type PCAP struct {
	Backend string `yaml:"backend"` // "auto" | "pcap" | "afpacket" (Linux only)
	Sockbuf int    `yaml:"sockbuf"`
}

func (p *PCAP) setDefaults(role string) {
	if p.Backend == "" {
		p.Backend = "auto"
	}

	if p.Sockbuf == 0 {
		if role == "server" {
			p.Sockbuf = 16 * 1024 * 1024 // 16 MB for high-throughput server
		} else {
			p.Sockbuf = 8 * 1024 * 1024 // 8 MB for client
		}
	}
}

func (p *PCAP) validate() []error {
	var errors []error

	// Validate backend
	switch p.Backend {
	case "auto", "pcap":
		// Valid on all platforms
	case "afpacket":
		// AF_PACKET is Linux-only
		if runtime.GOOS != "linux" {
			errors = append(errors, fmt.Errorf("backend 'afpacket' is only available on Linux"))
		}
	default:
		errors = append(errors, fmt.Errorf("invalid backend '%s', must be 'auto', 'pcap', or 'afpacket'", p.Backend))
	}

	if p.Sockbuf < 1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf must be >= 1024 bytes"))
	}

	if p.Sockbuf > 100*1024*1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf too large (max 100MB)"))
	}

	// Should be power of 2 for optimal performance, but not required
	if p.Sockbuf&(p.Sockbuf-1) != 0 {
		flog.Warnf("PCAP sockbuf (%d bytes) is not a power of 2 - consider using values like 4MB, 8MB, or 16MB for better performance", p.Sockbuf)
	}

	return errors
}
