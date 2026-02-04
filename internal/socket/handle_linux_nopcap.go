//go:build linux && nopcap

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
)

// newHandle creates a RawHandle using AF_PACKET only (no libpcap dependency).
// This is used when building with -tags nopcap for minimal containers like MikroTik.
func newHandle(cfg *conf.Network) (RawHandle, error) {
	backend := cfg.PCAP.Backend
	if backend == "" {
		backend = "auto"
	}

	switch backend {
	case "auto", "afpacket":
		flog.Debugf("Using AF_PACKET backend (nopcap build)")
		return newAfpacketHandle(cfg)

	case "pcap":
		return nil, fmt.Errorf("pcap backend unavailable: built with -tags nopcap")

	default:
		return nil, fmt.Errorf("unknown backend '%s', only 'afpacket' available in nopcap build", backend)
	}
}
