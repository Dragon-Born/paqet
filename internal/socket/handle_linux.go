//go:build linux && !nopcap

package socket

import (
	"paqet/internal/conf"
	"paqet/internal/flog"
)

// newHandle creates a RawHandle based on the configured backend.
// On Linux, supports "auto", "pcap", and "afpacket" backends.
func newHandle(cfg *conf.Network) (RawHandle, error) {
	backend := cfg.PCAP.Backend
	if backend == "" {
		backend = "auto"
	}

	switch backend {
	case "pcap":
		flog.Debugf("Using pcap backend (explicit)")
		return newPcapHandle(cfg)

	case "afpacket":
		flog.Debugf("Using AF_PACKET backend (explicit)")
		return newAfpacketHandle(cfg)

	case "auto":
		// Try AF_PACKET first (no libpcap dependency), fall back to pcap
		handle, err := newAfpacketHandle(cfg)
		if err == nil {
			flog.Debugf("Using AF_PACKET backend (auto-selected)")
			return handle, nil
		}
		flog.Debugf("AF_PACKET unavailable (%v), falling back to pcap", err)

		handle, err = newPcapHandle(cfg)
		if err != nil {
			return nil, err
		}
		flog.Debugf("Using pcap backend (fallback)")
		return handle, nil

	default:
		// Unknown backend, default to auto behavior
		flog.Warnf("Unknown backend '%s', using auto-selection", backend)
		return newHandle(&conf.Network{
			Interface: cfg.Interface,
			PCAP:      conf.PCAP{Sockbuf: cfg.PCAP.Sockbuf, Backend: "auto"},
		})
	}
}
