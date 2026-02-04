//go:build linux && !nopcap

// Note: gopls on non-Linux platforms may show false errors for pcap.Direction
// constants since they're defined in platform-specific files. The code compiles
// correctly on Linux.

package socket

import (
	"fmt"
	"paqet/internal/conf"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// pcapHandle wraps a pcap.Handle to implement RawHandle interface.
type pcapHandle struct {
	handle *pcap.Handle
}

// newPcapHandle creates a new RawHandle using libpcap on Linux.
func newPcapHandle(cfg *conf.Network) (RawHandle, error) {
	inactive, err := pcap.NewInactiveHandle(cfg.Interface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(cfg.PCAP.Sockbuf); err != nil {
		return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", cfg.PCAP.Sockbuf, err)
	}

	if err = inactive.SetSnapLen(65536); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}
	if err = inactive.SetPromisc(true); err != nil {
		return nil, fmt.Errorf("failed to enable promiscuous mode: %v", err)
	}
	if err = inactive.SetTimeout(pcap.BlockForever); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	return &pcapHandle{handle: handle}, nil
}

func (h *pcapHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return h.handle.ZeroCopyReadPacketData()
}

func (h *pcapHandle) WritePacketData(data []byte) error {
	return h.handle.WritePacketData(data)
}

func (h *pcapHandle) SetBPFFilter(filter string) error {
	return h.handle.SetBPFFilter(filter)
}

func (h *pcapHandle) SetDirection(dir Direction) error {
	var pcapDir pcap.Direction
	switch dir {
	case DirectionIn:
		pcapDir = pcap.DirectionIn
	case DirectionOut:
		pcapDir = pcap.DirectionOut
	case DirectionInOut:
		pcapDir = pcap.DirectionInOut
	}
	return h.handle.SetDirection(pcapDir)
}

func (h *pcapHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
