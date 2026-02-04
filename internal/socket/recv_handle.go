package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type RecvHandle struct {
	handle  RawHandle
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	h := &RecvHandle{
		handle:  handle,
		decoded: make([]gopacket.LayerType, 0, 4),
	}

	h.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&h.eth, &h.ipv4, &h.ipv6, &h.tcp,
	)
	h.parser.IgnoreUnsupported = true

	return h, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	addr := &net.UDPAddr{}
	h.decoded = h.decoded[:0]

	if err := h.parser.DecodeLayers(data, &h.decoded); err != nil {
		// Ignore unsupported layer errors; we only need IP+TCP
	}

	for _, typ := range h.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			addr.IP = h.ipv4.SrcIP
		case layers.LayerTypeIPv6:
			addr.IP = h.ipv6.SrcIP
		case layers.LayerTypeTCP:
			addr.Port = int(h.tcp.SrcPort)
		}
	}

	payload := h.tcp.Payload

	if len(payload) == 0 {
		return nil, addr, nil
	}
	return payload, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
