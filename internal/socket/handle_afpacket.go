//go:build linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
)

const (
	afpacketFrameSize = 4096       // Frame size for TPacket ring buffer
	afpacketBlockSize = 512 * 1024 // 512KB per block
)

// afpacketHandle wraps an afpacket.TPacket to implement RawHandle interface.
type afpacketHandle struct {
	tpacket   *afpacket.TPacket
	direction Direction
	srcMAC    []byte // Source MAC for direction filtering
}

// newAfpacketHandle creates a new RawHandle using AF_PACKET on Linux.
// AF_PACKET is a Linux-only socket type that provides raw network access
// without requiring libpcap, making it suitable for minimal containers.
func newAfpacketHandle(cfg *conf.Network) (RawHandle, error) {
	// Calculate number of blocks from sockbuf size
	numBlocks := cfg.PCAP.Sockbuf / afpacketBlockSize
	if numBlocks < 2 {
		numBlocks = 2
	}
	if numBlocks > 128 {
		numBlocks = 128
	}

	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(cfg.Interface.Name),
		afpacket.OptFrameSize(afpacketFrameSize),
		afpacket.OptBlockSize(afpacketBlockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(-time.Millisecond), // -1ms → poll timeout of -1 (block forever)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET handle on %s: %v", cfg.Interface.Name, err)
	}

	flog.Debugf("AF_PACKET handle created on %s with %d blocks (%d MB buffer)",
		cfg.Interface.Name, numBlocks, (numBlocks*afpacketBlockSize)/(1024*1024))

	return &afpacketHandle{
		tpacket:   tpacket,
		direction: DirectionInOut,
		srcMAC:    cfg.Interface.HardwareAddr,
	}, nil
}

func (h *afpacketHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		data, ci, err := h.tpacket.ZeroCopyReadPacketData()
		if err != nil {
			return nil, ci, err
		}

		// AF_PACKET doesn't have native direction filtering like pcap.
		// We implement it by checking the source MAC address.
		if h.direction != DirectionInOut && len(data) >= 14 && len(h.srcMAC) == 6 {
			srcMAC := data[6:12]
			isOutgoing := macEqual(srcMAC, h.srcMAC)

			if h.direction == DirectionIn && isOutgoing {
				// Want incoming only, but this is outgoing - skip
				continue
			}
			if h.direction == DirectionOut && !isOutgoing {
				// Want outgoing only, but this is incoming - skip
				continue
			}
		}

		return data, ci, nil
	}
}

func (h *afpacketHandle) WritePacketData(data []byte) error {
	return h.tpacket.WritePacketData(data)
}

func (h *afpacketHandle) SetBPFFilter(filter string) error {
	// Use pure-Go BPF compiler (no libpcap dependency)
	rawBPF, err := compileBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to compile BPF filter: %v", err)
	}

	return h.tpacket.SetBPF(rawBPF)
}

func (h *afpacketHandle) SetDirection(dir Direction) error {
	// AF_PACKET doesn't have native direction filtering.
	// We store the desired direction and filter in ZeroCopyReadPacketData.
	h.direction = dir
	return nil
}

func (h *afpacketHandle) Close() {
	if h.tpacket != nil {
		h.tpacket.Close()
	}
}

// macEqual compares two MAC addresses for equality.
func macEqual(a, b []byte) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
		a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}
