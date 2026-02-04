//go:build linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
)

const (
	afpacketFrameSize = 4096       // Frame size for TPacket ring buffer
	afpacketBlockSize = 512 * 1024 // 512KB per block
)

// sharedAfpacketHandle is a shared AF_PACKET handle with reference counting.
// Multiple connections share the same underlying TPacket to avoid memory-mapped
// buffer conflicts in container environments like MikroTik.
type sharedAfpacketHandle struct {
	tpacket  *afpacket.TPacket
	srcMAC   []byte
	refCount int32
}

var (
	sharedHandles   = make(map[string]*sharedAfpacketHandle) // interface name -> shared handle
	sharedHandlesMu sync.Mutex
)

// afpacketHandle wraps a shared AF_PACKET handle to implement RawHandle interface.
type afpacketHandle struct {
	shared    *sharedAfpacketHandle
	ifaceName string
	direction Direction
}

// newAfpacketHandle creates a new RawHandle using AF_PACKET on Linux.
// AF_PACKET is a Linux-only socket type that provides raw network access
// without requiring libpcap, making it suitable for minimal containers.
//
// Handles are shared per interface to avoid memory-mapped buffer conflicts
// when multiple connections use the same interface.
func newAfpacketHandle(cfg *conf.Network) (RawHandle, error) {
	sharedHandlesMu.Lock()
	defer sharedHandlesMu.Unlock()

	ifaceName := cfg.Interface.Name

	// Check if we already have a shared handle for this interface
	shared, exists := sharedHandles[ifaceName]
	if exists {
		atomic.AddInt32(&shared.refCount, 1)
		flog.Debugf("AF_PACKET: reusing shared handle on %s (refCount=%d)", ifaceName, atomic.LoadInt32(&shared.refCount))

		return &afpacketHandle{
			shared:    shared,
			ifaceName: ifaceName,
			direction: DirectionInOut,
		}, nil
	}

	// Create new shared handle
	numBlocks := cfg.PCAP.Sockbuf / afpacketBlockSize
	if numBlocks < 2 {
		numBlocks = 2
	}
	if numBlocks > 128 {
		numBlocks = 128
	}

	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptFrameSize(afpacketFrameSize),
		afpacket.OptBlockSize(afpacketBlockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(-time.Millisecond), // -1ms → poll timeout of -1 (block forever)
		afpacket.TPacketVersion2,                   // Use v2 for better compatibility (v3 can crash in containers)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET handle on %s: %v", ifaceName, err)
	}

	shared = &sharedAfpacketHandle{
		tpacket:  tpacket,
		srcMAC:   cfg.Interface.HardwareAddr,
		refCount: 1,
	}
	sharedHandles[ifaceName] = shared

	flog.Infof("AF_PACKET: created shared handle on %s with %d blocks (%d MB buffer)",
		ifaceName, numBlocks, (numBlocks*afpacketBlockSize)/(1024*1024))

	return &afpacketHandle{
		shared:    shared,
		ifaceName: ifaceName,
		direction: DirectionInOut,
	}, nil
}

func (h *afpacketHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		data, ci, err := h.shared.tpacket.ZeroCopyReadPacketData()
		if err != nil {
			return nil, ci, err
		}

		// AF_PACKET doesn't have native direction filtering like pcap.
		// We implement it by checking the source MAC address.
		srcMAC := h.shared.srcMAC
		if h.direction != DirectionInOut && len(data) >= 14 && len(srcMAC) == 6 {
			pktSrcMAC := data[6:12]
			isOutgoing := macEqual(pktSrcMAC, srcMAC)

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
	return h.shared.tpacket.WritePacketData(data)
}

func (h *afpacketHandle) SetBPFFilter(filter string) error {
	// Use pure-Go BPF compiler (no libpcap dependency)
	rawBPF, err := compileBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to compile BPF filter: %v", err)
	}

	return h.shared.tpacket.SetBPF(rawBPF)
}

func (h *afpacketHandle) SetDirection(dir Direction) error {
	// AF_PACKET doesn't have native direction filtering.
	// We store the desired direction and filter in ZeroCopyReadPacketData.
	h.direction = dir
	return nil
}

func (h *afpacketHandle) Close() {
	if h.shared == nil {
		return
	}

	// Don't actually close the shared TPacket or nil out h.shared - it's shared
	// across multiple goroutines (probes, connections, read loops). Other goroutines
	// may still be reading from this handle even after Close() is called.
	// The TPacket lives for the program's lifetime.
	//
	// We still track refCount for debugging purposes.
	newCount := atomic.AddInt32(&h.shared.refCount, -1)
	flog.Debugf("AF_PACKET: releasing handle on %s (refCount=%d)", h.ifaceName, newCount)
}

// macEqual compares two MAC addresses for equality.
func macEqual(a, b []byte) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
		a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}
