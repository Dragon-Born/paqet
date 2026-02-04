package socket

import (
	"github.com/gopacket/gopacket"
)

// Direction specifies which direction of packets to capture.
type Direction int

const (
	DirectionIn    Direction = iota // Capture incoming packets only
	DirectionOut                    // Capture outgoing packets only
	DirectionInOut                  // Capture both directions
)

// RawHandle is an interface that abstracts raw packet capture backends.
// It is implemented by both pcap handles and AF_PACKET handles.
type RawHandle interface {
	// ZeroCopyReadPacketData reads a packet without copying.
	// The returned slice is only valid until the next read.
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)

	// WritePacketData writes a raw packet to the network.
	WritePacketData(data []byte) error

	// SetBPFFilter sets a BPF filter on the handle.
	SetBPFFilter(filter string) error

	// SetDirection sets which direction of packets to capture.
	// Note: Not all platforms/backends support this (e.g., Windows Npcap).
	SetDirection(dir Direction) error

	// Close releases resources associated with the handle.
	Close()
}
