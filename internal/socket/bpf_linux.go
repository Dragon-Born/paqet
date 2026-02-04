//go:build linux

package socket

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// Ethernet/IP constants
const (
	ethOffsetType = 12
	ethHeaderLen  = 14
	etherTypeIPv4 = 0x0800
	ipProtoTCP    = 6
)

// compileBPFFilter compiles a simple BPF filter string to raw instructions.
// Uses golang.org/x/net/bpf high-level types for automatic jump calculation.
//
// Supports a subset of tcpdump filter syntax (IPv4 only):
//   - "tcp and dst port N"
//   - "tcp and src port N"
//   - "tcp"
//   - "ether dst MAC"
//
// For complex filters or IPv6, use pcap.CompileBPFFilter instead (requires libpcap).
func compileBPFFilter(filter string) ([]bpf.RawInstruction, error) {
	filter = strings.TrimSpace(strings.ToLower(filter))

	var instructions []bpf.Instruction

	switch {
	case strings.HasPrefix(filter, "tcp and dst port "):
		portStr := strings.TrimPrefix(filter, "tcp and dst port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		instructions = buildTCPPortFilter(uint16(port), true)

	case strings.HasPrefix(filter, "tcp and src port "):
		portStr := strings.TrimPrefix(filter, "tcp and src port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		instructions = buildTCPPortFilter(uint16(port), false)

	case filter == "tcp":
		instructions = buildTCPFilter()

	case strings.HasPrefix(filter, "ether dst "):
		macStr := strings.TrimPrefix(filter, "ether dst ")
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address: %s", macStr)
		}
		instructions = buildEtherDstFilter(mac)

	default:
		return nil, fmt.Errorf("unsupported filter: %s (use pcap backend for complex filters)", filter)
	}

	// Assemble high-level instructions to raw BPF
	raw, err := bpf.Assemble(instructions)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble BPF: %w", err)
	}

	return raw, nil
}

// buildTCPPortFilter creates BPF for "tcp and {dst|src} port N" (IPv4 only)
// This version handles variable IP header length by reading the IHL field.
//
// Program structure (9 instructions, indices 0-8):
//
//	0: Load EtherType
//	1: If not IPv4 → reject (7)
//	2: Load IP protocol
//	3: If not TCP → reject (7)
//	4: LoadMemShift (IHL*4 into X register)
//	5: LoadIndirect TCP port (using X + offset)
//	6: If port matches → accept (8), else reject (7)
//	7: Reject
//	8: Accept
func buildTCPPortFilter(port uint16, isDst bool) []bpf.Instruction {
	// TCP port offset within TCP header: src=0, dst=2
	tcpPortOffset := uint32(0)
	if isDst {
		tcpPortOffset = 2
	}

	return []bpf.Instruction{
		// 0: Load EtherType (2 bytes at offset 12)
		bpf.LoadAbsolute{Off: ethOffsetType, Size: 2},

		// 1: If not IPv4 → skip 5 to reject (index 7)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipTrue: 0, SkipFalse: 5},

		// 2: Load IP protocol (1 byte at offset 14+9=23)
		bpf.LoadAbsolute{Off: ethHeaderLen + 9, Size: 1},

		// 3: If not TCP → skip 3 to reject (index 7)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProtoTCP, SkipTrue: 0, SkipFalse: 3},

		// 4: Load IHL*4 into X register
		bpf.LoadMemShift{Off: ethHeaderLen},

		// 5: Load TCP port using X (IHL*4) as base: offset = ethHeaderLen + X + tcpPortOffset
		bpf.LoadIndirect{Off: ethHeaderLen + tcpPortOffset, Size: 2},

		// 6: If port matches → skip 1 to accept (8), else fall through to reject (7)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipTrue: 1, SkipFalse: 0},

		// 7: Reject
		bpf.RetConstant{Val: 0},

		// 8: Accept
		bpf.RetConstant{Val: 0xffffffff},
	}
}

// buildTCPFilter creates BPF for "tcp" (any TCP packet, IPv4 only)
func buildTCPFilter() []bpf.Instruction {
	return []bpf.Instruction{
		// 0: Load EtherType
		bpf.LoadAbsolute{Off: ethOffsetType, Size: 2},
		// 1: If not IPv4 → reject
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipTrue: 0, SkipFalse: 2},
		// 2: Load protocol
		bpf.LoadAbsolute{Off: ethHeaderLen + 9, Size: 1},
		// 3: If TCP → accept, else reject
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProtoTCP, SkipTrue: 1, SkipFalse: 0},
		// 4: Reject
		bpf.RetConstant{Val: 0},
		// 5: Accept
		bpf.RetConstant{Val: 0xffffffff},
	}
}

// buildEtherDstFilter creates BPF for "ether dst MAC"
func buildEtherDstFilter(mac net.HardwareAddr) []bpf.Instruction {
	macHigh := uint32(mac[0])<<8 | uint32(mac[1])
	macLow := uint32(mac[2])<<24 | uint32(mac[3])<<16 | uint32(mac[4])<<8 | uint32(mac[5])

	return []bpf.Instruction{
		// 0: Load first 2 bytes of dst MAC
		bpf.LoadAbsolute{Off: 0, Size: 2},
		// 1: If not match → reject
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: macHigh, SkipTrue: 0, SkipFalse: 2},
		// 2: Load last 4 bytes of dst MAC
		bpf.LoadAbsolute{Off: 2, Size: 4},
		// 3: If match → accept, else reject
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: macLow, SkipTrue: 1, SkipFalse: 0},
		// 4: Reject
		bpf.RetConstant{Val: 0},
		// 5: Accept
		bpf.RetConstant{Val: 0xffffffff},
	}
}
