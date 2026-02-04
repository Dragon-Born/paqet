//go:build linux

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/bpf"
)

// BPF instruction constants (from linux/bpf_common.h)
const (
	bpfLD   = 0x00
	bpfLDX  = 0x01
	bpfST   = 0x02
	bpfSTX  = 0x03
	bpfALU  = 0x04
	bpfJMP  = 0x05
	bpfRET  = 0x06
	bpfMISC = 0x07

	bpfW   = 0x00 // 32 bits
	bpfH   = 0x08 // 16 bits
	bpfB   = 0x10 // 8 bits
	bpfIMM = 0x00
	bpfABS = 0x20
	bpfIND = 0x40
	bpfMEM = 0x60
	bpfLEN = 0x80
	bpfMSH = 0xa0

	bpfADD = 0x00
	bpfSUB = 0x10
	bpfMUL = 0x20
	bpfDIV = 0x30
	bpfOR  = 0x40
	bpfAND = 0x50
	bpfLSH = 0x60
	bpfRSH = 0x70
	bpfNEG = 0x80
	bpfMOD = 0x90
	bpfXOR = 0xa0

	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40

	bpfK = 0x00
	bpfX = 0x08
	bpfA = 0x10

	bpfTAX = 0x00
	bpfTXA = 0x80
)

// Ethernet header offsets
const (
	ethOffsetDstMAC  = 0
	ethOffsetSrcMAC  = 6
	ethOffsetType    = 12
	ethHeaderLen     = 14
	etherTypeIPv4    = 0x0800
	etherTypeIPv6    = 0x86dd
	ipProtoTCP       = 6
	ipProtoUDP       = 17
	ipv4HeaderMinLen = 20
	ipv6HeaderLen    = 40
)

// compileBPFFilter compiles a simple BPF filter string to raw instructions.
// Supports a subset of tcpdump filter syntax:
//   - "tcp and dst port N"
//   - "tcp and src port N"
//   - "tcp"
//   - "udp and dst port N"
//   - "ether dst MAC"
//
// For complex filters, use pcap.CompileBPFFilter instead (requires libpcap).
func compileBPFFilter(filter string) ([]bpf.RawInstruction, error) {
	filter = strings.TrimSpace(strings.ToLower(filter))

	// Parse the filter
	if strings.HasPrefix(filter, "tcp and dst port ") {
		portStr := strings.TrimPrefix(filter, "tcp and dst port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		return buildTCPDstPortFilter(uint16(port)), nil
	}

	if strings.HasPrefix(filter, "tcp and src port ") {
		portStr := strings.TrimPrefix(filter, "tcp and src port ")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		return buildTCPSrcPortFilter(uint16(port)), nil
	}

	if filter == "tcp" {
		return buildTCPFilter(), nil
	}

	if strings.HasPrefix(filter, "ether dst ") {
		macStr := strings.TrimPrefix(filter, "ether dst ")
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address: %s", macStr)
		}
		return buildEtherDstFilter(mac), nil
	}

	return nil, fmt.Errorf("unsupported filter: %s (use pcap backend for complex filters)", filter)
}

// buildTCPDstPortFilter creates BPF for "tcp and dst port N" on IPv4/IPv6
func buildTCPDstPortFilter(port uint16) []bpf.RawInstruction {
	return []bpf.RawInstruction{
		// Load EtherType
		{Op: bpfLD | bpfH | bpfABS, K: ethOffsetType},

		// Check IPv4 (0x0800)
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv4, Jt: 0, Jf: 7},

		// IPv4: Load protocol field (offset 23 from start = 14 + 9)
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 9},
		// Check if TCP (protocol = 6)
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 0, Jf: 14},

		// IPv4: Load IHL (header length in 32-bit words)
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen},
		{Op: bpfALU | bpfAND | bpfK, K: 0x0f},
		{Op: bpfALU | bpfMUL | bpfK, K: 4}, // Convert to bytes
		// Add ethernet header length
		{Op: bpfALU | bpfADD | bpfK, K: ethHeaderLen},
		// Store in X (index register)
		{Op: bpfMISC | bpfTAX},
		// Load TCP dst port (2 bytes at IP header + 2)
		{Op: bpfLD | bpfH | bpfIND, K: 2},
		// Check port
		{Op: bpfJMP | bpfJEQ | bpfK, K: uint32(port), Jt: 6, Jf: 7},

		// Check IPv6 (0x86dd)
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv6, Jt: 0, Jf: 6},

		// IPv6: Load next header (offset 20 from IPv6 start = 14 + 6)
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 6},
		// Check if TCP
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 0, Jf: 3},

		// IPv6: TCP dst port is at offset 14 + 40 + 2 = 56
		{Op: bpfLD | bpfH | bpfABS, K: ethHeaderLen + ipv6HeaderLen + 2},
		// Check port
		{Op: bpfJMP | bpfJEQ | bpfK, K: uint32(port), Jt: 0, Jf: 1},

		// Accept
		{Op: bpfRET | bpfK, K: 0xffffffff},
		// Reject
		{Op: bpfRET | bpfK, K: 0},
	}
}

// buildTCPSrcPortFilter creates BPF for "tcp and src port N"
func buildTCPSrcPortFilter(port uint16) []bpf.RawInstruction {
	return []bpf.RawInstruction{
		// Load EtherType
		{Op: bpfLD | bpfH | bpfABS, K: ethOffsetType},

		// Check IPv4
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv4, Jt: 0, Jf: 7},

		// IPv4: Load protocol
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 9},
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 0, Jf: 14},

		// IPv4: Load IHL and compute TCP header offset
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen},
		{Op: bpfALU | bpfAND | bpfK, K: 0x0f},
		{Op: bpfALU | bpfMUL | bpfK, K: 4},
		{Op: bpfALU | bpfADD | bpfK, K: ethHeaderLen},
		{Op: bpfMISC | bpfTAX},
		// Load TCP src port (first 2 bytes)
		{Op: bpfLD | bpfH | bpfIND, K: 0},
		{Op: bpfJMP | bpfJEQ | bpfK, K: uint32(port), Jt: 6, Jf: 7},

		// Check IPv6
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv6, Jt: 0, Jf: 6},

		// IPv6: Load next header
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 6},
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 0, Jf: 3},

		// IPv6: TCP src port at offset 14 + 40 + 0
		{Op: bpfLD | bpfH | bpfABS, K: ethHeaderLen + ipv6HeaderLen},
		{Op: bpfJMP | bpfJEQ | bpfK, K: uint32(port), Jt: 0, Jf: 1},

		// Accept
		{Op: bpfRET | bpfK, K: 0xffffffff},
		// Reject
		{Op: bpfRET | bpfK, K: 0},
	}
}

// buildTCPFilter creates BPF for "tcp" (any TCP packet)
func buildTCPFilter() []bpf.RawInstruction {
	return []bpf.RawInstruction{
		// Load EtherType
		{Op: bpfLD | bpfH | bpfABS, K: ethOffsetType},

		// Check IPv4
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv4, Jt: 0, Jf: 3},
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 9},
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 4, Jf: 5},

		// Check IPv6
		{Op: bpfJMP | bpfJEQ | bpfK, K: etherTypeIPv6, Jt: 0, Jf: 4},
		{Op: bpfLD | bpfB | bpfABS, K: ethHeaderLen + 6},
		{Op: bpfJMP | bpfJEQ | bpfK, K: ipProtoTCP, Jt: 0, Jf: 2},

		// Accept
		{Op: bpfRET | bpfK, K: 0xffffffff},
		// Reject
		{Op: bpfRET | bpfK, K: 0},
	}
}

// buildEtherDstFilter creates BPF for "ether dst MAC"
func buildEtherDstFilter(mac net.HardwareAddr) []bpf.RawInstruction {
	// Convert MAC to uint32 for comparison (last 4 bytes)
	macLow := binary.BigEndian.Uint32(mac[2:6])

	return []bpf.RawInstruction{
		// Load first 2 bytes of dst MAC
		{Op: bpfLD | bpfH | bpfABS, K: 0},
		{Op: bpfJMP | bpfJEQ | bpfK, K: uint32(mac[0])<<8 | uint32(mac[1]), Jt: 0, Jf: 4},

		// Load last 4 bytes of dst MAC
		{Op: bpfLD | bpfW | bpfABS, K: 2},
		{Op: bpfJMP | bpfJEQ | bpfK, K: macLow, Jt: 0, Jf: 2},

		// Accept
		{Op: bpfRET | bpfK, K: 0xffffffff},
		// Reject
		{Op: bpfRET | bpfK, K: 0},
	}
}
