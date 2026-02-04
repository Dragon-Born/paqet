//go:build linux

package socket

import (
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

func TestCompileBPFFilter_TCPDstPort(t *testing.T) {
	tests := []struct {
		filter  string
		wantErr bool
	}{
		{"tcp and dst port 443", false},
		{"tcp and dst port 8080", false},
		{"tcp and dst port 1", false},
		{"tcp and dst port 65535", false},
		{"tcp and dst port 0", true},     // Invalid port
		{"tcp and dst port 65536", true}, // Invalid port
		{"tcp and dst port abc", true},   // Non-numeric
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			prog, err := compileBPFFilter(tt.filter)
			if tt.wantErr {
				if err == nil {
					t.Errorf("compileBPFFilter(%q) expected error, got nil", tt.filter)
				}
				return
			}
			if err != nil {
				t.Errorf("compileBPFFilter(%q) unexpected error: %v", tt.filter, err)
				return
			}
			if len(prog) == 0 {
				t.Errorf("compileBPFFilter(%q) returned empty program", tt.filter)
			}
			// Validate the program is well-formed
			if err := validateBPFProgram(prog); err != nil {
				t.Errorf("compileBPFFilter(%q) produced invalid BPF: %v", tt.filter, err)
			}
		})
	}
}

func TestCompileBPFFilter_TCPSrcPort(t *testing.T) {
	prog, err := compileBPFFilter("tcp and src port 12345")
	if err != nil {
		t.Fatalf("compileBPFFilter failed: %v", err)
	}
	if len(prog) == 0 {
		t.Fatal("empty BPF program")
	}
	if err := validateBPFProgram(prog); err != nil {
		t.Errorf("invalid BPF program: %v", err)
	}
}

func TestCompileBPFFilter_TCP(t *testing.T) {
	prog, err := compileBPFFilter("tcp")
	if err != nil {
		t.Fatalf("compileBPFFilter failed: %v", err)
	}
	if len(prog) == 0 {
		t.Fatal("empty BPF program")
	}
	if err := validateBPFProgram(prog); err != nil {
		t.Errorf("invalid BPF program: %v", err)
	}
}

func TestCompileBPFFilter_EtherDst(t *testing.T) {
	tests := []struct {
		filter  string
		wantErr bool
	}{
		{"ether dst 00:11:22:33:44:55", false},
		{"ether dst aa:bb:cc:dd:ee:ff", false},
		{"ether dst 00:00:00:00:00:00", false},
		{"ether dst ff:ff:ff:ff:ff:ff", false},
		{"ether dst invalid", true},
		{"ether dst 00:11:22", true}, // Too short
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			prog, err := compileBPFFilter(tt.filter)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.filter)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if err := validateBPFProgram(prog); err != nil {
				t.Errorf("invalid BPF program: %v", err)
			}
		})
	}
}

func TestCompileBPFFilter_Unsupported(t *testing.T) {
	unsupported := []string{
		"udp and dst port 53",
		"icmp",
		"ip host 192.168.1.1",
		"port 80",
		"",
	}

	for _, filter := range unsupported {
		t.Run(filter, func(t *testing.T) {
			_, err := compileBPFFilter(filter)
			if err == nil {
				t.Errorf("expected error for unsupported filter %q", filter)
			}
		})
	}
}

func TestCompileBPFFilter_CaseInsensitive(t *testing.T) {
	filters := []string{
		"TCP AND DST PORT 443",
		"Tcp And Dst Port 443",
		"tcp and dst port 443",
	}

	for _, filter := range filters {
		t.Run(filter, func(t *testing.T) {
			prog, err := compileBPFFilter(filter)
			if err != nil {
				t.Errorf("compileBPFFilter(%q) failed: %v", filter, err)
				return
			}
			if len(prog) == 0 {
				t.Error("empty program")
			}
		})
	}
}

// TestBPFProgramStructure verifies the BPF programs have correct structure
func TestBPFProgramStructure(t *testing.T) {
	prog, err := compileBPFFilter("tcp and dst port 443")
	if err != nil {
		t.Fatalf("compileBPFFilter failed: %v", err)
	}

	// Program must end with RET instructions
	lastInstr := prog[len(prog)-1]
	if lastInstr.Op&0x07 != bpfRET {
		t.Error("program doesn't end with RET instruction")
	}

	// Second-to-last should also be RET (accept path)
	if len(prog) >= 2 {
		secondLast := prog[len(prog)-2]
		if secondLast.Op&0x07 != bpfRET {
			t.Error("expected RET instruction for accept path")
		}
	}

	// Check for at least one JMP instruction (for filtering)
	hasJump := false
	for _, instr := range prog {
		if instr.Op&0x07 == bpfJMP {
			hasJump = true
			break
		}
	}
	if !hasJump {
		t.Error("program has no jump instructions")
	}
}

// TestBuildTCPDstPortFilter_IPv4AndIPv6 verifies the filter handles both IP versions
func TestBuildTCPDstPortFilter_IPv4AndIPv6(t *testing.T) {
	prog := buildTCPDstPortFilter(443)

	// Should check for both EtherType values
	hasIPv4Check := false
	hasIPv6Check := false

	for _, instr := range prog {
		if instr.Op == bpfJMP|bpfJEQ|bpfK {
			if instr.K == etherTypeIPv4 {
				hasIPv4Check = true
			}
			if instr.K == etherTypeIPv6 {
				hasIPv6Check = true
			}
		}
	}

	if !hasIPv4Check {
		t.Error("filter doesn't check for IPv4 EtherType")
	}
	if !hasIPv6Check {
		t.Error("filter doesn't check for IPv6 EtherType")
	}
}

// TestBuildEtherDstFilter verifies MAC address matching
func TestBuildEtherDstFilter(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	prog := buildEtherDstFilter(mac)

	if len(prog) < 4 {
		t.Fatal("program too short")
	}

	// First instruction should load from offset 0 (dst MAC)
	if prog[0].Op != bpfLD|bpfH|bpfABS || prog[0].K != 0 {
		t.Error("first instruction should load dst MAC bytes")
	}

	// Should have comparison for MAC bytes
	hasHighCheck := false
	hasLowCheck := false
	expectedHigh := uint32(0xaa)<<8 | uint32(0xbb)
	expectedLow := uint32(0xcc)<<24 | uint32(0xdd)<<16 | uint32(0xee)<<8 | uint32(0xff)

	for _, instr := range prog {
		if instr.Op == bpfJMP|bpfJEQ|bpfK {
			if instr.K == expectedHigh {
				hasHighCheck = true
			}
			if instr.K == expectedLow {
				hasLowCheck = true
			}
		}
	}

	if !hasHighCheck {
		t.Errorf("missing check for high MAC bytes (expected 0x%x)", expectedHigh)
	}
	if !hasLowCheck {
		t.Errorf("missing check for low MAC bytes (expected 0x%x)", expectedLow)
	}
}

// validateBPFProgram performs basic validation on a BPF program
func validateBPFProgram(prog []bpf.RawInstruction) error {
	if len(prog) == 0 {
		return nil
	}

	// Check that all jumps are within bounds
	for i, instr := range prog {
		class := instr.Op & 0x07
		if class == bpfJMP {
			jmpType := instr.Op & 0xf0
			if jmpType != bpfJA { // Conditional jump
				jtTarget := i + 1 + int(instr.Jt)
				jfTarget := i + 1 + int(instr.Jf)
				if jtTarget >= len(prog) || jfTarget >= len(prog) {
					return &bpfError{i, "jump target out of bounds"}
				}
			} else { // Unconditional jump
				target := i + 1 + int(instr.K)
				if target >= len(prog) {
					return &bpfError{i, "unconditional jump out of bounds"}
				}
			}
		}
	}

	// Program must end with RET
	lastClass := prog[len(prog)-1].Op & 0x07
	if lastClass != bpfRET {
		return &bpfError{len(prog) - 1, "program must end with RET"}
	}

	return nil
}

type bpfError struct {
	index int
	msg   string
}

func (e *bpfError) Error() string {
	return e.msg
}

// Benchmark BPF filter compilation
func BenchmarkCompileBPFFilter(b *testing.B) {
	b.Run("tcp_dst_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = compileBPFFilter("tcp and dst port 443")
		}
	})

	b.Run("tcp_src_port", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = compileBPFFilter("tcp and src port 12345")
		}
	})

	b.Run("tcp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = compileBPFFilter("tcp")
		}
	})

	b.Run("ether_dst", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = compileBPFFilter("ether dst aa:bb:cc:dd:ee:ff")
		}
	})
}
