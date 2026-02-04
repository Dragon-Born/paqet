//go:build linux

package socket

import (
	"net"
	"os"
	"os/user"
	"testing"

	"paqet/internal/conf"
)

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root privileges")
	}
}

func skipIfNoLoopback(t *testing.T) {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("skipping: loopback interface not found: %v", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Skip("skipping: loopback interface is down")
	}
}

func getTestInterface(t *testing.T) *net.Interface {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("failed to get loopback interface: %v", err)
	}
	return iface
}

// TestNewAfpacketHandle_Creation tests basic handle creation
func TestNewAfpacketHandle_Creation(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)
	cfg := &conf.Network{
		Interface: iface,
		PCAP: conf.PCAP{
			Sockbuf: 2 * 1024 * 1024, // 2MB
		},
	}

	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		t.Fatalf("newAfpacketHandle failed: %v", err)
	}
	defer handle.Close()

	// Verify it implements RawHandle
	var _ RawHandle = handle
}

// TestAfpacketHandle_SetBPFFilter tests BPF filter application
func TestAfpacketHandle_SetBPFFilter(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)
	cfg := &conf.Network{
		Interface: iface,
		PCAP: conf.PCAP{
			Sockbuf: 2 * 1024 * 1024,
		},
	}

	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		t.Fatalf("newAfpacketHandle failed: %v", err)
	}
	defer handle.Close()

	tests := []struct {
		filter  string
		wantErr bool
	}{
		{"tcp and dst port 443", false},
		{"tcp and dst port 8080", false},
		{"tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			err := handle.SetBPFFilter(tt.filter)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestAfpacketHandle_SetDirection tests direction filtering
func TestAfpacketHandle_SetDirection(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)
	cfg := &conf.Network{
		Interface: iface,
		PCAP: conf.PCAP{
			Sockbuf: 2 * 1024 * 1024,
		},
	}

	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		t.Fatalf("newAfpacketHandle failed: %v", err)
	}
	defer handle.Close()

	directions := []Direction{DirectionIn, DirectionOut, DirectionInOut}
	for _, dir := range directions {
		if err := handle.SetDirection(dir); err != nil {
			t.Errorf("SetDirection(%v) failed: %v", dir, err)
		}
	}
}

// TestAfpacketHandle_Close tests handle cleanup
func TestAfpacketHandle_Close(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)
	cfg := &conf.Network{
		Interface: iface,
		PCAP: conf.PCAP{
			Sockbuf: 2 * 1024 * 1024,
		},
	}

	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		t.Fatalf("newAfpacketHandle failed: %v", err)
	}

	// Should not panic on close
	handle.Close()

	// Should not panic on double close
	handle.Close()
}

// TestNewHandle_BackendSelection tests the backend dispatcher
func TestNewHandle_BackendSelection(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)

	tests := []struct {
		backend string
		wantErr bool
	}{
		{"auto", false},
		{"afpacket", false},
		// pcap may or may not be available depending on build
	}

	for _, tt := range tests {
		t.Run(tt.backend, func(t *testing.T) {
			cfg := &conf.Network{
				Interface: iface,
				PCAP: conf.PCAP{
					Backend: tt.backend,
					Sockbuf: 2 * 1024 * 1024,
				},
			}

			handle, err := newHandle(cfg)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
					handle.Close()
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			handle.Close()
		})
	}
}

// TestAfpacketHandle_WritePacketData tests packet writing capability
func TestAfpacketHandle_WritePacketData(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)
	cfg := &conf.Network{
		Interface: iface,
		PCAP: conf.PCAP{
			Sockbuf: 2 * 1024 * 1024,
		},
	}

	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		t.Fatalf("newAfpacketHandle failed: %v", err)
	}
	defer handle.Close()

	// Build a minimal Ethernet frame (won't actually be valid, but tests the write path)
	// This is a dummy frame that will be dropped by the kernel
	frame := make([]byte, 64)
	// Dst MAC
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Src MAC
	copy(frame[6:12], iface.HardwareAddr)
	// EtherType (IPv4)
	frame[12] = 0x08
	frame[13] = 0x00

	// Write should succeed (even if packet is dropped)
	err = handle.WritePacketData(frame)
	if err != nil {
		t.Errorf("WritePacketData failed: %v", err)
	}
}

// TestAfpacketBufferSizing tests buffer size configuration
func TestAfpacketBufferSizing(t *testing.T) {
	skipIfNotRoot(t)
	skipIfNoLoopback(t)

	iface := getTestInterface(t)

	tests := []struct {
		name    string
		sockbuf int
		wantErr bool
	}{
		{"1MB", 1 * 1024 * 1024, false},
		{"2MB", 2 * 1024 * 1024, false},
		{"8MB", 8 * 1024 * 1024, false},
		{"minimum", 512 * 1024, false}, // At least 2 blocks
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &conf.Network{
				Interface: iface,
				PCAP: conf.PCAP{
					Backend: "afpacket",
					Sockbuf: tt.sockbuf,
				},
			}

			handle, err := newAfpacketHandle(cfg)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
					handle.Close()
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			handle.Close()
		})
	}
}

func init() {
	// Log test environment info
	if u, err := user.Current(); err == nil {
		if os.Getuid() == 0 {
			_ = u // Running as root
		}
	}
}
