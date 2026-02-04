//go:build linux

package socket

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// TestRawHandleInterface verifies the RawHandle interface definition
func TestRawHandleInterface(t *testing.T) {
	// This is a compile-time check that the interface is properly defined
	var _ RawHandle = (*mockHandle)(nil)
}

// mockHandle is a mock implementation for testing
type mockHandle struct {
	readData  []byte
	readInfo  gopacket.CaptureInfo
	readErr   error
	writeErr  error
	filterErr error
	dirErr    error
	filter    string
	direction Direction
	closed    bool
}

func (m *mockHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return m.readData, m.readInfo, m.readErr
}

func (m *mockHandle) WritePacketData(data []byte) error {
	return m.writeErr
}

func (m *mockHandle) SetBPFFilter(filter string) error {
	m.filter = filter
	return m.filterErr
}

func (m *mockHandle) SetDirection(dir Direction) error {
	m.direction = dir
	return m.dirErr
}

func (m *mockHandle) Close() {
	m.closed = true
}

// TestDirection verifies Direction constants
func TestDirection(t *testing.T) {
	tests := []struct {
		dir  Direction
		name string
	}{
		{DirectionIn, "DirectionIn"},
		{DirectionOut, "DirectionOut"},
		{DirectionInOut, "DirectionInOut"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify distinct values
			for _, other := range tests {
				if tt.name != other.name && tt.dir == other.dir {
					t.Errorf("%s and %s have same value", tt.name, other.name)
				}
			}
		})
	}
}

// TestMacEqual tests MAC address comparison
func TestMacEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{
			name: "equal",
			a:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			b:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			want: true,
		},
		{
			name: "not_equal",
			a:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			b:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x56},
			want: false,
		},
		{
			name: "first_byte_diff",
			a:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			b:    []byte{0x01, 0x11, 0x22, 0x33, 0x44, 0x55},
			want: false,
		},
		{
			name: "short_a",
			a:    []byte{0x00, 0x11, 0x22},
			b:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			want: false,
		},
		{
			name: "short_b",
			a:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			b:    []byte{0x00, 0x11, 0x22},
			want: false,
		},
		{
			name: "empty",
			a:    []byte{},
			b:    []byte{},
			want: false,
		},
		{
			name: "nil",
			a:    nil,
			b:    nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := macEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("macEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func BenchmarkMacEqual(b *testing.B) {
	mac1 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	mac2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	b.Run("equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			macEqual(mac1, mac2)
		}
	})

	mac3 := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	b.Run("not_equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			macEqual(mac1, mac3)
		}
	})
}
