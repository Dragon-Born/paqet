package protocol

import (
	"bytes"
	"paqet/internal/conf"
	"paqet/internal/tnet"
	"testing"
)

func TestPingPongRoundTrip(t *testing.T) {
	for _, typ := range []PType{PPING, PPONG} {
		var buf bytes.Buffer
		w := Proto{Type: typ}
		if err := w.Write(&buf); err != nil {
			t.Fatalf("write type 0x%02x: %v", typ, err)
		}
		if buf.Len() != 1 {
			t.Fatalf("expected 1 byte for ping/pong, got %d", buf.Len())
		}
		var r Proto
		if err := r.Read(&buf); err != nil {
			t.Fatalf("read type 0x%02x: %v", typ, err)
		}
		if r.Type != typ {
			t.Fatalf("expected type 0x%02x, got 0x%02x", typ, r.Type)
		}
	}
}

func TestTCPRoundTrip(t *testing.T) {
	addr, _ := tnet.NewAddr("93.184.216.34:443")
	var buf bytes.Buffer
	w := Proto{Type: PTCP, Addr: addr}
	if err := w.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	var r Proto
	if err := r.Read(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.Type != PTCP {
		t.Fatalf("expected PTCP, got 0x%02x", r.Type)
	}
	if r.Addr.Host != "93.184.216.34" || r.Addr.Port != 443 {
		t.Fatalf("addr mismatch: got %s", r.Addr.String())
	}
}

func TestUDPRoundTrip(t *testing.T) {
	addr, _ := tnet.NewAddr("[::1]:8080")
	var buf bytes.Buffer
	w := Proto{Type: PUDP, Addr: addr}
	if err := w.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	var r Proto
	if err := r.Read(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.Type != PUDP {
		t.Fatalf("expected PUDP, got 0x%02x", r.Type)
	}
	if r.Addr.Host != "::1" || r.Addr.Port != 8080 {
		t.Fatalf("addr mismatch: got %s", r.Addr.String())
	}
}

func TestTCPFRoundTrip(t *testing.T) {
	tcpf := []conf.TCPF{
		{SYN: true, ACK: true},
		{PSH: true, ACK: true},
	}
	var buf bytes.Buffer
	w := Proto{Type: PTCPF, TCPF: tcpf}
	if err := w.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	var r Proto
	if err := r.Read(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.Type != PTCPF {
		t.Fatalf("expected PTCPF, got 0x%02x", r.Type)
	}
	if len(r.TCPF) != 2 {
		t.Fatalf("expected 2 TCPF entries, got %d", len(r.TCPF))
	}
	if !r.TCPF[0].SYN || !r.TCPF[0].ACK {
		t.Fatalf("TCPF[0] mismatch: %+v", r.TCPF[0])
	}
	if !r.TCPF[1].PSH || !r.TCPF[1].ACK {
		t.Fatalf("TCPF[1] mismatch: %+v", r.TCPF[1])
	}
}

func TestWriteNilAddrReturnsError(t *testing.T) {
	var buf bytes.Buffer
	w := Proto{Type: PTCP, Addr: nil}
	if err := w.Write(&buf); err == nil {
		t.Fatal("expected error for nil addr")
	}
}

func TestUnknownTypeReturnsError(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0xFF)
	var r Proto
	if err := r.Read(&buf); err == nil {
		t.Fatal("expected error for unknown type")
	}
}
