package transport

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// mockPacketConn is an in-memory net.PacketConn for testing.
// Writes go into a buffer; reads come from a channel.
type mockPacketConn struct {
	incoming chan mockPkt
	written  []mockPkt
	mu       sync.Mutex
	closed   bool
	local    net.Addr
}

type mockPkt struct {
	data []byte
	addr net.Addr
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		incoming: make(chan mockPkt, 64),
		local:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
	}
}

func (m *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-m.incoming
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, pkt.data)
	return n, pkt.addr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data := make([]byte, len(p))
	copy(data, p)
	m.written = append(m.written, mockPkt{data: data, addr: addr})
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.incoming)
	}
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr                { return m.local }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// inject sends a packet into the mock conn's read path.
func (m *mockPacketConn) inject(data []byte, addr net.Addr) {
	d := make([]byte, len(data))
	copy(d, data)
	m.incoming <- mockPkt{data: d, addr: addr}
}

// getWritten returns all written packets.
func (m *mockPacketConn) getWritten() []mockPkt {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockPkt, len(m.written))
	copy(out, m.written)
	return out
}

var testAddr = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}

// --- ProtoTag / ProtoName ---

func TestProtoTagMapping(t *testing.T) {
	tests := []struct {
		name string
		tag  byte
	}{
		{"kcp", TagKCP},
		{"quic", TagQUIC},
		{"udp", TagUDP},
	}
	for _, tt := range tests {
		if got := ProtoTag(tt.name); got != tt.tag {
			t.Errorf("ProtoTag(%q) = 0x%02x, want 0x%02x", tt.name, got, tt.tag)
		}
		if got := ProtoName(tt.tag); got != tt.name {
			t.Errorf("ProtoName(0x%02x) = %q, want %q", tt.tag, got, tt.name)
		}
	}
}

func TestProtoTagUnknown(t *testing.T) {
	if got := ProtoTag("websocket"); got != 0 {
		t.Errorf("ProtoTag(unknown) = 0x%02x, want 0", got)
	}
	if got := ProtoName(0xFF); got != "unknown" {
		t.Errorf("ProtoName(0xFF) = %q, want unknown", got)
	}
}

// --- VirtualPacketConn ---

func TestVirtualPacketConnWritePrependsTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	payload := []byte("hello")
	n, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 written packet, got %d", len(pkts))
	}
	if pkts[0].data[0] != TagKCP {
		t.Errorf("tag byte = 0x%02x, want 0x%02x", pkts[0].data[0], TagKCP)
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Errorf("payload = %q, want %q", pkts[0].data[1:], payload)
	}
}

func TestVirtualPacketConnReadStripsTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagQUIC)

	payload := []byte("world")
	tagged := append([]byte{TagQUIC}, payload...)
	mock.inject(tagged, testAddr)

	buf := make([]byte, 1500)
	n, addr, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("read data = %q, want %q", buf[:n], payload)
	}
	if addr == nil {
		t.Error("addr should not be nil")
	}
}

func TestVirtualPacketConnReadDropsWrongTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// Inject a packet with wrong tag.
	wrongTagged := append([]byte{TagQUIC}, []byte("data")...)
	mock.inject(wrongTagged, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for wrong tag, got %d", n)
	}
}

func TestVirtualPacketConnReadDropsTooShort(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// Inject a 1-byte packet (tag only, no payload).
	mock.inject([]byte{TagKCP}, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for too-short packet, got %d", n)
	}
}

func TestVirtualPacketConnWriteReadRoundTrip(t *testing.T) {
	// Simulate client write → wire → client read on same VirtualPacketConn.
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagUDP)

	payload := []byte("round-trip test payload with some length to it")
	_, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Take what was written to the mock and inject it back.
	pkts := mock.getWritten()
	mock.inject(pkts[0].data, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("round-trip mismatch: got %q, want %q", buf[:n], payload)
	}
}

// --- DemuxedPacketConn ---

func TestDemuxedPacketConnDeliverAndRead(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	defer dc.Close()

	payload := []byte("demuxed packet data")
	dc.deliver(payload, testAddr)

	buf := make([]byte, 1500)
	n, addr, err := dc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}
	if addr == nil {
		t.Error("addr should not be nil (was the critical bug)")
	}
	if !addr.(*net.UDPAddr).IP.Equal(testAddr.IP) {
		t.Errorf("addr IP = %v, want %v", addr, testAddr)
	}
}

func TestDemuxedPacketConnWritePrependsTag(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagQUIC, mock)
	defer dc.Close()

	payload := []byte("tagged write")
	n, err := dc.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if pkts[0].data[0] != TagQUIC {
		t.Errorf("tag = 0x%02x, want 0x%02x", pkts[0].data[0], TagQUIC)
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Errorf("payload = %q, want %q", pkts[0].data[1:], payload)
	}
}

func TestDemuxedPacketConnReadAfterClose(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	dc.Close()

	buf := make([]byte, 1500)
	_, _, err := dc.ReadFrom(buf)
	if err != net.ErrClosed {
		t.Errorf("expected net.ErrClosed, got %v", err)
	}
}

func TestDemuxedPacketConnDeliverAfterClose(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	dc.Close()

	// Should not panic.
	dc.deliver([]byte("late packet"), testAddr)
}

func TestDemuxedPacketConnCloseIdempotent(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)

	// Closing twice should not panic.
	dc.Close()
	dc.Close()
}

// --- ProtoDemux ---

func TestProtoDemuxRoutesCorrectly(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC, TagUDP)

	kcpConn := demux.Conn(TagKCP)
	quicConn := demux.Conn(TagQUIC)
	udpConn := demux.Conn(TagUDP)

	if kcpConn == nil || quicConn == nil || udpConn == nil {
		t.Fatal("all protocol conns should be non-nil")
	}

	// Inject tagged packets.
	kcpPayload := []byte("kcp-data")
	quicPayload := []byte("quic-data")
	udpPayload := []byte("udp-data")

	mock.inject(append([]byte{TagKCP}, kcpPayload...), testAddr)
	mock.inject(append([]byte{TagQUIC}, quicPayload...), testAddr)
	mock.inject(append([]byte{TagUDP}, udpPayload...), testAddr)

	// Read from each protocol conn.
	buf := make([]byte, 1500)

	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("KCP ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], kcpPayload) {
		t.Errorf("KCP got %q, want %q", buf[:n], kcpPayload)
	}

	n, _, err = quicConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("QUIC ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], quicPayload) {
		t.Errorf("QUIC got %q, want %q", buf[:n], quicPayload)
	}

	n, _, err = udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("UDP ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], udpPayload) {
		t.Errorf("UDP got %q, want %q", buf[:n], udpPayload)
	}

	demux.Close()
}

func TestProtoDemuxDropsUnknownTag(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)

	kcpConn := demux.Conn(TagKCP)

	// Inject unknown tag, then a valid KCP packet.
	mock.inject(append([]byte{0xFF}, []byte("unknown")...), testAddr)
	mock.inject(append([]byte{TagKCP}, []byte("valid")...), testAddr)

	buf := make([]byte, 1500)
	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	// Should get the valid packet, unknown was dropped.
	if !bytes.Equal(buf[:n], []byte("valid")) {
		t.Errorf("got %q, want %q", buf[:n], "valid")
	}

	demux.Close()
}

func TestProtoDemuxDropsTooShort(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)
	kcpConn := demux.Conn(TagKCP)

	// Inject a 1-byte packet (tag only, no data) — should be dropped.
	mock.inject([]byte{TagKCP}, testAddr)
	// Then a valid packet.
	mock.inject(append([]byte{TagKCP}, []byte("ok")...), testAddr)

	buf := make([]byte, 1500)
	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("ok")) {
		t.Errorf("got %q, want %q", buf[:n], "ok")
	}

	demux.Close()
}

func TestProtoDemuxPreservesAddr(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)
	kcpConn := demux.Conn(TagKCP)

	srcAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 9999}
	mock.inject(append([]byte{TagKCP}, []byte("data")...), srcAddr)

	buf := make([]byte, 1500)
	_, addr, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr == nil {
		t.Fatal("addr is nil, demux must preserve source address")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}
	if !udpAddr.IP.Equal(srcAddr.IP) || udpAddr.Port != srcAddr.Port {
		t.Errorf("addr = %v, want %v", udpAddr, srcAddr)
	}

	demux.Close()
}

func TestProtoDemuxConnLookup(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC)

	if demux.Conn(TagKCP) == nil {
		t.Error("Conn(TagKCP) should not be nil")
	}
	if demux.Conn(TagQUIC) == nil {
		t.Error("Conn(TagQUIC) should not be nil")
	}
	// TagUDP was not registered.
	if demux.Conn(TagUDP) != nil {
		t.Error("Conn(TagUDP) should be nil when not registered")
	}

	demux.Close()
}

// --- Pool correctness ---

func TestGetDemuxBufSmall(t *testing.T) {
	pool, buf := getDemuxBuf(100)
	if pool == nil {
		t.Fatal("pool should not be nil")
	}
	if len(buf) != 100 {
		t.Errorf("buf len = %d, want 100", len(buf))
	}
	if cap(buf) < 100 {
		t.Errorf("buf cap = %d, want >= 100", cap(buf))
	}
	pool.Put(&buf)
}

func TestGetDemuxBufLarge(t *testing.T) {
	pool, buf := getDemuxBuf(2000)
	if pool == nil {
		t.Fatal("pool should not be nil")
	}
	if len(buf) != 2000 {
		t.Errorf("buf len = %d, want 2000", len(buf))
	}
	pool.Put(&buf)
}

// --- Concurrency stress ---

func TestDemuxConcurrentDeliver(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	defer dc.Close()

	const numPackets = 1000
	var wg sync.WaitGroup
	wg.Add(numPackets)

	for i := range numPackets {
		go func(idx int) {
			defer wg.Done()
			data := []byte{byte(idx & 0xFF)}
			dc.deliver(data, testAddr)
		}(i)
	}

	wg.Wait()

	// Drain what was delivered (some may have been dropped if channel full).
	drained := 0
	for {
		select {
		case <-dc.ch:
			drained++
		default:
			goto done
		}
	}
done:
	if drained == 0 {
		t.Error("expected at least some packets delivered")
	}
	t.Logf("delivered %d/%d packets (channel capacity 512)", drained, numPackets)
}

func TestProtoDemuxConcurrentReads(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC)
	defer demux.Close()

	kcpConn := demux.Conn(TagKCP)
	quicConn := demux.Conn(TagQUIC)

	const perProto = 50
	// Inject alternating KCP and QUIC packets.
	for i := range perProto {
		mock.inject(append([]byte{TagKCP}, byte(i)), testAddr)
		mock.inject(append([]byte{TagQUIC}, byte(i)), testAddr)
	}

	// Read from both in parallel.
	var wg sync.WaitGroup
	readN := func(dc *DemuxedPacketConn, n int) {
		defer wg.Done()
		buf := make([]byte, 1500)
		for range n {
			_, _, err := dc.ReadFrom(buf)
			if err != nil {
				t.Errorf("ReadFrom error: %v", err)
				return
			}
		}
	}

	wg.Add(2)
	go readN(kcpConn, perProto)
	go readN(quicConn, perProto)
	wg.Wait()
}

// --- WriteTo pooling (no allocation check) ---

func TestVirtualPacketConnWriteLargePayload(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// 1400 bytes — typical MTU payload.
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("n = %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts[0].data) != 1+len(payload) {
		t.Errorf("wire len = %d, want %d", len(pkts[0].data), 1+len(payload))
	}
	if pkts[0].data[0] != TagKCP {
		t.Error("tag byte missing")
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Error("payload corrupted")
	}
}

func TestDemuxedPacketConnWriteLargePayload(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagQUIC, mock)
	defer dc.Close()

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := dc.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("n = %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if pkts[0].data[0] != TagQUIC {
		t.Error("tag byte missing")
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Error("payload corrupted")
	}
}
