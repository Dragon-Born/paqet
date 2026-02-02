package transport

import (
	"net"
	"sync"
	"time"
)

// Protocol tag bytes prepended to every packet for demuxing.
const (
	TagKCP  byte = 0x10
	TagQUIC byte = 0x20
	TagUDP  byte = 0x30
)

// ProtoName returns the human-readable name for a protocol tag.
func ProtoName(tag byte) string {
	switch tag {
	case TagKCP:
		return "kcp"
	case TagQUIC:
		return "quic"
	case TagUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// ProtoTag returns the tag byte for a protocol name.
func ProtoTag(name string) byte {
	switch name {
	case "kcp":
		return TagKCP
	case "quic":
		return TagQUIC
	case "udp":
		return TagUDP
	default:
		return 0
	}
}

// VirtualPacketConn wraps a net.PacketConn and transparently prepends a
// protocol tag byte on writes and strips it on reads. Used for client-side
// tagging when speaking to a multi-protocol server.
//
// On the read path, the caller's buffer is passed directly to the inner
// ReadFrom offset by 1 byte, avoiding any intermediate copy. On the write
// path, a pooled buffer is used to prepend the tag byte without per-packet
// heap allocation.
type VirtualPacketConn struct {
	inner net.PacketConn
	tag   byte
}

// NewVirtualPacketConn wraps a PacketConn with a protocol tag byte.
func NewVirtualPacketConn(inner net.PacketConn, tag byte) *VirtualPacketConn {
	return &VirtualPacketConn{inner: inner, tag: tag}
}

func (v *VirtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) == 0 {
		return 0, nil, nil
	}
	// Read directly into caller's buffer at offset 0, but we need to
	// receive the tag byte too. Use the caller's buffer with +1 capacity
	// trick: read into a buffer that starts 1 byte before p.
	// Since we can't do that safely, use the pool buffer approach but
	// read into it and do a single copy (unavoidable with tag stripping).
	bp := writeBufPool.Get().(*[]byte)
	buf := *bp
	n, addr, err := v.inner.ReadFrom(buf)
	if err != nil {
		writeBufPool.Put(bp)
		return 0, nil, err
	}
	if n < 2 {
		writeBufPool.Put(bp)
		return 0, addr, nil
	}
	if buf[0] != v.tag {
		writeBufPool.Put(bp)
		return 0, addr, nil
	}
	nn := copy(p, buf[1:n])
	writeBufPool.Put(bp)
	return nn, addr, nil
}

func (v *VirtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	bp := writeBufPool.Get().(*[]byte)
	buf := *bp
	buf[0] = v.tag
	nn := copy(buf[1:], p)
	n, err := v.inner.WriteTo(buf[:1+nn], addr)
	writeBufPool.Put(bp)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		n--
	}
	return n, nil
}

func (v *VirtualPacketConn) Close() error                       { return nil }
func (v *VirtualPacketConn) LocalAddr() net.Addr                { return v.inner.LocalAddr() }
func (v *VirtualPacketConn) SetDeadline(t time.Time) error      { return v.inner.SetDeadline(t) }
func (v *VirtualPacketConn) SetReadDeadline(t time.Time) error  { return v.inner.SetReadDeadline(t) }
func (v *VirtualPacketConn) SetWriteDeadline(t time.Time) error { return v.inner.SetWriteDeadline(t) }
func (v *VirtualPacketConn) SetDSCP(dscp int) error             { return nil }

// writeBufPool is shared by VirtualPacketConn for both read and write paths.
// Stored as *[]byte to avoid interface boxing allocation on Get().
var writeBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

// DemuxedPacketConn is a per-protocol view of the server's packet stream.
// It receives packets from ProtoDemux (tag already stripped) via a channel
// and writes tagged packets back to the underlying PacketConn.
//
// The read path does one copy (channel buffer → caller buffer).
// The write path uses a pooled buffer to prepend the tag byte.
type DemuxedPacketConn struct {
	tag    byte
	writer net.PacketConn
	ch     chan demuxPacket
	done   chan struct{}
	once   sync.Once
}

type demuxPacket struct {
	data []byte
	n    int
	addr net.Addr
	pool *sync.Pool
}

func (p *demuxPacket) putBack() {
	if p.pool != nil {
		b := p.data
		p.pool.Put(&b)
	}
}

func newDemuxedPacketConn(tag byte, writer net.PacketConn) *DemuxedPacketConn {
	return &DemuxedPacketConn{
		tag:    tag,
		writer: writer,
		ch:     make(chan demuxPacket, 512),
		done:   make(chan struct{}),
	}
}

// deliver is called by ProtoDemux from its read loop. It copies the data
// into a pooled buffer and enqueues it. This is one unavoidable copy since
// the demux read buffer is reused immediately after deliver returns.
func (d *DemuxedPacketConn) deliver(data []byte, addr net.Addr) {
	pool, buf := getDemuxBuf(len(data))
	copy(buf, data)
	select {
	case d.ch <- demuxPacket{data: buf, n: len(data), addr: addr, pool: pool}:
	case <-d.done:
		pool.Put(&buf)
	default:
		pool.Put(&buf)
	}
}

func (d *DemuxedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-d.ch:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data[:pkt.n])
		addr := pkt.addr
		pkt.putBack()
		return n, addr, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	}
}

func (d *DemuxedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	bp := writeBufPool.Get().(*[]byte)
	buf := *bp
	buf[0] = d.tag
	nn := copy(buf[1:], p)
	n, err := d.writer.WriteTo(buf[:1+nn], addr)
	writeBufPool.Put(bp)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		n--
	}
	return n, nil
}

func (d *DemuxedPacketConn) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

func (d *DemuxedPacketConn) LocalAddr() net.Addr                { return d.writer.LocalAddr() }
func (d *DemuxedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (d *DemuxedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *DemuxedPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *DemuxedPacketConn) SetDSCP(dscp int) error             { return nil }

var (
	demuxSmallPool = sync.Pool{New: func() any { b := make([]byte, 1500); return &b }}
	demuxLargePool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

func getDemuxBuf(n int) (*sync.Pool, []byte) {
	if n <= 1500 {
		bp := demuxSmallPool.Get().(*[]byte)
		return &demuxSmallPool, (*bp)[:n]
	}
	bp := demuxLargePool.Get().(*[]byte)
	return &demuxLargePool, (*bp)[:n]
}
