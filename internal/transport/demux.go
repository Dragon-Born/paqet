package transport

import (
	"net"
	"paqet/internal/flog"
)

// ProtoDemux reads from a single PacketConn and routes packets to
// per-protocol DemuxedPacketConns based on the first byte (protocol tag).
//
// Tags are 0x10 (KCP), 0x20 (QUIC), 0x30 (UDP). The lookup table is
// indexed by tag>>4, giving O(1) dispatch with no map or branch.
type ProtoDemux struct {
	inner net.PacketConn
	// lookup is indexed by tag>>4. Only slots 1,2,3 are used for
	// tags 0x10, 0x20, 0x30. nil means unregistered.
	lookup [4]*DemuxedPacketConn
	conns  []*DemuxedPacketConn // for Close iteration
	done   chan struct{}
}

// NewProtoDemux creates a demuxer for the given protocol tags.
// It starts a background read loop immediately.
func NewProtoDemux(pConn net.PacketConn, tags ...byte) *ProtoDemux {
	d := &ProtoDemux{
		inner: pConn,
		done:  make(chan struct{}),
	}
	for _, tag := range tags {
		dc := newDemuxedPacketConn(tag, pConn)
		idx := tag >> 4
		if int(idx) < len(d.lookup) {
			d.lookup[idx] = dc
		}
		d.conns = append(d.conns, dc)
	}
	go d.readLoop()
	return d
}

// Conn returns the DemuxedPacketConn for the given protocol tag.
func (d *ProtoDemux) Conn(tag byte) *DemuxedPacketConn {
	idx := tag >> 4
	if int(idx) < len(d.lookup) {
		return d.lookup[idx]
	}
	return nil
}

func (d *ProtoDemux) readLoop() {
	defer close(d.done)
	buf := make([]byte, 65536)
	for {
		n, addr, err := d.inner.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}

		tag := buf[0]
		idx := tag >> 4
		var dc *DemuxedPacketConn
		if int(idx) < len(d.lookup) {
			dc = d.lookup[idx]
		}
		if dc == nil {
			flog.Debugf("demux: unknown protocol tag 0x%02x from %s, dropping", tag, addr)
			continue
		}
		dc.deliver(buf[1:n], addr)
	}
}

// Close shuts down the demuxer and all per-protocol conns.
func (d *ProtoDemux) Close() {
	d.inner.Close()
	for _, dc := range d.conns {
		dc.Close()
	}
}
