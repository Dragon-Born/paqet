package client

import (
	"context"
	"paqet/internal/flog"
	"paqet/internal/pkg/hash"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"sync/atomic"
)

// udpStreamCounter generates unique keys for uncached UDP streams
var udpStreamCounter uint64

// UDP returns a cached or new UDP stream for the given address pair.
// Used by TUN mode where stream reuse is beneficial.
func (c *Client) UDP(lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	key := hash.AddrPair(lAddr, tAddr)
	if v, ok := c.udpPool.strms.Load(key); ok {
		strm := v.(tnet.Strm)
		flog.Debugf("reusing UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
		return strm, false, key, nil
	}

	strm, err := c.newStrm()
	if err != nil {
		flog.Debugf("failed to create stream for UDP %s -> %s: %v", lAddr, tAddr, err)
		return nil, false, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		flog.Debugf("invalid UDP address %s: %v", tAddr, err)
		strm.Close()
		return nil, false, 0, err
	}
	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write UDP protocol header for %s -> %s on stream %d: %v", lAddr, tAddr, strm.SID(), err)
		strm.Close()
		return nil, false, 0, err
	}

	// Use LoadOrStore to handle concurrent insertions atomically
	if existing, loaded := c.udpPool.strms.LoadOrStore(key, strm); loaded {
		// Another goroutine already inserted, close our stream and use existing
		strm.Close()
		existingStrm := existing.(tnet.Strm)
		flog.Debugf("reusing UDP stream %d for %s -> %s (concurrent insert)", existingStrm.SID(), lAddr, tAddr)
		return existingStrm, false, key, nil
	}

	flog.Debugf("established UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
	return strm, true, key, nil
}

// UDPNew creates a new UDP stream without caching.
// Used by forward mode for parallel streams to the same target.
// Returns the stream and a unique key for cleanup.
func (c *Client) UDPNew(tAddr string) (tnet.Strm, uint64, error) {
	strm, err := c.newStrm()
	if err != nil {
		flog.Debugf("failed to create stream for UDP -> %s: %v", tAddr, err)
		return nil, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		flog.Debugf("invalid UDP address %s: %v", tAddr, err)
		strm.Close()
		return nil, 0, err
	}
	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write UDP protocol header for -> %s on stream %d: %v", tAddr, strm.SID(), err)
		strm.Close()
		return nil, 0, err
	}

	// Generate unique key for tracking (not stored in pool)
	key := atomic.AddUint64(&udpStreamCounter, 1)

	flog.Debugf("established UDP stream %d for -> %s", strm.SID(), tAddr)
	return strm, key, nil
}

// CloseUDPStream closes a stream directly (for UDPNew streams).
func (c *Client) CloseUDPStream(strm tnet.Strm) {
	if strm != nil {
		strm.Close()
	}
}

func (c *Client) CloseUDP(key uint64) error {
	return c.udpPool.delete(key)
}

// UDPDatagramSession represents a datagram-based UDP forwarding session.
// Uses QUIC datagrams for unreliable, high-throughput UDP forwarding.
type UDPDatagramSession struct {
	conn   tnet.DatagramConn
	ctx    context.Context
	cancel context.CancelFunc
}

// UDPDatagramNew creates a new datagram-based UDP session if the transport supports it.
// Returns nil if datagrams are not supported (caller should fall back to streams).
func (c *Client) UDPDatagramNew(ctx context.Context, tAddr string) (*UDPDatagramSession, error) {
	// Get a connection and check if it supports datagrams
	tc := c.iter.Next()
	if tc == nil {
		return nil, nil // No connections available
	}

	conn := tc.getConn()
	if conn == nil {
		return nil, nil
	}

	// Check if connection supports datagrams
	dgConn, ok := conn.(tnet.DatagramConn)
	if !ok || !dgConn.SupportsDatagrams() {
		flog.Debugf("connection doesn't support datagrams, falling back to streams")
		return nil, nil
	}

	// Open a control stream to register the datagram session
	strm, err := conn.OpenStrm()
	if err != nil {
		return nil, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		strm.Close()
		return nil, err
	}

	// Send PUDPDGM protocol header to register datagram mode
	p := protocol.Proto{Type: protocol.PUDPDGM, Addr: taddr}
	if err := p.Write(strm); err != nil {
		strm.Close()
		return nil, err
	}
	strm.Close() // Control stream no longer needed

	sessCtx, cancel := context.WithCancel(ctx)
	flog.Infof("established UDP datagram session for -> %s", tAddr)

	return &UDPDatagramSession{
		conn:   dgConn,
		ctx:    sessCtx,
		cancel: cancel,
	}, nil
}

// Send sends a UDP packet via QUIC datagram.
func (s *UDPDatagramSession) Send(data []byte) error {
	return s.conn.SendDatagram(data)
}

// Receive receives a UDP packet via QUIC datagram.
func (s *UDPDatagramSession) Receive() ([]byte, error) {
	return s.conn.ReceiveDatagram(s.ctx)
}

// Close closes the datagram session.
func (s *UDPDatagramSession) Close() {
	s.cancel()
}
