package client

import (
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
