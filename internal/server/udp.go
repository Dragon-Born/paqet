package server

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"sync"
	"sync/atomic"
	"time"
)

// sharedUDPConn manages a shared UDP connection with multiple stream writers.
// Critical for protocols like WireGuard that expect one source port per peer.
// Design inspired by udp2raw: single connection, multiplexed streams.
type sharedUDPConn struct {
	conn     *net.UDPConn
	addr     string
	refCount int32 // atomic reference count
	cancel   context.CancelFunc

	// Lock-free stream array for minimal contention
	// Uses copy-on-write for stream list updates (rare operation)
	streams atomic.Value // *[]tnet.Strm
	nextIdx uint64       // atomic counter for round-robin
}

// udpConnPool manages shared UDP connections by target address.
type udpConnPool struct {
	conns sync.Map   // addr -> *sharedUDPConn
	mu    sync.Mutex // protects creation
}

var serverUDPPool = &udpConnPool{}

func (p *udpConnPool) getOrCreate(ctx context.Context, addr string) (*sharedUDPConn, error) {
	// Fast path: connection exists
	if v, ok := p.conns.Load(addr); ok {
		shared := v.(*sharedUDPConn)
		atomic.AddInt32(&shared.refCount, 1)
		return shared, nil
	}

	// Slow path with mutex to prevent duplicate connections
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring lock
	if v, ok := p.conns.Load(addr); ok {
		shared := v.(*sharedUDPConn)
		atomic.AddInt32(&shared.refCount, 1)
		return shared, nil
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}

	// Increase socket buffers for high throughput
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)

	connCtx, cancel := context.WithCancel(ctx)
	shared := &sharedUDPConn{
		conn:     conn,
		addr:     addr,
		refCount: 1,
		cancel:   cancel,
	}
	// Initialize with empty slice
	emptyStreams := make([]tnet.Strm, 0, 16)
	shared.streams.Store(&emptyStreams)

	p.conns.Store(addr, shared)

	// Start the shared reader goroutine
	go shared.readLoop(connCtx)

	flog.Debugf("created shared UDP connection to %s", addr)
	return shared, nil
}

func (p *udpConnPool) release(shared *sharedUDPConn) {
	if atomic.AddInt32(&shared.refCount, -1) == 0 {
		p.conns.Delete(shared.addr)
		shared.cancel()
		shared.conn.Close()
		flog.Debugf("closed shared UDP connection to %s", shared.addr)
	}
}

// readLoop reads from the UDP connection and distributes to streams round-robin.
// Optimized: no locks in hot path, uses atomic.Value for stream list.
func (s *sharedUDPConn) readLoop(ctx context.Context) {
	// Use pooled buffer to reduce allocations
	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := s.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			flog.Debugf("shared UDP read error for %s: %v", s.addr, err)
			return
		}

		// Lock-free read of stream list
		streamsPtr := s.streams.Load().(*[]tnet.Strm)
		streams := *streamsPtr
		numStreams := len(streams)
		if numStreams == 0 {
			continue
		}

		// Round-robin select a stream (lock-free)
		idx := atomic.AddUint64(&s.nextIdx, 1) % uint64(numStreams)
		strm := streams[idx]

		// Write directly to stream - no channel overhead
		// The stream's internal buffering handles backpressure
		if err := buffer.WriteUDPFrame(strm, buf[:n]); err != nil {
			// Try next stream on failure
			for i := 1; i < numStreams; i++ {
				tryIdx := (int(idx) + i) % numStreams
				if err := buffer.WriteUDPFrame(streams[tryIdx], buf[:n]); err == nil {
					break
				}
			}
		}
	}
}

// addStream registers a stream (copy-on-write for thread safety).
func (s *sharedUDPConn) addStream(strm tnet.Strm) {
	for {
		oldPtr := s.streams.Load().(*[]tnet.Strm)
		oldStreams := *oldPtr
		newStreams := make([]tnet.Strm, len(oldStreams)+1)
		copy(newStreams, oldStreams)
		newStreams[len(oldStreams)] = strm
		if s.streams.CompareAndSwap(oldPtr, &newStreams) {
			return
		}
	}
}

// removeStream unregisters a stream (copy-on-write for thread safety).
func (s *sharedUDPConn) removeStream(strm tnet.Strm) {
	for {
		oldPtr := s.streams.Load().(*[]tnet.Strm)
		oldStreams := *oldPtr
		newStreams := make([]tnet.Strm, 0, len(oldStreams))
		for _, st := range oldStreams {
			if st != strm {
				newStreams = append(newStreams, st)
			}
		}
		if s.streams.CompareAndSwap(oldPtr, &newStreams) {
			return
		}
	}
}

func (s *Server) handleUDPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("accepted UDP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleUDP(ctx, strm, p.Addr.String())
}

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) error {
	// Get or create shared connection for this target
	shared, err := serverUDPPool.getOrCreate(ctx, addr)
	if err != nil {
		flog.Errorf("failed to get shared UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer serverUDPPool.release(shared)

	// Register this stream for receiving responses
	shared.addStream(strm)
	defer shared.removeStream(strm)

	flog.Debugf("UDP stream %d joined shared connection to %s (refs: %d)", strm.SID(), addr, atomic.LoadInt32(&shared.refCount))

	// Stream -> target: read length-prefixed frames, write to shared UDP
	// This is the only goroutine needed - responses are written by readLoop
	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := buffer.ReadUDPFrame(strm, buf)
		if err != nil {
			flog.Debugf("UDP stream %d to %s ended: %v", strm.SID(), addr, err)
			return err
		}

		// Write to shared connection (all streams share one UDP socket)
		shared.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := shared.conn.Write(buf[:n]); err != nil {
			flog.Debugf("UDP stream %d write to %s failed: %v", strm.SID(), addr, err)
			return err
		}
		shared.conn.SetWriteDeadline(time.Time{})
	}
}
