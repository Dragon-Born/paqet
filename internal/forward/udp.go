package forward

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/pkg/hash"
	"paqet/internal/tnet"
	"sync"
	"sync/atomic"
	"time"
)

// udpStream represents a stream with its own mutex for lock-free round-robin writes.
type udpStream struct {
	strm tnet.Strm
	mu   sync.Mutex
}

// udpSession tracks an active UDP forwarding session with multiple streams.
type udpSession struct {
	streams    []*udpStream
	numStreams int
	nextIdx    uint64 // atomic for round-robin
	cancel     context.CancelFunc
}

func (f *Forward) listenUDP(ctx context.Context) {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to resolve UDP listen address '%s': %v", f.listenAddr, err)
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		flog.Errorf("failed to bind UDP socket on %s: %v", laddr, err)
		return
	}
	defer conn.Close()

	// Increase socket buffers for high-throughput scenarios (8MB each)
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	streamCount := f.streams
	flog.Infof("UDP forwarder listening on %s -> %s (%d streams)", laddr, f.targetAddr, streamCount)

	// Track sessions per client address
	var sessions sync.Map // uint64 -> *udpSession

	for {
		bufp := buffer.UPool.Get().(*[]byte)
		buf := *bufp

		n, caddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			buffer.UPool.Put(bufp)
			select {
			case <-ctx.Done():
				return
			default:
				flog.Errorf("UDP read error on %s: %v", f.listenAddr, err)
				continue
			}
		}
		if n == 0 {
			buffer.UPool.Put(bufp)
			continue
		}

		key := hash.AddrPair(caddr.String(), f.targetAddr)

		// Check for existing session
		if v, ok := sessions.Load(key); ok {
			sess := v.(*udpSession)
			// Round-robin across streams (each stream has its own lock)
			idx := atomic.AddUint64(&sess.nextIdx, 1) % uint64(sess.numStreams)
			stream := sess.streams[idx]

			// Direct write with per-stream lock (no channel overhead)
			stream.mu.Lock()
			err := buffer.WriteUDPFrame(stream.strm, buf[:n])
			stream.mu.Unlock()
			buffer.UPool.Put(bufp)

			if err != nil {
				flog.Debugf("UDP stream %d write error: %v", stream.strm.SID(), err)
			}
			continue
		}

		// New session - establish streams
		sessCtx, sessCancel := context.WithCancel(ctx)
		sess := &udpSession{
			streams:    make([]*udpStream, streamCount),
			numStreams: streamCount,
			cancel:     sessCancel,
		}

		success := true
		for i := 0; i < streamCount; i++ {
			strm, _, err := f.client.UDPNew(f.targetAddr)
			if err != nil {
				flog.Errorf("failed to establish UDP stream %d: %v", i, err)
				for j := 0; j < i; j++ {
					sess.streams[j].strm.Close()
				}
				sessCancel()
				buffer.UPool.Put(bufp)
				success = false
				break
			}
			sess.streams[i] = &udpStream{strm: strm}
		}
		if !success {
			continue
		}

		// Store session
		sessions.Store(key, sess)

		// Send first packet
		sess.streams[0].mu.Lock()
		err = buffer.WriteUDPFrame(sess.streams[0].strm, buf[:n])
		sess.streams[0].mu.Unlock()
		buffer.UPool.Put(bufp)

		if err != nil {
			flog.Errorf("failed to write first packet: %v", err)
			sessions.Delete(key)
			sessCancel()
			for _, s := range sess.streams {
				s.strm.Close()
			}
			continue
		}

		flog.Infof("accepted UDP session for %s -> %s (%d streams)", caddr, f.targetAddr, streamCount)

		// Start reader goroutine for each stream
		for i, stream := range sess.streams {
			go f.udpReadLoop(sessCtx, sess, stream, conn, caddr, key, &sessions, i)
		}
	}
}

// udpReadLoop reads from a stream and writes back to the local UDP client.
func (f *Forward) udpReadLoop(ctx context.Context, sess *udpSession, stream *udpStream, conn *net.UDPConn, caddr *net.UDPAddr, key uint64, sessions *sync.Map, idx int) {
	bufp := buffer.UPool.Get().(*[]byte)
	var pktsRead uint64
	defer func() {
		buffer.UPool.Put(bufp)
		// Only stream 0 cleans up
		if idx == 0 {
			sessions.Delete(key)
			sess.cancel()
			for _, s := range sess.streams {
				s.strm.Close()
			}
			flog.Debugf("UDP session closed for %s -> %s", caddr, f.targetAddr)
		}
	}()
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stream.strm.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := buffer.ReadUDPFrame(stream.strm, buf)
		if err != nil {
			if idx == 0 {
				flog.Debugf("UDP stream %d read error after %d packets: %v", stream.strm.SID(), pktsRead, err)
			}
			return
		}
		pktsRead++

		if _, err := conn.WriteToUDP(buf[:n], caddr); err != nil {
			flog.Debugf("UDP write to %s failed: %v", caddr, err)
			return
		}
	}
}
