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

// udpStream represents a single stream in the pool.
type udpStream struct {
	strm    tnet.Strm
	key     uint64
	writeCh chan []byte
}

// udpSession tracks an active UDP forwarding session with multiple parallel streams.
type udpSession struct {
	streams    []*udpStream // slice of parallel streams (size = f.streams)
	numStreams int          // number of streams in this session
	nextIdx    uint64       // atomic counter for round-robin
	cancel     context.CancelFunc
	dropped    uint64 // count of dropped packets due to buffer full
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
	flog.Infof("UDP forwarder listening on %s -> %s (%d parallel streams)", laddr, f.targetAddr, streamCount)

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
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			buffer.UPool.Put(bufp)

			// Round-robin across streams for parallelism
			idx := atomic.AddUint64(&sess.nextIdx, 1) % uint64(sess.numStreams)
			stream := sess.streams[idx]

			select {
			case stream.writeCh <- pkt:
				// Packet queued successfully
			default:
				// Channel full, drop packet (back-pressure)
				sess.dropped++
				if sess.dropped%1000 == 1 {
					flog.Debugf("UDP forward: dropped %d packets for %s (buffer full)", sess.dropped, caddr)
				}
			}
			continue
		}

		// New session - establish multiple streams for parallelism
		sessCtx, sessCancel := context.WithCancel(ctx)
		sess := &udpSession{
			streams:    make([]*udpStream, streamCount),
			numStreams: streamCount,
			cancel:     sessCancel,
		}

		// Calculate per-stream buffer size (total ~4096 packets across all streams)
		perStreamBuffer := 4096 / streamCount
		if perStreamBuffer < 64 {
			perStreamBuffer = 64
		}

		// Create multiple parallel streams using UDPNew (no caching)
		success := true
		for i := 0; i < streamCount; i++ {
			strm, strmKey, err := f.client.UDPNew(f.targetAddr)
			if err != nil {
				flog.Errorf("failed to establish UDP stream %d for %s -> %s: %v", i, caddr, f.targetAddr, err)
				// Close already created streams
				for j := 0; j < i; j++ {
					f.client.CloseUDPStream(sess.streams[j].strm)
				}
				sessCancel()
				buffer.UPool.Put(bufp)
				success = false
				break
			}

			sess.streams[i] = &udpStream{
				strm:    strm,
				key:     strmKey,
				writeCh: make(chan []byte, perStreamBuffer),
			}
		}
		if !success {
			continue
		}

		// Store session before sending first packet
		sessions.Store(key, sess)

		// Send first packet to stream 0
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		buffer.UPool.Put(bufp)
		sess.streams[0].writeCh <- pkt

		flog.Infof("accepted UDP session for %s -> %s (%d parallel streams)", caddr, f.targetAddr, streamCount)

		// Start writer and reader goroutines for each stream
		for i := 0; i < streamCount; i++ {
			stream := sess.streams[i]
			go f.udpWriteLoop(sessCtx, stream)
			go f.udpReadLoop(sessCtx, sess, stream, conn, caddr, key, &sessions, i)
		}
	}
}

// udpWriteLoop reads packets from the write channel and sends them to the stream.
// Uses length-prefixed framing to preserve UDP datagram boundaries.
// Optimized to drain multiple packets per iteration for high throughput.
func (f *Forward) udpWriteLoop(ctx context.Context, stream *udpStream) {
	var pktsWritten uint64
	for {
		select {
		case <-ctx.Done():
			flog.Debugf("UDP stream %d writer stopping, wrote %d packets", stream.strm.SID(), pktsWritten)
			return
		case pkt := <-stream.writeCh:
			// Set deadline once for this batch
			stream.strm.SetWriteDeadline(time.Now().Add(10 * time.Second))

			// Write first packet
			if err := buffer.WriteUDPFrame(stream.strm, pkt); err != nil {
				flog.Debugf("UDP stream %d write error after %d packets: %v", stream.strm.SID(), pktsWritten, err)
				return
			}
			pktsWritten++

			// Drain any additional queued packets without blocking
			drain := true
			for drain {
				select {
				case pkt = <-stream.writeCh:
					if err := buffer.WriteUDPFrame(stream.strm, pkt); err != nil {
						flog.Debugf("UDP stream %d write error after %d packets: %v", stream.strm.SID(), pktsWritten, err)
						return
					}
					pktsWritten++
				default:
					drain = false
				}
			}

			stream.strm.SetWriteDeadline(time.Time{})
		}
	}
}

// udpReadLoop reads from the stream and writes back to the local UDP client.
// Uses length-prefixed framing to preserve UDP datagram boundaries.
func (f *Forward) udpReadLoop(ctx context.Context, sess *udpSession, stream *udpStream, conn *net.UDPConn, caddr *net.UDPAddr, key uint64, sessions *sync.Map, streamIdx int) {
	bufp := buffer.UPool.Get().(*[]byte)
	var pktsRead uint64
	defer func() {
		buffer.UPool.Put(bufp)
		// Only stream 0 cleans up the session
		if streamIdx == 0 {
			sessions.Delete(key)
			sess.cancel()
			// Close all streams
			for i := 0; i < sess.numStreams; i++ {
				if sess.streams[i] != nil {
					f.client.CloseUDPStream(sess.streams[i].strm)
				}
			}
			flog.Debugf("UDP session closed for %s -> %s", caddr, f.targetAddr)
		}
		flog.Debugf("UDP stream %d closed (read %d packets)", stream.strm.SID(), pktsRead)
	}()
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 60s timeout for WireGuard keepalives (default 25s interval)
		stream.strm.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := buffer.ReadUDPFrame(stream.strm, buf)
		if err != nil {
			flog.Debugf("UDP stream %d read error after %d packets: %v", stream.strm.SID(), pktsRead, err)
			return
		}
		pktsRead++

		if _, err := conn.WriteToUDP(buf[:n], caddr); err != nil {
			flog.Debugf("UDP write to %s failed after %d packets: %v", caddr, pktsRead, err)
			return
		}
	}
}
