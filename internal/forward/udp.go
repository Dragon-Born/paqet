package forward

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/pkg/hash"
	"paqet/internal/tnet"
	"sync"
	"time"
)

// udpSession tracks an active UDP forwarding session with its own write channel.
type udpSession struct {
	strm    tnet.Strm
	key     uint64
	writeCh chan []byte // buffered channel for outgoing packets
	cancel  context.CancelFunc
	dropped uint64 // count of dropped packets due to buffer full
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
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	flog.Infof("UDP forwarder listening on %s -> %s", laddr, f.targetAddr)

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
			// Non-blocking send to write channel
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			buffer.UPool.Put(bufp)

			select {
			case sess.writeCh <- pkt:
				// Packet queued successfully
			default:
				// Channel full, drop packet (back-pressure)
				sess.dropped++
				if sess.dropped%100 == 1 {
					flog.Debugf("UDP forward: dropped %d packets for %s (buffer full, queue len: %d)", sess.dropped, caddr, len(sess.writeCh))
				}
			}
			continue
		}

		// New session - establish stream
		strm, isNew, strmKey, err := f.client.UDP(caddr.String(), f.targetAddr)
		if err != nil {
			buffer.UPool.Put(bufp)
			flog.Errorf("failed to establish UDP stream for %s -> %s: %v", caddr, f.targetAddr, err)
			continue
		}

		if !isNew {
			// Stream exists but session doesn't - race condition recovery
			// Write first packet directly with length prefix
			if err := buffer.WriteUDPFrame(strm, buf[:n]); err != nil {
				buffer.UPool.Put(bufp)
				flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
				f.client.CloseUDP(strmKey)
				continue
			}
			buffer.UPool.Put(bufp)
			continue
		}

		// Create new session with buffered write channel
		sessCtx, sessCancel := context.WithCancel(ctx)
		sess := &udpSession{
			strm:    strm,
			key:     strmKey,
			writeCh: make(chan []byte, 256), // buffer up to 256 packets
			cancel:  sessCancel,
		}

		// Store session before sending first packet
		sessions.Store(key, sess)

		// Send first packet
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		buffer.UPool.Put(bufp)
		sess.writeCh <- pkt

		flog.Infof("accepted UDP connection %d for %s -> %s", strm.SID(), caddr, f.targetAddr)

		// Start writer goroutine (local -> stream)
		go f.udpWriteLoop(sessCtx, sess)

		// Start reader goroutine (stream -> local)
		go f.udpReadLoop(sessCtx, sess, conn, caddr, key, &sessions)
	}
}

// udpWriteLoop reads packets from the write channel and sends them to the stream.
// Uses length-prefixed framing to preserve UDP datagram boundaries.
func (f *Forward) udpWriteLoop(ctx context.Context, sess *udpSession) {
	var pktsWritten uint64
	for {
		select {
		case <-ctx.Done():
			flog.Debugf("UDP stream %d writer stopping, wrote %d packets", sess.strm.SID(), pktsWritten)
			return
		case pkt := <-sess.writeCh:
			sess.strm.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := buffer.WriteUDPFrame(sess.strm, pkt); err != nil {
				flog.Debugf("UDP stream %d write error after %d packets: %v", sess.strm.SID(), pktsWritten, err)
				sess.cancel()
				return
			}
			sess.strm.SetWriteDeadline(time.Time{})
			pktsWritten++
		}
	}
}

// udpReadLoop reads from the stream and writes back to the local UDP client.
// Uses length-prefixed framing to preserve UDP datagram boundaries.
func (f *Forward) udpReadLoop(ctx context.Context, sess *udpSession, conn *net.UDPConn, caddr *net.UDPAddr, key uint64, sessions *sync.Map) {
	bufp := buffer.UPool.Get().(*[]byte)
	var pktsRead uint64
	defer func() {
		buffer.UPool.Put(bufp)
		sessions.Delete(key)
		f.client.CloseUDP(sess.key)
		sess.cancel()
		flog.Debugf("closing UDP session stream %d", sess.strm.SID())
		flog.Debugf("UDP stream %d closed for %s -> %s (read %d packets)", sess.strm.SID(), caddr, f.targetAddr, pktsRead)
	}()
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 60s timeout for WireGuard keepalives (default 25s interval)
		sess.strm.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := buffer.ReadUDPFrame(sess.strm, buf)
		if err != nil {
			flog.Debugf("UDP stream %d read error for %s after %d packets: %v", sess.strm.SID(), caddr, pktsRead, err)
			return
		}
		pktsRead++

		if _, err := conn.WriteToUDP(buf[:n], caddr); err != nil {
			flog.Debugf("UDP write to %s failed after %d packets: %v", caddr, pktsRead, err)
			return
		}
	}
}
