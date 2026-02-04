package tun

import (
	"context"
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (t *TUN) setupUDPForwarder() {
	fwd := udp.NewForwarder(t.ns.s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		dstIP := addrToNetIP(id.LocalAddress)
		dstPort := id.LocalPort

		// Check if this is DNS traffic (port 53).
		isDNS := t.filter.IsDNS(dstPort)

		// For DNS: allow even if destination is private (will redirect to configured DNS).
		// For non-DNS: use normal filtering.
		if isDNS {
			if !t.filter.shouldForwardDNS(dstIP, dstPort) {
				return true // drop
			}
		} else {
			if !t.filter.shouldForward(dstIP) {
				return true // drop — don't tunnel this traffic
			}
		}

		localAddr := fmt.Sprintf("%s:%d", formatAddr(id.RemoteAddress), id.RemotePort)

		// For DNS traffic, redirect to configured DNS server.
		var targetAddr string
		if isDNS {
			targetAddr = fmt.Sprintf("%s:%d", t.filter.DNSServer(), dstPort)
			if dstIP.String() != t.filter.DNSServer() {
				flog.Debugf("TUN DNS: redirecting %s -> %s (was %s)", localAddr, targetAddr, dstIP)
			}
		} else {
			targetAddr = fmt.Sprintf("%s:%d", dstIP, dstPort)
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			flog.Errorf("TUN UDP: failed to create endpoint for %s -> %s: %v", localAddr, targetAddr, err)
			return true
		}

		conn := gonet.NewUDPConn(&wq, ep)
		go t.handleUDP(t.ctx, conn, localAddr, targetAddr)
		return true
	})
	t.ns.s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func (t *TUN) handleUDP(ctx context.Context, conn *gonet.UDPConn, localAddr, targetAddr string) {
	defer conn.Close()

	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	buf := *bufp

	// Read the first packet to establish the stream.
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		flog.Errorf("TUN UDP: failed to read first packet for %s -> %s: %v", localAddr, targetAddr, err)
		return
	}

	strm, isNew, key, err := t.client.UDP(localAddr, targetAddr)
	if err != nil {
		flog.Errorf("TUN UDP: failed to establish stream for %s -> %s: %v", localAddr, targetAddr, err)
		return
	}

	if err := buffer.WriteUDPFrame(strm, buf[:n]); err != nil {
		flog.Errorf("TUN UDP: failed to forward %d bytes from %s -> %s: %v", n, localAddr, targetAddr, err)
		t.client.CloseUDP(key)
		return
	}

	if !isNew {
		// Stream already has a reader goroutine; just keep writing.
		t.udpWriteLoop(ctx, conn, strm, localAddr, targetAddr)
		return
	}

	flog.Debugf("TUN UDP: stream %d established for %s -> %s", strm.SID(), localAddr, targetAddr)

	// Start reader: strm -> gVisor conn.
	// Uses length-prefixed framing to preserve UDP datagram boundaries.
	go func() {
		defer func() {
			flog.Debugf("TUN UDP: stream %d closed for %s -> %s", strm.SID(), localAddr, targetAddr)
			t.client.CloseUDP(key)
		}()
		rbuf := buffer.UPool.Get().(*[]byte)
		defer buffer.UPool.Put(rbuf)
		rb := *rbuf
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			strm.SetDeadline(time.Now().Add(8 * time.Second))
			rn, err := buffer.ReadUDPFrame(strm, rb)
			strm.SetDeadline(time.Time{})
			if err != nil {
				flog.Debugf("TUN UDP: stream %d read error for %s -> %s: %v", strm.SID(), localAddr, targetAddr, err)
				return
			}
			if _, err := conn.Write(rb[:rn]); err != nil {
				flog.Debugf("TUN UDP: gVisor write error for %s -> %s: %v", localAddr, targetAddr, err)
				return
			}
		}
	}()

	// Continue writing in this goroutine.
	t.udpWriteLoop(ctx, conn, strm, localAddr, targetAddr)
}

func (t *TUN) udpWriteLoop(ctx context.Context, conn *gonet.UDPConn, strm interface{ Write([]byte) (int, error) }, localAddr, targetAddr string) {
	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if err := buffer.WriteUDPFrame(strm, buf[:n]); err != nil {
			flog.Debugf("TUN UDP: write error for %s -> %s: %v", localAddr, targetAddr, err)
			return
		}
	}
}
