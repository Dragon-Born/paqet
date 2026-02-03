package tun

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (t *TUN) setupTCPForwarder() {
	fwd := tcp.NewForwarder(t.ns.s, 0, 65535, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dstIP := addrToNetIP(id.LocalAddress)
		if !t.filter.shouldForward(dstIP) {
			r.Complete(true) // RST — don't tunnel this traffic
			return
		}
		targetAddr := fmt.Sprintf("%s:%d", dstIP, id.LocalPort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			flog.Errorf("TUN TCP: failed to create endpoint for %s: %v", targetAddr, err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go t.handleTCP(t.ctx, conn, targetAddr)
	})
	t.ns.s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func (t *TUN) handleTCP(ctx context.Context, conn net.Conn, targetAddr string) {
	defer conn.Close()

	strm, err := t.client.TCP(targetAddr)
	if err != nil {
		flog.Errorf("TUN TCP: failed to establish stream for %s: %v", targetAddr, err)
		return
	}
	defer strm.Close()
	flog.Debugf("TUN TCP: stream %d established for %s", strm.SID(), targetAddr)

	errCh := make(chan error, 2)
	go func() {
		errCh <- buffer.CopyT(conn, strm)
	}()
	go func() {
		errCh <- buffer.CopyT(strm, conn)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			flog.Debugf("TUN TCP: stream %d closed for %s: %v", strm.SID(), targetAddr, err)
		}
	case <-ctx.Done():
	}
}

func addrToNetIP(addr tcpip.Address) net.IP {
	if addr.Len() == 4 {
		a := addr.As4()
		return net.IP(a[:])
	}
	a := addr.As16()
	return net.IP(a[:])
}

func formatAddr(addr tcpip.Address) string {
	return addrToNetIP(addr).String()
}
