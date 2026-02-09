package socket

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"paqet/internal/conf"
	"sync"
	"sync/atomic"
	"time"
)

// errPollTimeout is returned by AF_PACKET handles when the poll timeout expires.
// PacketConn.ReadFrom retries on this error, checking for context cancellation
// between attempts. This enables graceful shutdown: Close cancels the context,
// the reader sees the cancellation on the next poll timeout, exits, and only
// then is the handle closed (avoiding SIGSEGV on unmapped ring buffer).
var errPollTimeout = errors.New("poll timeout")

type PacketConn struct {
	cfg           *conf.Network
	handle        RawHandle // underlying raw handle, owned by PacketConn
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	localAddr     *net.UDPAddr
	readDeadline  atomic.Int64 // UnixNano, 0 means no deadline
	writeDeadline atomic.Int64
	iptGuard      *iptablesGuard
	readWg        sync.WaitGroup // tracks active ReadFrom calls for safe shutdown

	ctx    context.Context
	cancel context.CancelFunc
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	// Install iptables rules to prevent kernel RSTs and conntrack interference.
	// Must be done before the handle starts capturing so we don't miss early packets.
	guard := newIptablesGuard(cfg.Port)
	guard.Install()

	// Create one raw handle shared between send and recv within this PacketConn.
	// Each PacketConn gets its own independent handle, so multiple connections
	// don't conflict on the same ring buffer (AF_PACKET) or capture handle (pcap).
	handle, err := newHandle(cfg)
	if err != nil {
		guard.Remove()
		return nil, fmt.Errorf("failed to create raw handle on %s: %v", cfg.Interface.Name, err)
	}

	sendHandle, err := newSendHandle(cfg, handle)
	if err != nil {
		handle.Close()
		guard.Remove()
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := newRecvHandle(cfg, handle)
	if err != nil {
		handle.Close()
		guard.Remove()
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	// Determine local address for LocalAddr() — required by quic-go.
	var localAddr *net.UDPAddr
	if cfg.IPv4.Addr != nil {
		localAddr = cfg.IPv4.Addr
	} else if cfg.IPv6.Addr != nil {
		localAddr = cfg.IPv6.Addr
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
		handle:     handle,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		localAddr:  localAddr,
		iptGuard:   guard,
		ctx:        ctx,
		cancel:     cancel,
	}

	return conn, nil
}

func (c *PacketConn) checkDeadline(dl *atomic.Int64) error {
	d := dl.Load()
	if d != 0 && time.Now().UnixNano() >= d {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	default:
	}

	c.readWg.Add(1)
	defer c.readWg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return 0, nil, c.ctx.Err()
		default:
		}

		if err := c.checkDeadline(&c.readDeadline); err != nil {
			return 0, nil, err
		}

		payload, addr, err := c.recvHandle.Read()
		if err != nil {
			if err == errPollTimeout {
				continue
			}
			return 0, nil, err
		}
		n = copy(data, payload)
		return n, addr, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}

	if err := c.checkDeadline(&c.writeDeadline); err != nil {
		return 0, err
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	err = c.sendHandle.Write(data, daddr)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.cancel()

	// Wait for active readers to notice the cancelled context and exit.
	// AF_PACKET uses a 200ms poll timeout, so readers exit within ~200ms.
	// For pcap backends, handle.Close() below will unblock any blocked reads.
	ch := make(chan struct{})
	go func() { c.readWg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
	}

	// Close the underlying raw handle once. Send and recv don't own it.
	if c.handle != nil {
		c.handle.Close()
	}

	// If pcap reader was unblocked by handle.Close(), wait for it to finish.
	<-ch

	// Remove iptables rules for this port.
	if c.iptGuard != nil {
		c.iptGuard.Remove()
	}

	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	ns := deadlineToNano(t)
	c.readDeadline.Store(ns)
	c.writeDeadline.Store(ns)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(deadlineToNano(t))
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(deadlineToNano(t))
	return nil
}

func (c *PacketConn) SetReadBuffer(bytes int) error { return nil }

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}

func deadlineToNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
