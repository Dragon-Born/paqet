package socket

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"paqet/internal/conf"
	"sync"
	"sync/atomic"
	"time"
)

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Int64 // UnixNano, 0 means no deadline
	writeDeadline atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
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

	if err := c.checkDeadline(&c.readDeadline); err != nil {
		return 0, nil, err
	}

	payload, addr, err := c.recvHandle.Read()
	if err != nil {
		return 0, nil, err
	}
	n = copy(data, payload)

	return n, addr, nil
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if c.sendHandle != nil {
			c.sendHandle.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if c.recvHandle != nil {
			c.recvHandle.Close()
		}
	}()
	wg.Wait()

	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
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
