package quic

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"time"

	"github.com/quic-go/quic-go"
)

// Conn wraps a quic.Conn and implements tnet.Conn.
type Conn struct {
	PacketConn net.PacketConn
	QConn      *quic.Conn
}

func (c *Conn) newStrm(s *quic.Stream) tnet.Strm {
	return &Strm{
		stream:     s,
		localAddr:  c.QConn.LocalAddr(),
		remoteAddr: c.QConn.RemoteAddr(),
	}
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.QConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return c.newStrm(strm), nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.QConn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return c.newStrm(strm), nil
}

func (c *Conn) Ping(wait bool) error {
	strm, err := c.QConn.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	defer strm.Close()
	if wait {
		p := protocol.Proto{Type: protocol.PPING}
		err = p.Write(strm)
		if err != nil {
			return fmt.Errorf("connection test failed: %v", err)
		}
		err = p.Read(strm)
		if err != nil {
			return fmt.Errorf("connection test failed: %v", err)
		}
		if p.Type != protocol.PPONG {
			return fmt.Errorf("connection test failed: unexpected response type")
		}
	}
	return nil
}

func (c *Conn) Close() error {
	var err error
	if c.QConn != nil {
		err = c.QConn.CloseWithError(0, "close")
	}
	if c.PacketConn != nil {
		c.PacketConn.Close()
	}
	return err
}

func (c *Conn) LocalAddr() net.Addr                { return c.QConn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.QConn.RemoteAddr() }
func (c *Conn) SetDeadline(_ time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(_ time.Time) error { return nil }
