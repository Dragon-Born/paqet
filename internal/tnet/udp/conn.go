package udp

import (
	"fmt"
	"net"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"time"

	"github.com/xtaci/smux"
)

// Conn wraps a smux.Session over raw UDP and implements tnet.Conn.
type Conn struct {
	PacketConn *socket.PacketConn
	Session    *smux.Session
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) Ping(wait bool) error {
	strm, err := c.Session.OpenStream()
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
	if c.Session != nil {
		c.Session.Close()
	}
	if c.PacketConn != nil {
		c.PacketConn.Close()
	}
	return err
}

func (c *Conn) LocalAddr() net.Addr                { return c.Session.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.Session.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.Session.SetDeadline(t) }
func (c *Conn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(_ time.Time) error { return nil }
