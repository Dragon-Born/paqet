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

const pingTimeout = 5 * time.Second

func (c *Conn) Ping(wait bool) error {
	strm, err := c.QConn.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	defer strm.Close()
	if wait {
		deadline := time.Now().Add(pingTimeout)
		strm.SetWriteDeadline(deadline)
		strm.SetReadDeadline(deadline)

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

// SupportsDatagrams returns true if the connection supports QUIC datagrams.
func (c *Conn) SupportsDatagrams() bool {
	state := c.QConn.ConnectionState()
	return state.SupportsDatagrams.Local && state.SupportsDatagrams.Remote
}

// SendDatagram sends an unreliable datagram over QUIC.
// Returns error if datagrams not supported or payload too large.
func (c *Conn) SendDatagram(data []byte) error {
	return c.QConn.SendDatagram(data)
}

// ReceiveDatagram receives an unreliable datagram from QUIC.
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.QConn.ReceiveDatagram(ctx)
}
