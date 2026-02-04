package tnet

import (
	"context"
	"net"
	"time"
)

type Conn interface {
	OpenStrm() (Strm, error)
	AcceptStrm() (Strm, error)
	Ping(wait bool) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// DatagramConn extends Conn with unreliable datagram support.
// QUIC connections implement this for high-throughput UDP forwarding.
type DatagramConn interface {
	Conn
	SupportsDatagrams() bool
	SendDatagram(data []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}
