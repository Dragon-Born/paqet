package quic

import (
	"context"
	"net"
	"paqet/internal/conf"
	"paqet/internal/tnet"

	"github.com/quic-go/quic-go"
)

// Listener wraps a quic.Listener and implements tnet.Listener.
type Listener struct {
	packetConn net.PacketConn
	cfg        *conf.QUIC
	listener   *quic.Listener
}

// Listen creates a QUIC listener on the given raw PacketConn.
func Listen(cfg *conf.QUIC, pConn net.PacketConn) (tnet.Listener, error) {
	tlsConf, err := buildTLSConfig(cfg, true)
	if err != nil {
		return nil, err
	}

	quicConf := buildQUICConfig(cfg)

	l, err := quic.Listen(pConn, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}

	return &Listener{packetConn: pConn, cfg: cfg, listener: l}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	qConn, err := l.listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return &Conn{nil, qConn}, nil
}

func (l *Listener) Close() error {
	if l.listener != nil {
		l.listener.Close()
	}
	if l.packetConn != nil {
		l.packetConn.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
