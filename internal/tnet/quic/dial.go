package quic

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"

	"github.com/quic-go/quic-go"
)

// Dial creates a QUIC connection to the given address using the raw PacketConn.
func Dial(addr *net.UDPAddr, cfg *conf.QUIC, pConn *socket.PacketConn) (tnet.Conn, error) {
	tlsConf, err := buildTLSConfig(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build QUIC TLS config: %w", err)
	}

	quicConf := buildQUICConfig(cfg)

	qConn, err := quic.Dial(context.Background(), pConn, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	flog.Debugf("QUIC connection established to %s", addr)
	return &Conn{pConn, qConn}, nil
}
