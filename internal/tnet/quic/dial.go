package quic

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"

	"github.com/quic-go/quic-go"
)

// dialTimeout is the maximum time to wait for QUIC handshake.
const dialTimeout = 10 * time.Second

// Dial creates a QUIC connection to the given address using the raw PacketConn.
func Dial(addr *net.UDPAddr, cfg *conf.QUIC, pConn net.PacketConn) (tnet.Conn, error) {
	tlsConf, err := buildTLSConfig(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build QUIC TLS config: %w", err)
	}

	quicConf := buildQUICConfig(cfg)

	// Use timeout context to prevent hanging if UDP is blocked.
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	qConn, err := quic.Dial(ctx, pConn, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	flog.Debugf("QUIC connection established to %s", addr)
	return &Conn{pConn, qConn}, nil
}
