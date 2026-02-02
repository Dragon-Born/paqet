package udp

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"

	"github.com/xtaci/smux"
)

// Dial creates a raw UDP connection with smux multiplexing to the given address.
func Dial(addr *net.UDPAddr, cfg *conf.UDP, pConn *socket.PacketConn) (tnet.Conn, error) {
	cipher, err := NewCipher(cfg.Block)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP cipher: %w", err)
	}

	adapter := NewConnAdapter(pConn, addr, cipher)

	sess, err := smux.Client(adapter, smuxConf(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to create smux session over UDP: %w", err)
	}

	flog.Debugf("UDP connection established to %s with smux", addr)
	return &Conn{pConn, sess}, nil
}
