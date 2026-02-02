package transport

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	pquic "paqet/internal/tnet/quic"
	"paqet/internal/tnet/udp"
)

// Dial creates a transport connection based on the configured protocol.
func Dial(addr *net.UDPAddr, cfg *conf.Transport, pConn *socket.PacketConn) (tnet.Conn, error) {
	switch cfg.Protocol {
	case "kcp":
		return kcp.Dial(addr, cfg.KCP, pConn)
	case "quic":
		return pquic.Dial(addr, cfg.QUIC, pConn)
	case "udp":
		return udp.Dial(addr, cfg.UDP, pConn)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", cfg.Protocol)
	}
}

// Listen creates a transport listener based on the configured protocol.
func Listen(cfg *conf.Transport, pConn *socket.PacketConn) (tnet.Listener, error) {
	switch cfg.Protocol {
	case "kcp":
		return kcp.Listen(cfg.KCP, pConn)
	case "quic":
		return pquic.Listen(cfg.QUIC, pConn)
	case "udp":
		return udp.Listen(cfg.UDP, pConn)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", cfg.Protocol)
	}
}
