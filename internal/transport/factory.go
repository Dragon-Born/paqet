package transport

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	pquic "paqet/internal/tnet/quic"
	"paqet/internal/tnet/udp"
)

// Dial creates a transport connection based on the configured protocol.
// For "auto" mode, the caller should use Probe() first to select the best protocol,
// then call DialProto() with the chosen protocol name.
func Dial(addr *net.UDPAddr, cfg *conf.Transport, pConn net.PacketConn) (tnet.Conn, error) {
	switch cfg.Protocol {
	case "kcp":
		return kcp.Dial(addr, cfg.KCP, pConn)
	case "quic":
		return pquic.Dial(addr, cfg.QUIC, pConn)
	case "udp":
		return udp.Dial(addr, cfg.UDP, pConn)
	case "auto":
		return nil, fmt.Errorf("use Probe() and DialProto() for auto mode")
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", cfg.Protocol)
	}
}

// DialProto dials using a specific protocol, wrapping the PacketConn with
// the appropriate protocol tag for multi-protocol demuxing.
func DialProto(proto string, addr *net.UDPAddr, cfg *conf.Transport, pConn net.PacketConn) (tnet.Conn, error) {
	tag := ProtoTag(proto)
	if tag == 0 {
		return nil, fmt.Errorf("unknown protocol: %s", proto)
	}
	tagged := NewVirtualPacketConn(pConn, tag)
	switch proto {
	case "kcp":
		return kcp.Dial(addr, cfg.KCP, tagged)
	case "quic":
		return pquic.Dial(addr, cfg.QUIC, tagged)
	case "udp":
		return udp.Dial(addr, cfg.UDP, tagged)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", proto)
	}
}

// Listen creates a transport listener based on the configured protocol.
// For "auto" mode, use ListenMulti() instead.
func Listen(cfg *conf.Transport, pConn net.PacketConn) (tnet.Listener, error) {
	switch cfg.Protocol {
	case "kcp":
		return kcp.Listen(cfg.KCP, pConn)
	case "quic":
		return pquic.Listen(cfg.QUIC, pConn)
	case "udp":
		return udp.Listen(cfg.UDP, pConn)
	case "auto":
		return ListenMulti(cfg, pConn)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", cfg.Protocol)
	}
}
