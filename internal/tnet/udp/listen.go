package udp

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"

	"github.com/xtaci/smux"
)

// Listener implements tnet.Listener for raw UDP transport.
type Listener struct {
	packetConn net.PacketConn
	cfg        *conf.UDP
	demux      *Demux
}

// Listen creates a UDP listener that demuxes incoming packets by source address.
func Listen(cfg *conf.UDP, pConn net.PacketConn) (tnet.Listener, error) {
	cipher, err := NewCipher(cfg.Block)
	if err != nil {
		return nil, err
	}

	demux := NewDemux(pConn, cipher)
	flog.Debugf("UDP listener started with packet demuxing")

	return &Listener{packetConn: pConn, cfg: cfg, demux: demux}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	cc, err := l.demux.Accept()
	if err != nil {
		return nil, err
	}

	reader := newClientConnReader(cc, l.packetConn, l.demux.cipher)

	sess, err := smux.Server(reader, smuxConf(l.cfg))
	if err != nil {
		return nil, err
	}

	return &Conn{nil, sess}, nil
}

func (l *Listener) Close() error {
	if l.demux != nil {
		l.demux.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.packetConn.LocalAddr()
}
