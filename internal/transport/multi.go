package transport

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	pquic "paqet/internal/tnet/quic"
	"paqet/internal/tnet/udp"
	"sync"
)

// MultiListener listens on all configured protocols simultaneously
// and merges Accept() into a single stream.
type MultiListener struct {
	listeners []tnet.Listener
	acceptCh  chan acceptResult
	done      chan struct{}
	once      sync.Once
	demux     *ProtoDemux
}

type acceptResult struct {
	conn tnet.Conn
	err  error
}

// ListenMulti creates listeners for all protocols on the same PacketConn
// using a protocol demuxer.
func ListenMulti(cfg *conf.Transport, pConn net.PacketConn) (*MultiListener, error) {
	demux := NewProtoDemux(pConn, TagKCP, TagQUIC, TagUDP)

	ml := &MultiListener{
		acceptCh: make(chan acceptResult, 16),
		done:     make(chan struct{}),
		demux:    demux,
	}

	// Start KCP listener.
	if cfg.KCP != nil {
		kcpConn := demux.Conn(TagKCP)
		l, err := kcp.Listen(cfg.KCP, kcpConn)
		if err != nil {
			demux.Close()
			return nil, err
		}
		ml.listeners = append(ml.listeners, l)
		flog.Infof("multi-protocol: KCP listener started")
	}

	// Start QUIC listener.
	if cfg.QUIC != nil {
		quicConn := demux.Conn(TagQUIC)
		l, err := pquic.Listen(cfg.QUIC, quicConn)
		if err != nil {
			ml.closeListeners()
			demux.Close()
			return nil, err
		}
		ml.listeners = append(ml.listeners, l)
		flog.Infof("multi-protocol: QUIC listener started")
	}

	// Start UDP listener.
	if cfg.UDP != nil {
		udpConn := demux.Conn(TagUDP)
		l, err := udp.Listen(cfg.UDP, udpConn)
		if err != nil {
			ml.closeListeners()
			demux.Close()
			return nil, err
		}
		ml.listeners = append(ml.listeners, l)
		flog.Infof("multi-protocol: UDP listener started")
	}

	// Start accept goroutines for each listener.
	for _, l := range ml.listeners {
		go ml.acceptLoop(l)
	}

	return ml, nil
}

func (ml *MultiListener) acceptLoop(l tnet.Listener) {
	for {
		conn, err := l.Accept()
		select {
		case ml.acceptCh <- acceptResult{conn, err}:
			if err != nil {
				return
			}
		case <-ml.done:
			return
		}
	}
}

func (ml *MultiListener) Accept() (tnet.Conn, error) {
	select {
	case res := <-ml.acceptCh:
		return res.conn, res.err
	case <-ml.done:
		return nil, net.ErrClosed
	}
}

func (ml *MultiListener) Close() error {
	ml.once.Do(func() {
		close(ml.done)
		ml.closeListeners()
		ml.demux.Close()
	})
	return nil
}

func (ml *MultiListener) closeListeners() {
	for _, l := range ml.listeners {
		l.Close()
	}
}

func (ml *MultiListener) Addr() net.Addr {
	if len(ml.listeners) > 0 {
		return ml.listeners[0].Addr()
	}
	return nil
}
