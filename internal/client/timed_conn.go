package client

import (
	"context"
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
	"sync"
	"time"
)

type timedConn struct {
	cfg         *conf.Conf
	conn        tnet.Conn
	expire      time.Time
	ctx         context.Context
	protocol    string // resolved protocol name
	mu          sync.Mutex
	reconnectCh chan struct{}
}

func newTimedConn(ctx context.Context, cfg *conf.Conf, proto string) (*timedConn, error) {
	var err error
	tc := &timedConn{
		cfg:         cfg,
		ctx:         ctx,
		protocol:    proto,
		reconnectCh: make(chan struct{}, 1),
	}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	// Start background reconnect loop.
	go tc.reconnectLoop()

	return tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.cfg.Network
	pConn, err := socket.New(tc.ctx, &netCfg)
	if err != nil {
		return nil, fmt.Errorf("could not create raw packet conn: %w", err)
	}

	var conn tnet.Conn
	if tc.cfg.Transport.Protocol == "auto" {
		// In auto mode, use tagged connection with the probed protocol.
		conn, err = transport.DialProto(tc.protocol, tc.cfg.Server.Addr, &tc.cfg.Transport, pConn)
	} else {
		conn, err = transport.Dial(tc.cfg.Server.Addr, &tc.cfg.Transport, pConn)
	}
	if err != nil {
		pConn.Close()
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		conn.Close()
		pConn.Close()
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) waitConn() tnet.Conn {
	for {
		if c, err := tc.createConn(); err == nil {
			return c
		} else {
			time.Sleep(time.Second)
		}
	}
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
}

// triggerReconnect signals the reconnect loop to reconnect.
func (tc *timedConn) triggerReconnect() {
	select {
	case tc.reconnectCh <- struct{}{}:
		flog.Debugf("reconnect triggered")
	default:
		// Already reconnecting
	}
}

// reconnectLoop handles background reconnection.
func (tc *timedConn) reconnectLoop() {
	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-tc.reconnectCh:
			tc.reconnect()
		}
	}
}

// reconnect closes the current connection and establishes a new one.
func (tc *timedConn) reconnect() {
	tc.mu.Lock()
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
	tc.mu.Unlock()

	flog.Infof("reconnecting...")

	// Use waitConn which retries until success.
	newConn := tc.waitConn()

	tc.mu.Lock()
	tc.conn = newConn
	tc.mu.Unlock()

	flog.Infof("reconnected successfully")
}

// getConn returns the current connection safely.
func (tc *timedConn) getConn() tnet.Conn {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.conn
}
