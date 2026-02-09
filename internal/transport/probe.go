package transport

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	pquic "paqet/internal/tnet/quic"
	"paqet/internal/tnet/udp"
	"sort"
	"time"
)

// ProbeResult holds the measurement results for a single protocol.
type ProbeResult struct {
	Protocol string
	RTT      time.Duration
	Success  bool
	Error    error
}

const probeTimeout = 5 * time.Second
const probePings = 3
const pingTimeout = 3 * time.Second

// Probe tests each configured protocol by connecting to the server,
// sending pings, and measuring RTT. Returns results sorted by RTT (best first).
func Probe(addr *net.UDPAddr, cfg *conf.Transport, newConn func() (net.PacketConn, error)) ([]ProbeResult, error) {
	protocols := autoProtocols(cfg)
	if len(protocols) == 0 {
		return nil, fmt.Errorf("no protocols configured for auto mode")
	}

	results := make([]ProbeResult, 0, len(protocols))
	for _, proto := range protocols {
		flog.Infof("probing protocol: %s", proto)
		result := probeOne(proto, addr, cfg, newConn)
		results = append(results, result)
		if result.Success {
			flog.Infof("  %s: RTT=%v", proto, result.RTT)
		} else {
			flog.Infof("  %s: failed (%v)", proto, result.Error)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Success != results[j].Success {
			return results[i].Success
		}
		return results[i].RTT < results[j].RTT
	})

	return results, nil
}

// SelectBest returns the protocol name of the best result, or error if none succeeded.
func SelectBest(results []ProbeResult) (string, error) {
	for _, r := range results {
		if r.Success {
			return r.Protocol, nil
		}
	}
	return "", fmt.Errorf("all protocol probes failed")
}

func autoProtocols(cfg *conf.Transport) []string {
	var protos []string
	if cfg.KCP != nil {
		protos = append(protos, "kcp")
	}
	if cfg.QUIC != nil {
		protos = append(protos, "quic")
	}
	if cfg.UDP != nil {
		protos = append(protos, "udp")
	}
	return protos
}

func probeOne(proto string, addr *net.UDPAddr, cfg *conf.Transport, newConn func() (net.PacketConn, error)) ProbeResult {
	result := ProbeResult{Protocol: proto}

	pConn, err := newConn()
	if err != nil {
		result.Error = fmt.Errorf("create conn: %w", err)
		return result
	}

	// Wrap with protocol tag so the multi-protocol server can demux.
	tagged := NewVirtualPacketConn(pConn, ProtoTag(proto))

	var conn tnet.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		switch proto {
		case "kcp":
			conn, err = kcp.Dial(addr, cfg.KCP, tagged)
		case "quic":
			conn, err = pquic.Dial(addr, cfg.QUIC, tagged)
		case "udp":
			conn, err = udp.Dial(addr, cfg.UDP, tagged)
		default:
			err = fmt.Errorf("unknown protocol: %s", proto)
		}
	}()

	select {
	case <-done:
	case <-time.After(probeTimeout):
		result.Error = fmt.Errorf("dial timed out")
		pConn.Close()
		return result
	}

	if err != nil {
		result.Error = fmt.Errorf("dial: %w", err)
		pConn.Close()
		return result
	}
	defer func() {
		conn.Close()
		pConn.Close()
	}()

	// Measure RTT with ping. Each ping has a timeout to prevent
	// blocking indefinitely if the server stops responding.
	var totalRTT time.Duration
	var successes int
	for i := 0; i < probePings; i++ {
		start := time.Now()
		pingErr := make(chan error, 1)
		go func() { pingErr <- conn.Ping(true) }()
		select {
		case err := <-pingErr:
			if err != nil {
				flog.Debugf("  %s: ping %d failed: %v", proto, i+1, err)
				continue
			}
		case <-time.After(pingTimeout):
			flog.Debugf("  %s: ping %d timed out", proto, i+1)
			continue
		}
		totalRTT += time.Since(start)
		successes++
	}

	if successes == 0 {
		result.Error = fmt.Errorf("all pings failed")
		return result
	}

	result.RTT = totalRTT / time.Duration(successes)
	result.Success = true
	return result
}
