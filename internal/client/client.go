package client

import (
	"context"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/iterator"
	"paqet/internal/socket"
	"paqet/internal/transport"
	"sync"
)

type Client struct {
	cfg      *conf.Conf
	iter     *iterator.Iterator[*timedConn]
	udpPool  *udpPool
	mu       sync.Mutex
	protocol string // resolved protocol (set by probe for auto mode)
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		iter:     &iterator.Iterator[*timedConn]{},
		udpPool:  &udpPool{},
		protocol: cfg.Transport.Protocol,
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	// In auto mode, probe protocols to find the best one.
	if c.cfg.Transport.Protocol == "auto" {
		proto, err := c.probeProtocols(ctx)
		if err != nil {
			return err
		}
		c.protocol = proto
		flog.Infof("auto-protocol selected: %s", proto)
	}

	for i := range c.cfg.Transport.Conn {
		tc, err := newTimedConn(ctx, c.cfg, c.protocol)
		if err != nil {
			flog.Errorf("failed to establish connection %d: %v", i+1, err)
			return err
		}
		flog.Debugf("client connection %d established successfully", i+1)
		c.iter.Items = append(c.iter.Items, tc)
	}
	go c.ticker(ctx)
	go c.startNetworkMonitor(ctx)

	go func() {
		<-ctx.Done()
		for _, tc := range c.iter.Items {
			tc.close()
		}
		flog.Infof("client shutdown complete")
	}()

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %s (%d connections, protocol: %s)", ipv4Addr, ipv6Addr, c.cfg.Server.Addr, len(c.iter.Items), c.protocol)
	return nil
}

func (c *Client) probeProtocols(ctx context.Context) (string, error) {
	newConn := func() (net.PacketConn, error) {
		netCfg := c.cfg.Network
		return socket.New(ctx, &netCfg)
	}

	results, err := transport.Probe(c.cfg.Server.Addr, &c.cfg.Transport, newConn)
	if err != nil {
		return "", err
	}

	return transport.SelectBest(results)
}
