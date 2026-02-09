package tun

import (
	"context"
	"fmt"
	"net/netip"
	"paqet/internal/client"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	client   *client.Client
	cfg      *conf.TUN
	serverIP string
	dev      wgtun.Device
	devName  string
	ns       *netStack
	router   routeManager
	filter   *filter
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	done     chan struct{}
}

func New(c *client.Client, cfg *conf.TUN, serverIP string) (*TUN, error) {
	return &TUN{
		client:   c,
		cfg:      cfg,
		serverIP: serverIP,
		router:   newRouteManager(),
		filter:   newFilter(serverIP, cfg.DNS),
		done:     make(chan struct{}),
	}, nil
}

func (t *TUN) Start(ctx context.Context) error {
	t.ctx, t.cancel = context.WithCancel(ctx)

	// Create TUN device.
	dev, name, err := createTUN(t.cfg.Name_, t.cfg.MTU)
	if err != nil {
		return err
	}
	t.dev = dev
	t.devName = name
	flog.Infof("TUN device created: %s (MTU %d)", name, t.cfg.MTU)

	// Parse address prefix.
	prefix, err := netip.ParsePrefix(t.cfg.Addr)
	if err != nil {
		t.dev.Close()
		return fmt.Errorf("invalid TUN address: %w", err)
	}

	// Create gVisor network stack.
	ns, err := newNetStack(dev, prefix, t.cfg.MTU)
	if err != nil {
		t.dev.Close()
		return fmt.Errorf("failed to create network stack: %w", err)
	}
	t.ns = ns

	// Set up TCP and UDP forwarders on the stack.
	t.setupTCPForwarder()
	t.setupUDPForwarder()

	// Start packet shuttles between TUN device and gVisor.
	go ns.tunToStack(t.ctx)
	go ns.stackToTun(t.ctx)

	// Configure system routes and DNS.
	if *t.cfg.AutoRoute {
		if err := t.router.addRoutes(t.dev, t.devName, t.cfg.Addr, t.serverIP, t.cfg.DNS, t.cfg.Exclude); err != nil {
			t.Close()
			return fmt.Errorf("failed to configure routes: %w", err)
		}
	}

	flog.Infof("TUN mode started: %s %s -> tunnel -> server", t.devName, prefix.Addr())
	return nil
}

// Close performs graceful shutdown: restores routes, closes stack and device.
// Safe to call multiple times.
func (t *TUN) Close() {
	t.once.Do(func() {
		defer close(t.done)
		if *t.cfg.AutoRoute {
			if err := t.router.removeRoutes(); err != nil {
				flog.Errorf("TUN: failed to remove routes: %v", err)
			}
		}
		if t.ns != nil {
			t.ns.close()
		}
		if t.dev != nil {
			t.dev.Close()
		}
		flog.Infof("TUN device %s closed", t.devName)
	})
}
