package forward

import (
	"context"
	"fmt"
	"paqet/internal/client"
	"paqet/internal/flog"
	"sync"
)

type Forward struct {
	client     *client.Client
	listenAddr string
	targetAddr string
	streams    int // Number of parallel streams for UDP forwarding
	wg         sync.WaitGroup
}

func New(client *client.Client, listenAddr, targetAddr string, streams int) (*Forward, error) {
	if streams < 1 {
		streams = 8 // default
	}
	return &Forward{
		client:     client,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		streams:    streams,
	}, nil
}

func (f *Forward) Start(ctx context.Context, protocol string) error {
	flog.Debugf("starting %s forwarder: %s -> %s", protocol, f.listenAddr, f.targetAddr)
	switch protocol {
	case "tcp":
		return f.startTCP(ctx)
	case "udp":
		return f.startUDP(ctx)
	default:
		flog.Errorf("unsupported protocol: %s", protocol)
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (f *Forward) startTCP(ctx context.Context) error {
	f.wg.Go(func() {
		if err := f.listenTCP(ctx); err != nil {
			flog.Debugf("TCP forwarder stopped with: %v", err)
		}
	})
	return nil
}

func (f *Forward) startUDP(ctx context.Context) error {
	f.wg.Go(func() {
		f.listenUDP(ctx)
	})
	return nil
}
