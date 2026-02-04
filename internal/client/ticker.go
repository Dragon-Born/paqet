package client

import (
	"context"
	"paqet/internal/flog"
	"time"
)

const (
	healthCheckInterval = 30 * time.Second
)

func (c *Client) ticker(ctx context.Context) {
	healthTicker := time.NewTicker(healthCheckInterval)
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-healthTicker.C:
			c.healthCheck()
		}
	}
}

func (c *Client) healthCheck() {
	for i, tc := range c.iter.Items {
		if tc == nil {
			continue
		}

		tc.mu.Lock()
		conn := tc.conn
		tc.mu.Unlock()

		if conn == nil {
			continue
		}

		if err := conn.Ping(true); err != nil {
			flog.Warnf("connection %d health check failed: %v", i+1, err)
			tc.triggerReconnect()
		}
	}
}
