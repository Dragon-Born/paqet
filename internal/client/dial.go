package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"
)

const maxRetries = 10

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tc := c.iter.Next()
	conn := tc.getConn()
	if conn == nil {
		tc.triggerReconnect()
		return nil, fmt.Errorf("connection unavailable, reconnecting")
	}
	if err := conn.Ping(false); err != nil {
		flog.Infof("connection lost, retrying....")
		tc.triggerReconnect()
		return nil, fmt.Errorf("connection lost, reconnecting")
	}
	go tc.sendTCPF(conn)
	return conn, nil
}

func (c *Client) newStrm() (tnet.Strm, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := c.newConn()
		if err != nil {
			flog.Debugf("session creation failed (attempt %d/%d), retrying", attempt+1, maxRetries)
			backoff(attempt)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			flog.Debugf("failed to open stream (attempt %d/%d), retrying: %v", attempt+1, maxRetries, err)
			backoff(attempt)
			continue
		}
		return strm, nil
	}
	return nil, fmt.Errorf("failed to create stream after %d attempts", maxRetries)
}

func backoff(attempt int) {
	d := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	time.Sleep(d)
}
