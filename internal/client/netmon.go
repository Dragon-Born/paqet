package client

import (
	"context"
	"net"
	"paqet/internal/flog"
	"time"
)

const (
	netmonCheckInterval = 5 * time.Second
)

// networkState represents the current network state for change detection.
type networkState struct {
	interfaceUp bool
	localIP     string
}

// startNetworkMonitor monitors for network changes and triggers reconnection.
func (c *Client) startNetworkMonitor(ctx context.Context) {
	ticker := time.NewTicker(netmonCheckInterval)
	defer ticker.Stop()

	var lastState networkState
	// Initialize with current state.
	lastState = c.getNetworkState()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentState := c.getNetworkState()
			if c.networkChanged(lastState, currentState) {
				flog.Infof("network change detected (interface: %v->%v, IP: %s->%s)",
					lastState.interfaceUp, currentState.interfaceUp,
					lastState.localIP, currentState.localIP)
				c.handleNetworkChange()
			}
			lastState = currentState
		}
	}
}

// getNetworkState captures the current network state.
func (c *Client) getNetworkState() networkState {
	state := networkState{}

	ifaceName := c.cfg.Network.Interface_
	if ifaceName == "" && c.cfg.Network.Interface != nil {
		ifaceName = c.cfg.Network.Interface.Name
	}

	if ifaceName == "" {
		return state
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return state
	}

	state.interfaceUp = iface.Flags&net.FlagUp != 0

	addrs, err := iface.Addrs()
	if err != nil {
		return state
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				state.localIP = ipv4.String()
				break
			}
		}
	}

	return state
}

// networkChanged returns true if the network state has changed significantly.
func (c *Client) networkChanged(prev, curr networkState) bool {
	// Detect interface going down or coming up.
	if prev.interfaceUp != curr.interfaceUp {
		return true
	}
	// Detect IP address change (e.g., DHCP renewal, WiFi switch).
	if prev.localIP != curr.localIP && prev.localIP != "" && curr.localIP != "" {
		return true
	}
	return false
}

// handleNetworkChange handles a network change by invalidating pools and triggering reconnects.
func (c *Client) handleNetworkChange() {
	// Invalidate UDP pool first.
	c.udpPool.invalidateAll()

	// Trigger reconnect on all connections.
	for _, tc := range c.iter.Items {
		if tc != nil {
			tc.triggerReconnect()
		}
	}

	flog.Infof("triggered reconnection for all connections")
}
