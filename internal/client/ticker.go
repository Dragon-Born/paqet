package client

import "context"

func (c *Client) ticker(ctx context.Context) {
	// Placeholder for periodic tasks (e.g., TCPF resend).
	// Currently unused — returns immediately to avoid wasting a goroutine.
}
