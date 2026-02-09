//go:build !linux

package socket

type iptablesGuard struct{}

func newIptablesGuard(_ int) *iptablesGuard { return &iptablesGuard{} }
func (g *iptablesGuard) Install()           {}
func (g *iptablesGuard) Remove()            {}
