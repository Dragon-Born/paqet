package tun

import (
	"net"
	"net/netip"
)

// filter decides which destination IPs should be forwarded through the tunnel.
// Traffic to the paqet server, loopback, link-local, multicast, and private
// networks is dropped — exactly what other TUN-based VPNs (sing-box, tun2socks) do.
type filter struct {
	serverIP netip.Addr
}

func newFilter(serverIP string) *filter {
	addr, _ := netip.ParseAddr(serverIP)
	return &filter{serverIP: addr}
}

// shouldForward returns true if traffic to this IP should go through the tunnel.
func (f *filter) shouldForward(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	// Never forward traffic to the paqet server itself (prevents routing loop).
	if addr == f.serverIP {
		return false
	}

	// Drop loopback (127.0.0.0/8, ::1).
	if addr.IsLoopback() {
		return false
	}

	// Drop link-local (169.254.0.0/16, fe80::/10).
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}

	// Drop multicast (224.0.0.0/4, ff00::/8).
	if addr.IsMulticast() {
		return false
	}

	// Drop private/reserved networks.
	if addr.IsPrivate() {
		return false
	}

	// Drop unspecified (0.0.0.0, ::).
	if addr.IsUnspecified() {
		return false
	}

	return true
}
