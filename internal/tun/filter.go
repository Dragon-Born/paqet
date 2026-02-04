package tun

import (
	"net"
	"net/netip"
)

// filter decides which destination IPs should be forwarded through the tunnel.
// Traffic to the paqet server, loopback, link-local, multicast, and private
// networks is dropped — exactly what other TUN-based VPNs (sing-box, tun2socks) do.
// Exception: DNS traffic (port 53) to private IPs is allowed and redirected.
type filter struct {
	serverIP netip.Addr
	dnsIP    netip.Addr
}

func newFilter(serverIP, dnsIP string) *filter {
	sAddr, _ := netip.ParseAddr(serverIP)
	dAddr, _ := netip.ParseAddr(dnsIP)
	return &filter{serverIP: sAddr, dnsIP: dAddr}
}

// DNSServer returns the configured DNS server IP.
func (f *filter) DNSServer() string {
	return f.dnsIP.String()
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

	// Drop private/reserved networks (but DNS is handled separately).
	if addr.IsPrivate() {
		return false
	}

	// Drop unspecified (0.0.0.0, ::).
	if addr.IsUnspecified() {
		return false
	}

	return true
}

// shouldForwardDNS returns true if DNS traffic (port 53) should be forwarded.
// DNS to any destination (including private IPs) is allowed and will be
// redirected to the configured DNS server.
func (f *filter) shouldForwardDNS(ip net.IP, port uint16) bool {
	if port != 53 {
		return false
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	// Never forward to paqet server.
	if addr == f.serverIP {
		return false
	}

	// Drop loopback DNS.
	if addr.IsLoopback() {
		return false
	}

	// Allow DNS to private IPs (will be redirected to configured DNS).
	// Allow DNS to public IPs (will go through tunnel).
	return true
}

// IsDNS returns true if the destination port is DNS (53).
func (f *filter) IsDNS(port uint16) bool {
	return port == 53
}
