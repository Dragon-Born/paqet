//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"paqet/internal/flog"
	"strconv"
	"strings"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type windowsRouteManager struct {
	serverIP    string
	tunAddr     string
	tunName     string
	origGateway string
	ifIndex     int
	dnsIP       string
	excludes    []string
}

func newRouteManager() routeManager {
	return &windowsRouteManager{}
}

func (r *windowsRouteManager) addRoutes(_ wgtun.Device, tunName, tunAddr, serverIP, dnsIP string, excludes []string) error {
	r.serverIP = serverIP
	r.tunAddr = tunAddr
	r.tunName = tunName
	r.dnsIP = dnsIP
	r.excludes = excludes

	// Get TUN interface index by name.
	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		return fmt.Errorf("failed to get TUN interface: %w", err)
	}
	r.ifIndex = iface.Index
	flog.Debugf("TUN interface index: %d", r.ifIndex)

	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}
	ip := prefix.Addr().String()
	ifStr := strconv.Itoa(r.ifIndex)

	// Get the current default gateway.
	gw, err := r.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.origGateway = gw
	flog.Infof("TUN route: original default gateway %s", gw)

	// Route server IP through original gateway to prevent loop.
	if err := runWin("route", "add", serverIP, "mask", "255.255.255.255", gw); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	// Route excluded CIDRs through original gateway (e.g., SSH source IPs).
	for _, cidr := range excludes {
		pfx, _ := netip.ParsePrefix(cidr)
		mask := net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen())
		if err := runWin("route", "add", pfx.Masked().Addr().String(), "mask", net.IP(mask).String(), gw); err != nil {
			return fmt.Errorf("failed to add exclude route for %s: %w", cidr, err)
		}
		flog.Infof("TUN route: excluded %s via %s", cidr, gw)
	}

	// Use two /1 routes to capture all traffic, specifying the TUN interface index.
	if err := runWin("route", "add", "0.0.0.0", "mask", "128.0.0.0", ip, "metric", "5", "IF", ifStr); err != nil {
		return fmt.Errorf("failed to add 0.0.0.0/1 route: %w", err)
	}
	if err := runWin("route", "add", "128.0.0.0", "mask", "128.0.0.0", ip, "metric", "5", "IF", ifStr); err != nil {
		return fmt.Errorf("failed to add 128.0.0.0/1 route: %w", err)
	}

	// Configure DNS on the TUN interface.
	if dnsIP != "" {
		if err := r.setupDNS(tunName, dnsIP); err != nil {
			flog.Warnf("TUN DNS: failed to configure: %v", err)
		} else {
			flog.Infof("TUN DNS: set to %s on %s", dnsIP, tunName)
		}
	}

	flog.Infof("TUN route: default route via %s (%s, IF %d), server %s via %s", ip, tunName, r.ifIndex, serverIP, gw)
	return nil
}

func (r *windowsRouteManager) removeRoutes() error {
	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Restore DNS settings.
	if r.dnsIP != "" && r.tunName != "" {
		if err := r.restoreDNS(); err != nil {
			flog.Warnf("TUN DNS: failed to restore: %v", err)
		} else {
			flog.Infof("TUN DNS: restored")
		}
	}

	// Remove the two /1 routes.
	save(runWin("route", "delete", "0.0.0.0", "mask", "128.0.0.0"))
	save(runWin("route", "delete", "128.0.0.0", "mask", "128.0.0.0"))

	// Remove server-specific route.
	save(runWin("route", "delete", r.serverIP))

	// Remove excluded routes.
	for _, cidr := range r.excludes {
		pfx, _ := netip.ParsePrefix(cidr)
		save(runWin("route", "delete", pfx.Masked().Addr().String()))
	}

	if firstErr != nil {
		flog.Errorf("TUN route: errors during route cleanup: %v", firstErr)
	} else {
		flog.Infof("TUN route: restored original routes")
	}
	return firstErr
}

// setupDNS configures DNS on the TUN interface.
func (r *windowsRouteManager) setupDNS(tunName, dnsIP string) error {
	// Set a low interface metric so Windows prefers TUN's DNS over other interfaces.
	// Windows uses the DNS server from the interface with the lowest metric.
	_ = runWin("netsh", "interface", "ipv4", "set", "interface",
		"interface="+tunName, "metric=1")

	// Set DNS server on TUN interface with validate=no to skip connectivity check.
	if err := runWin("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+tunName, "static", dnsIP, "primary", "validate=no"); err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	// Flush DNS cache to apply immediately.
	_ = runWin("ipconfig", "/flushdns")

	return nil
}

// restoreDNS removes DNS configuration from the TUN interface.
func (r *windowsRouteManager) restoreDNS() error {
	// Set DNS back to DHCP (automatic).
	return runWin("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+r.tunName, "dhcp", "validate=no")
}

func (r *windowsRouteManager) getDefaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	// Parse "route print 0.0.0.0" output for the default gateway.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2], nil
			}
		}
	}
	return "", fmt.Errorf("could not determine default gateway")
}

func runWin(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
