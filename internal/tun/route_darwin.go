//go:build darwin

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"paqet/internal/flog"
	"strings"
)

type darwinRouteManager struct {
	origGateway    string
	origIface      string
	serverIP       string
	tunAddr        string
	networkService string   // e.g., "Wi-Fi", "Ethernet"
	origDNS        []string // original DNS servers
}

func newRouteManager() routeManager {
	return &darwinRouteManager{}
}

func (r *darwinRouteManager) addRoutes(tunName, tunAddr, serverIP, dnsIP string) error {
	r.serverIP = serverIP
	r.tunAddr = tunAddr

	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}
	ip := prefix.Addr().String()

	// Get the current default gateway.
	gw, iface, err := r.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.origGateway = gw
	r.origIface = iface
	flog.Infof("TUN route: original default gateway %s via %s", gw, iface)

	// Assign address to TUN interface.
	if err := run("ifconfig", tunName, ip, ip, "up"); err != nil {
		return fmt.Errorf("failed to configure TUN interface: %w", err)
	}

	// Route server IP through original gateway to prevent loop.
	if err := run("route", "add", "-host", serverIP, gw); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	// Replace default route with TUN.
	_ = run("route", "delete", "default")
	if err := run("route", "add", "default", ip); err != nil {
		return fmt.Errorf("failed to set default route via TUN: %w", err)
	}

	// Configure system DNS to use tunnel DNS (like WireGuard does).
	// This preserves LAN access while ensuring DNS goes through the tunnel.
	if dnsIP != "" {
		if err := r.setupDNS(iface, dnsIP); err != nil {
			flog.Warnf("TUN DNS: failed to configure system DNS: %v", err)
			flog.Infof("TUN DNS: traffic to port 53 will still be redirected via gVisor")
		} else {
			flog.Infof("TUN DNS: system DNS set to %s (LAN access preserved)", dnsIP)
		}
	}

	flog.Infof("TUN route: default route via %s (%s), server %s via %s", ip, tunName, serverIP, gw)
	return nil
}

func (r *darwinRouteManager) removeRoutes() error {
	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Restore original DNS settings.
	if r.networkService != "" {
		if err := r.restoreDNS(); err != nil {
			flog.Warnf("TUN DNS: failed to restore DNS: %v", err)
		} else {
			flog.Infof("TUN DNS: restored original DNS settings")
		}
	}

	// Restore original default route.
	_ = run("route", "delete", "default")
	save(run("route", "add", "default", r.origGateway))

	// Remove server-specific route.
	save(run("route", "delete", "-host", r.serverIP))

	if firstErr != nil {
		flog.Errorf("TUN route: errors during route cleanup: %v", firstErr)
	} else {
		flog.Infof("TUN route: restored original default gateway %s", r.origGateway)
	}
	return firstErr
}

func (r *darwinRouteManager) getDefaultGateway() (string, string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", err
	}
	var gateway, iface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if gateway == "" {
		return "", "", fmt.Errorf("could not determine default gateway")
	}
	return gateway, iface, nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// setupDNS configures system DNS to use the specified server.
// This is the WireGuard approach - change system DNS instead of routing gateway.
func (r *darwinRouteManager) setupDNS(iface, dnsIP string) error {
	// Find network service name for the interface.
	service, err := r.getNetworkService(iface)
	if err != nil {
		return fmt.Errorf("failed to find network service for %s: %w", iface, err)
	}
	r.networkService = service

	// Save original DNS settings.
	r.origDNS = r.getCurrentDNS(service)
	flog.Debugf("TUN DNS: original DNS for %s: %v", service, r.origDNS)

	// Set new DNS.
	if err := run("networksetup", "-setdnsservers", service, dnsIP); err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	return nil
}

// restoreDNS restores the original DNS settings.
func (r *darwinRouteManager) restoreDNS() error {
	if r.networkService == "" {
		return nil
	}
	if len(r.origDNS) == 0 {
		// Was using DHCP DNS, clear manual settings.
		return run("networksetup", "-setdnsservers", r.networkService, "Empty")
	}
	args := append([]string{"-setdnsservers", r.networkService}, r.origDNS...)
	return run("networksetup", args...)
}

// getNetworkService finds the network service name for a given interface.
func (r *darwinRouteManager) getNetworkService(iface string) (string, error) {
	// Get hardware port info which maps interface to service name.
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "", err
	}

	// Parse output to find service name for our interface.
	// Format:
	// Hardware Port: Wi-Fi
	// Device: en0
	lines := strings.Split(string(out), "\n")
	var currentService string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			currentService = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		}
		if strings.HasPrefix(line, "Device:") {
			device := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if device == iface {
				return currentService, nil
			}
		}
	}

	return "", fmt.Errorf("no network service found for interface %s", iface)
}

// getCurrentDNS gets the current DNS servers for a network service.
func (r *darwinRouteManager) getCurrentDNS(service string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil
	}

	dnsStr := strings.TrimSpace(string(out))
	if strings.Contains(dnsStr, "There aren't any DNS Servers") {
		return nil // Using DHCP DNS
	}

	var servers []string
	for _, line := range strings.Split(dnsStr, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			servers = append(servers, line)
		}
	}
	return servers
}
