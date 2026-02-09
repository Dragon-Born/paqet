//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"paqet/internal/flog"
	"strings"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

type linuxRouteManager struct {
	origGateway string
	origIface   string
	serverIP    string
	tunName     string
	tunAddr     string
	excludes    []string
}

func newRouteManager() routeManager {
	return &linuxRouteManager{}
}

func (r *linuxRouteManager) addRoutes(_ wgtun.Device, tunName, tunAddr, serverIP, dnsIP string, excludes []string) error {
	r.serverIP = serverIP
	r.tunName = tunName
	r.tunAddr = tunAddr
	r.excludes = excludes
	// TODO: Implement DNS configuration for Linux (modify /etc/resolv.conf or use resolvconf)
	_ = dnsIP

	// Get the current default gateway.
	gw, iface, err := r.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	r.origGateway = gw
	r.origIface = iface
	flog.Infof("TUN route: original default gateway %s dev %s", gw, iface)

	// Assign address and bring up TUN interface.
	if err := run("ip", "addr", "add", tunAddr, "dev", tunName); err != nil {
		return fmt.Errorf("failed to add address to TUN: %w", err)
	}
	if err := run("ip", "link", "set", "dev", tunName, "up"); err != nil {
		return fmt.Errorf("failed to bring up TUN: %w", err)
	}

	// Route server IP through original gateway to prevent loop.
	if err := run("ip", "route", "add", serverIP+"/32", "via", gw, "dev", iface); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}

	// Route excluded CIDRs through original gateway (e.g., SSH source IPs).
	for _, cidr := range excludes {
		if err := run("ip", "route", "add", cidr, "via", gw, "dev", iface); err != nil {
			return fmt.Errorf("failed to add exclude route for %s: %w", cidr, err)
		}
		flog.Infof("TUN route: excluded %s via %s dev %s", cidr, gw, iface)
	}

	// Replace default route with TUN.
	if err := run("ip", "route", "replace", "default", "dev", tunName); err != nil {
		return fmt.Errorf("failed to set default route via TUN: %w", err)
	}

	flog.Infof("TUN route: default route via %s, server %s via %s dev %s", tunName, serverIP, gw, iface)
	return nil
}

func (r *linuxRouteManager) removeRoutes() error {
	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Restore original default route.
	save(run("ip", "route", "replace", "default", "via", r.origGateway, "dev", r.origIface))

	// Remove server-specific route.
	save(run("ip", "route", "delete", r.serverIP+"/32"))

	// Remove excluded routes.
	for _, cidr := range r.excludes {
		save(run("ip", "route", "delete", cidr))
	}

	if firstErr != nil {
		flog.Errorf("TUN route: errors during route cleanup: %v", firstErr)
	} else {
		flog.Infof("TUN route: restored original default gateway %s dev %s", r.origGateway, r.origIface)
	}
	return firstErr
}

func (r *linuxRouteManager) getDefaultGateway() (string, string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}
	// Expected: "default via 192.168.1.1 dev eth0 ..."
	parts := strings.Fields(string(out))
	var gateway, iface string
	for i, p := range parts {
		if p == "via" && i+1 < len(parts) {
			gateway = parts[i+1]
		}
		if p == "dev" && i+1 < len(parts) {
			iface = parts[i+1]
		}
	}
	if gateway == "" {
		return "", "", fmt.Errorf("could not determine default gateway")
	}
	return gateway, iface, nil
}
