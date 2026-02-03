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
	origGateway string
	origIface   string
	serverIP    string
	tunAddr     string
}

func newRouteManager() routeManager {
	return &darwinRouteManager{}
}

func (r *darwinRouteManager) addRoutes(tunName, tunAddr, serverIP string) error {
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
