//go:build windows

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"paqet/internal/flog"
	"strings"
)

type windowsRouteManager struct {
	serverIP    string
	tunAddr     string
	origGateway string
}

func newRouteManager() routeManager {
	return &windowsRouteManager{}
}

func (r *windowsRouteManager) addRoutes(tunName, tunAddr, serverIP string) error {
	r.serverIP = serverIP
	r.tunAddr = tunAddr

	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		return fmt.Errorf("invalid TUN address: %w", err)
	}
	ip := prefix.Addr().String()

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

	// Use two /1 routes to capture all traffic without replacing the default route.
	if err := runWin("route", "add", "0.0.0.0", "mask", "128.0.0.0", ip, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add 0.0.0.0/1 route: %w", err)
	}
	if err := runWin("route", "add", "128.0.0.0", "mask", "128.0.0.0", ip, "metric", "5"); err != nil {
		return fmt.Errorf("failed to add 128.0.0.0/1 route: %w", err)
	}

	flog.Infof("TUN route: default route via %s (%s), server %s via %s", ip, tunName, serverIP, gw)
	return nil
}

func (r *windowsRouteManager) removeRoutes() error {
	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Remove the two /1 routes.
	save(runWin("route", "delete", "0.0.0.0", "mask", "128.0.0.0"))
	save(runWin("route", "delete", "128.0.0.0", "mask", "128.0.0.0"))

	// Remove server-specific route.
	save(runWin("route", "delete", r.serverIP))

	if firstErr != nil {
		flog.Errorf("TUN route: errors during route cleanup: %v", firstErr)
	} else {
		flog.Infof("TUN route: restored original routes")
	}
	return firstErr
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
