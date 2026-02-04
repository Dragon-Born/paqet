//go:build linux

package conf

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DetectNetwork auto-detects network configuration on Linux.
func DetectNetwork() (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Get default gateway and interface from ip route.
	gateway, iface, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to detect default gateway: %w", err)
	}
	info.Interface = iface
	info.GatewayIP = gateway

	// Get local IP from interface.
	localIP, err := detectLocalIP(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to detect local IP: %w", err)
	}
	info.IPv4Addr = localIP

	// Get gateway MAC from neighbor cache.
	mac, err := getGatewayMAC(gateway)
	if err != nil {
		return nil, fmt.Errorf("failed to detect gateway MAC: %w", err)
	}
	info.GatewayMAC = mac

	return info, nil
}

// getDefaultGateway parses ip route output to find default gateway and interface.
func getDefaultGateway() (gateway string, iface string, err error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route command failed: %w", err)
	}

	// Expected: "default via 192.168.1.1 dev eth0 ..."
	parts := strings.Fields(string(out))
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
	if iface == "" {
		return "", "", fmt.Errorf("could not determine default interface")
	}

	return gateway, iface, nil
}

// getGatewayMAC retrieves the gateway's MAC address from the neighbor cache.
// If not found, it pings the gateway first to populate the cache.
func getGatewayMAC(gatewayIP string) (string, error) {
	// Try neighbor cache first.
	if mac, err := lookupNeighbor(gatewayIP); err == nil && mac != "" {
		return mac, nil
	}

	// Ping gateway to populate neighbor cache.
	_ = exec.Command("ping", "-c", "1", "-W", "1", gatewayIP).Run()
	time.Sleep(100 * time.Millisecond)

	// Retry neighbor lookup.
	mac, err := lookupNeighbor(gatewayIP)
	if err != nil {
		return "", err
	}
	if mac == "" {
		return "", fmt.Errorf("gateway MAC not found in neighbor cache")
	}

	return mac, nil
}

// lookupNeighbor parses ip neigh output for the given IP.
func lookupNeighbor(ip string) (string, error) {
	out, err := exec.Command("ip", "neigh", "show", ip).Output()
	if err != nil {
		return "", nil // Entry may not exist yet
	}

	// Parse output like: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
	parts := strings.Fields(string(out))
	for i, p := range parts {
		if p == "lladdr" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}

	return "", nil
}

// detectGUIDForInterface is a no-op on Linux (GUID only needed on Windows).
func detectGUIDForInterface(_ string) (string, error) {
	return "", fmt.Errorf("GUID detection not applicable on Linux")
}
