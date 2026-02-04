package conf

import (
	"fmt"
	"net"
)

// NetworkInfo holds auto-detected network configuration.
type NetworkInfo struct {
	Interface  string
	GUID       string // Windows NPF device GUID
	IPv4Addr   string
	GatewayIP  string
	GatewayMAC string
}

// detectLocalIP finds the first suitable IP address on the given interface.
func detectLocalIP(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// Prefer IPv4
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}
