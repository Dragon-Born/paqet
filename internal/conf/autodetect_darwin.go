//go:build darwin

package conf

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DetectNetwork auto-detects network configuration on macOS.
func DetectNetwork() (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Get default gateway and interface from route table.
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

	// Get gateway MAC from ARP cache.
	mac, err := getGatewayMAC(gateway)
	if err != nil {
		return nil, fmt.Errorf("failed to detect gateway MAC: %w", err)
	}
	info.GatewayMAC = mac

	return info, nil
}

// getDefaultGateway parses macOS route output to find default gateway and interface.
func getDefaultGateway() (gateway string, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("route command failed: %w", err)
	}

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
	if iface == "" {
		return "", "", fmt.Errorf("could not determine default interface")
	}

	return gateway, iface, nil
}

// getGatewayMAC retrieves the gateway's MAC address from the ARP cache.
// If not found, it pings the gateway first to populate the cache.
func getGatewayMAC(gatewayIP string) (string, error) {
	// Try ARP cache first.
	if mac, err := lookupARP(gatewayIP); err == nil && mac != "" {
		return mac, nil
	}

	// Ping gateway to populate ARP cache.
	_ = exec.Command("ping", "-c", "1", "-W", "1", gatewayIP).Run()
	time.Sleep(100 * time.Millisecond)

	// Retry ARP lookup.
	mac, err := lookupARP(gatewayIP)
	if err != nil {
		return "", err
	}
	if mac == "" {
		return "", fmt.Errorf("gateway MAC not found in ARP cache")
	}

	return mac, nil
}

// lookupARP parses the arp command output for the given IP.
func lookupARP(ip string) (string, error) {
	out, err := exec.Command("arp", "-n", ip).Output()
	if err != nil {
		return "", nil // ARP entry may not exist yet
	}

	// Parse output like: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ip) && strings.Contains(line, "at") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "at" && i+1 < len(parts) {
					mac := parts[i+1]
					// Skip incomplete entries
					if mac == "(incomplete)" {
						continue
					}
					return normalizeMAC(mac), nil
				}
			}
		}
	}

	return "", nil
}

// normalizeMAC ensures each octet has two hex digits.
// macOS arp can output "48:a9:8a:b0:bb:d" instead of "48:a9:8a:b0:bb:0d".
func normalizeMAC(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return mac
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
