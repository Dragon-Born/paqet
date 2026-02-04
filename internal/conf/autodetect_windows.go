//go:build windows

package conf

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DetectNetwork auto-detects network configuration on Windows.
func DetectNetwork() (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Get default gateway and interface from route table.
	gateway, iface, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to detect default gateway: %w", err)
	}
	info.Interface = iface
	info.GatewayIP = gateway

	// Get GUID for the interface (required for Npcap on Windows).
	guid, err := getInterfaceGUID(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to detect interface GUID: %w", err)
	}
	info.GUID = guid

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

// getDefaultGateway parses Windows route print output.
func getDefaultGateway() (gateway string, iface string, err error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", "", fmt.Errorf("route command failed: %w", err)
	}

	// Parse output for default gateway and interface.
	// Format: "0.0.0.0          0.0.0.0    192.168.1.1  192.168.1.100     35"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				gateway = fields[2]
				// The interface IP is in field 3, we need to find the interface name.
				ifaceIP := fields[3]
				iface, _ = getInterfaceByIP(ifaceIP)
				if iface != "" {
					break
				}
			}
		}
	}

	if gateway == "" {
		return "", "", fmt.Errorf("could not determine default gateway")
	}
	if iface == "" {
		// Fallback: try to get any active interface
		iface, _ = getFirstActiveInterface()
		if iface == "" {
			return "", "", fmt.Errorf("could not determine default interface")
		}
	}

	return gateway, iface, nil
}

// getInterfaceByIP finds the interface name that has the given IP address.
func getInterfaceByIP(ip string) (string, error) {
	out, err := exec.Command("netsh", "interface", "ip", "show", "addresses").Output()
	if err != nil {
		return "", err
	}

	var currentIface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Configuration for interface") {
			// Extract interface name between quotes
			start := strings.Index(line, "\"")
			end := strings.LastIndex(line, "\"")
			if start >= 0 && end > start {
				currentIface = line[start+1 : end]
			}
		}
		if strings.Contains(line, ip) && currentIface != "" {
			return currentIface, nil
		}
	}

	return "", fmt.Errorf("interface not found for IP %s", ip)
}

// getFirstActiveInterface returns the first active network interface.
func getFirstActiveInterface() (string, error) {
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Look for lines with "Connected" state
		if len(fields) >= 4 && fields[0] == "Enabled" && fields[1] == "Connected" {
			// Interface name is the rest of the fields
			return strings.Join(fields[3:], " "), nil
		}
	}

	return "", fmt.Errorf("no active interface found")
}

// getGatewayMAC retrieves the gateway's MAC address from the ARP cache.
func getGatewayMAC(gatewayIP string) (string, error) {
	// Try ARP cache first.
	if mac, err := lookupARP(gatewayIP); err == nil && mac != "" {
		return mac, nil
	}

	// Ping gateway to populate ARP cache.
	_ = exec.Command("ping", "-n", "1", "-w", "1000", gatewayIP).Run()
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

// lookupARP parses Windows arp -a output for the given IP.
func lookupARP(ip string) (string, error) {
	out, err := exec.Command("arp", "-a", ip).Output()
	if err != nil {
		return "", nil // Entry may not exist yet
	}

	// Parse output like: "192.168.1.1       aa-bb-cc-dd-ee-ff     dynamic"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ip) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Windows uses dashes in MAC addresses, convert to colons.
				mac := strings.ReplaceAll(fields[1], "-", ":")
				return mac, nil
			}
		}
	}

	return "", nil
}

// detectGUIDForInterface is the exported wrapper for GUID detection.
func detectGUIDForInterface(ifaceName string) (string, error) {
	return getInterfaceGUID(ifaceName)
}

// getInterfaceGUID retrieves the Npcap device GUID for the given interface name.
func getInterfaceGUID(ifaceName string) (string, error) {
	// Use getmac to get the transport name which contains the GUID.
	// Output format: "Connection Name","Network Adapter","Physical Address","Transport Name"
	out, err := exec.Command("getmac", "/v", "/fo", "csv").Output()
	if err != nil {
		return "", fmt.Errorf("getmac command failed: %w", err)
	}

	// Parse CSV output to find the interface.
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // Skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse CSV fields (simple parsing, handles quoted fields).
		fields := parseCSVLine(line)
		if len(fields) < 4 {
			continue
		}

		// Field 0 is connection name, field 3 is transport name.
		connName := fields[0]
		transportName := fields[3]

		if connName == ifaceName {
			// Extract GUID from transport name.
			// Format: \Device\Tcpip_{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
			guid := extractGUID(transportName)
			if guid != "" {
				// Convert to NPF format for Npcap.
				return "\\Device\\NPF_" + guid, nil
			}
		}
	}

	return "", fmt.Errorf("GUID not found for interface %s", ifaceName)
}

// parseCSVLine parses a single CSV line with quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var field strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, field.String())
			field.Reset()
		default:
			field.WriteRune(r)
		}
	}
	fields = append(fields, field.String())

	return fields
}

// extractGUID extracts the GUID from a transport name like \Device\Tcpip_{GUID}.
func extractGUID(transportName string) string {
	start := strings.Index(transportName, "{")
	end := strings.Index(transportName, "}")
	if start >= 0 && end > start {
		return transportName[start : end+1]
	}
	return ""
}
