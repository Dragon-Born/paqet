package conf

import (
	"fmt"
	"net"
	"runtime"

	"paqet/internal/flog"
)

type Addr struct {
	Addr_      string           `yaml:"addr"`
	RouterMac_ string           `yaml:"router_mac"`
	Addr       *net.UDPAddr     `yaml:"-"`
	Router     net.HardwareAddr `yaml:"-"`
}

type Network struct {
	Interface_ string         `yaml:"interface"`
	GUID       string         `yaml:"guid"`
	IPv4       Addr           `yaml:"ipv4"`
	IPv6       Addr           `yaml:"ipv6"`
	PCAP       PCAP           `yaml:"pcap"`
	TCP        TCP            `yaml:"tcp"`
	Interface  *net.Interface `yaml:"-"`
	Port       int            `yaml:"-"`
}

func (n *Network) setDefaults(role string) {
	// Auto-detect network settings if not configured.
	if n.needsAutoDetect() {
		info, err := DetectNetwork()
		if err != nil {
			flog.Warnf("network auto-detection failed: %v", err)
		} else {
			n.applyAutoDetected(info)
		}
	}

	// On Windows, detect GUID for manually configured interface if needed.
	if runtime.GOOS == "windows" && n.GUID == "" && n.Interface_ != "" {
		if guid, err := detectGUIDForInterface(n.Interface_); err == nil {
			n.GUID = guid
			flog.Infof("auto-detected interface GUID: %s", guid)
		} else {
			flog.Warnf("failed to detect GUID for interface %s: %v", n.Interface_, err)
		}
	}

	n.PCAP.setDefaults(role)
	n.TCP.setDefaults()
}

// needsAutoDetect returns true if any network settings need auto-detection.
func (n *Network) needsAutoDetect() bool {
	needsInterface := n.Interface_ == ""
	needsIP := n.IPv4.Addr_ == "" && n.IPv6.Addr_ == ""
	needsMAC := n.IPv4.RouterMac_ == "" && n.IPv6.RouterMac_ == ""
	needsGUID := runtime.GOOS == "windows" && n.GUID == ""

	return needsInterface || needsIP || needsMAC || needsGUID
}

// applyAutoDetected fills in missing network configuration from auto-detected values.
func (n *Network) applyAutoDetected(info *NetworkInfo) {
	if n.Interface_ == "" && info.Interface != "" {
		n.Interface_ = info.Interface
		flog.Infof("auto-detected interface: %s", info.Interface)
	}

	if n.GUID == "" && info.GUID != "" {
		n.GUID = info.GUID
		flog.Infof("auto-detected interface GUID: %s", info.GUID)
	}

	if n.IPv4.Addr_ == "" && info.IPv4Addr != "" {
		// Use port 0 for auto-assigned random port.
		n.IPv4.Addr_ = info.IPv4Addr + ":0"
		flog.Infof("auto-detected IPv4 address: %s", info.IPv4Addr)
	}

	if n.IPv4.RouterMac_ == "" && info.GatewayMAC != "" {
		n.IPv4.RouterMac_ = info.GatewayMAC
		flog.Infof("auto-detected gateway MAC: %s", info.GatewayMAC)
	}
}

func (n *Network) validate() []error {
	var errors []error

	if n.Interface_ == "" {
		errors = append(errors, fmt.Errorf("network interface is required"))
	}
	if len(n.Interface_) > 15 {
		errors = append(errors, fmt.Errorf("network interface name too long (max 15 characters): '%s'", n.Interface_))
	}
	lIface, err := net.InterfaceByName(n.Interface_)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to find network interface %s: %v", n.Interface_, err))
	}
	n.Interface = lIface

	if runtime.GOOS == "windows" && n.GUID == "" {
		errors = append(errors, fmt.Errorf("guid is required on windows"))
	}

	ipv4Configured := n.IPv4.Addr_ != ""
	ipv6Configured := n.IPv6.Addr_ != ""
	if !ipv4Configured && !ipv6Configured {
		errors = append(errors, fmt.Errorf("at least one address family (IPv4 or IPv6) must be configured"))
		return errors
	}
	if ipv4Configured {
		errors = append(errors, n.IPv4.validate()...)
	}
	if ipv6Configured {
		errors = append(errors, n.IPv6.validate()...)
	}
	if ipv4Configured && ipv6Configured {
		if n.IPv4.Addr.Port != n.IPv6.Addr.Port {
			errors = append(errors, fmt.Errorf("IPv4 port (%d) and IPv6 port (%d) must match when both are configured", n.IPv4.Addr.Port, n.IPv6.Addr.Port))
		}
	}
	if n.IPv4.Addr != nil {
		n.Port = n.IPv4.Addr.Port
	}
	if n.IPv6.Addr != nil {
		n.Port = n.IPv6.Addr.Port
	}

	errors = append(errors, n.PCAP.validate()...)
	errors = append(errors, n.TCP.validate()...)

	return errors
}

func (n *Addr) validate() []error {
	var errors []error

	l, err := validateAddr(n.Addr_, false)
	if err != nil {
		errors = append(errors, err)
	}
	n.Addr = l

	if n.RouterMac_ == "" {
		errors = append(errors, fmt.Errorf("Router MAC address is required"))
	}

	hwAddr, err := net.ParseMAC(n.RouterMac_)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid Router MAC address '%s': %v", n.RouterMac_, err))
	}
	n.Router = hwAddr

	// Clear raw strings after parsing to free memory
	n.Addr_ = ""
	n.RouterMac_ = ""

	return errors
}
