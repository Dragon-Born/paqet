package conf

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
)

type TUN struct {
	Name_     string   `yaml:"name"`
	Addr      string   `yaml:"addr"`
	MTU       int      `yaml:"mtu"`
	DNS       string   `yaml:"dns"`
	AutoRoute *bool    `yaml:"auto_route"`
	Exclude   []string `yaml:"exclude"`
}

func (c *TUN) setDefaults() {
	if c.Name_ == "" {
		if runtime.GOOS == "darwin" {
			c.Name_ = "utun"
		} else {
			c.Name_ = "paqet0"
		}
	}
	if c.Addr == "" {
		c.Addr = "10.0.85.1/24"
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.DNS == "" {
		c.DNS = "8.8.8.8"
	}
	if c.AutoRoute == nil {
		v := true
		c.AutoRoute = &v
	}
}

func (c *TUN) validate() []error {
	var errors []error

	if _, err := netip.ParsePrefix(c.Addr); err != nil {
		errors = append(errors, fmt.Errorf("tun.addr: invalid CIDR %q: %v", c.Addr, err))
	}

	if c.MTU < 576 || c.MTU > 65535 {
		errors = append(errors, fmt.Errorf("tun.mtu: must be between 576 and 65535, got %d", c.MTU))
	}

	if net.ParseIP(c.DNS) == nil {
		errors = append(errors, fmt.Errorf("tun.dns: invalid IP address %q", c.DNS))
	}

	for i, e := range c.Exclude {
		if _, err := netip.ParsePrefix(e); err != nil {
			// Try as bare IP and normalize to /32 or /128.
			if addr, err2 := netip.ParseAddr(e); err2 == nil {
				c.Exclude[i] = netip.PrefixFrom(addr, addr.BitLen()).String()
			} else {
				errors = append(errors, fmt.Errorf("tun.exclude[%d]: invalid CIDR or IP %q: %v", i, e, err))
			}
		}
	}

	return errors
}
