package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

func createTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create TUN device %q: %w", name, err)
	}

	// On macOS the system assigns utunN automatically; use the actual name.
	actualName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("failed to get TUN device name: %w", err)
	}

	return dev, actualName, nil
}
