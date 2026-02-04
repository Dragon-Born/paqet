package tun

import wgtun "golang.zx2c4.com/wireguard/tun"

type routeManager interface {
	addRoutes(dev wgtun.Device, tunName, tunAddr, serverIP, dnsIP string) error
	removeRoutes() error
}
