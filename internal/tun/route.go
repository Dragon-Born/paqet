package tun

type routeManager interface {
	addRoutes(tunName, tunAddr, serverIP, dnsIP string) error
	removeRoutes() error
}
