package tun

type routeManager interface {
	addRoutes(tunName, tunAddr, serverIP string) error
	removeRoutes() error
}
