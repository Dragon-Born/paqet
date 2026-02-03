//go:build !darwin

package tun

// Linux and Windows TUN devices deliver raw IP packets without a header prefix.
const tunOffset = 0
