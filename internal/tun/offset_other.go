//go:build !darwin && !linux

package tun

// Windows TUN devices deliver raw IP packets without a header prefix.
const tunOffset = 0
