//go:build linux

package tun

// Linux TUN devices with IFF_VNET_HDR require a 10-byte virtio-net header
// before each packet on Write. The offset reserves space for this header.
// virtioNetHdr: flags(1) + gsoType(1) + hdrLen(2) + gsoSize(2) + csumStart(2) + csumOffset(2) = 10
const tunOffset = 10
