//go:build darwin

package tun

// macOS utun devices prepend a 4-byte protocol header (AF_INET/AF_INET6).
// wireguard/tun expects offset >= 4 on darwin for both Read and Write.
const tunOffset = 4
