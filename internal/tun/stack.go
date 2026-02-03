package tun

import (
	"context"
	"fmt"
	"net/netip"
	"paqet/internal/flog"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID             = 1
	channelEndpointSz = 8192 // Increased from 1024 for high-bandwidth transfers
)

type netStack struct {
	s   *stack.Stack
	ep  *channel.Endpoint
	dev wgtun.Device
}

func newNetStack(dev wgtun.Device, prefix netip.Prefix, mtu int) (*netStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Tune TCP for high-bandwidth transfers.
	// Increase send buffer: min 4KB, default 4MB, max 16MB.
	tcpSendBufOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 4 << 20, Max: 16 << 20}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSendBufOpt); err != nil {
		flog.Warnf("failed to set TCP send buffer size: %v", err)
	}
	// Increase receive buffer: min 4KB, default 4MB, max 16MB.
	tcpRecvBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 4 << 20, Max: 16 << 20}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRecvBufOpt); err != nil {
		flog.Warnf("failed to set TCP receive buffer size: %v", err)
	}
	// Enable SACK for better loss recovery.
	sackOpt := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		flog.Warnf("failed to enable TCP SACK: %v", err)
	}

	ep := channel.New(channelEndpointSz, uint32(mtu), "")

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	addr := prefix.Addr()
	a4 := addr.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(a4).WithPrefix(),
	}
	protoAddr.AddressWithPrefix.PrefixLen = prefix.Bits()
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add address: %v", err)
	}

	// Route all traffic through this NIC.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	return &netStack{s: s, ep: ep, dev: dev}, nil
}

// tunToStack reads raw IP packets from the TUN device and injects them into gVisor.
func (ns *netStack) tunToStack(ctx context.Context) {
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 65536)
	sizes := make([]int, 1)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := ns.dev.Read(bufs, sizes, tunOffset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			flog.Errorf("TUN read error: %v", err)
			continue
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(bufs[0][tunOffset : tunOffset+sizes[0]]),
		})

		// Determine protocol from IP version.
		version := bufs[0][tunOffset] >> 4
		switch version {
		case 4:
			ns.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case 6:
			ns.ep.InjectInbound(header.IPv6ProtocolNumber, pkt)
		default:
			pkt.DecRef()
		}
	}
}

// stackToTun reads packets from the gVisor endpoint and writes them to the TUN device.
func (ns *netStack) stackToTun(ctx context.Context) {
	// Pre-allocate a reusable write buffer to avoid per-packet allocation.
	// 65536 + tunOffset covers the maximum IP packet size.
	buf := make([]byte, tunOffset+65536)
	bufs := [][]byte{buf}

	for {
		pkt := ns.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		data := view.AsSlice()
		n := len(data)

		copy(buf[tunOffset:], data)
		bufs[0] = buf[:tunOffset+n]
		if _, err := ns.dev.Write(bufs, tunOffset); err != nil {
			if ctx.Err() != nil {
				pkt.DecRef()
				return
			}
			flog.Errorf("TUN write error: %v", err)
		}
		pkt.DecRef()
	}
}

func (ns *netStack) close() {
	ns.s.Close()
	ns.ep.Close()
}
