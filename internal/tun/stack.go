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
	channelEndpointSz = 1024
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
	for {
		pkt := ns.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		data := view.AsSlice()

		// On macOS, wireguard/tun expects tunOffset bytes of headroom before the
		// IP packet for the AF_INET/AF_INET6 protocol header it writes on Write.
		buf := make([]byte, tunOffset+len(data))
		copy(buf[tunOffset:], data)
		bufs := [][]byte{buf}
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
