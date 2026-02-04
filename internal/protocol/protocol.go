package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"paqet/internal/conf"
	"paqet/internal/tnet"
)

type PType = byte

const (
	PPING   PType = 0x01
	PPONG   PType = 0x02
	PTCPF   PType = 0x03
	PTCP    PType = 0x04
	PUDP    PType = 0x05
	PICMP   PType = 0x06
	PUDPDGM PType = 0x07 // UDP with datagram mode (unreliable, high throughput)
)

var (
	ErrUnknownProtoType = errors.New("unknown protocol type")
	ErrNilAddr          = errors.New("addr is nil")
)

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
	ICMP *ICMPData // For ICMP packets
}

// ICMPData holds ICMP packet info for tunneling.
type ICMPData struct {
	DstIP   net.IP // Destination IP
	Payload []byte // Full ICMP payload (type, code, checksum, data)
}

func (p *Proto) Read(r io.Reader) error {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return err
	}
	p.Type = typeBuf[0]

	switch p.Type {
	case PPING, PPONG:
		return nil
	case PTCP, PUDP, PUDPDGM:
		return p.readAddr(r)
	case PTCPF:
		return p.readTCPF(r)
	case PICMP:
		return p.readICMP(r)
	default:
		return ErrUnknownProtoType
	}
}

func (p *Proto) Write(w io.Writer) error {
	if _, err := w.Write([]byte{p.Type}); err != nil {
		return err
	}

	switch p.Type {
	case PPING, PPONG:
		return nil
	case PTCP, PUDP, PUDPDGM:
		return p.writeAddr(w)
	case PTCPF:
		return p.writeTCPF(w)
	case PICMP:
		return p.writeICMP(w)
	default:
		return ErrUnknownProtoType
	}
}

// readTCPF reads TCPF entries using binary encoding.
// Wire format: uint16 count, then for each entry: 2 bytes of packed flags.
func (p *Proto) readTCPF(r io.Reader) error {
	var count uint16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return err
	}
	p.TCPF = make([]conf.TCPF, count)
	for i := range p.TCPF {
		var packed [2]byte
		if _, err := io.ReadFull(r, packed[:]); err != nil {
			return err
		}
		p.TCPF[i] = unpackTCPF(packed)
	}
	return nil
}

// writeTCPF writes TCPF entries using binary encoding.
func (p *Proto) writeTCPF(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(p.TCPF))); err != nil {
		return err
	}
	for _, f := range p.TCPF {
		packed := packTCPF(f)
		if _, err := w.Write(packed[:]); err != nil {
			return err
		}
	}
	return nil
}

// packTCPF encodes a TCPF into 2 bytes (9 flags, 7 bits reserved).
func packTCPF(f conf.TCPF) [2]byte {
	var b [2]byte
	if f.FIN {
		b[0] |= 1 << 0
	}
	if f.SYN {
		b[0] |= 1 << 1
	}
	if f.RST {
		b[0] |= 1 << 2
	}
	if f.PSH {
		b[0] |= 1 << 3
	}
	if f.ACK {
		b[0] |= 1 << 4
	}
	if f.URG {
		b[0] |= 1 << 5
	}
	if f.ECE {
		b[0] |= 1 << 6
	}
	if f.CWR {
		b[0] |= 1 << 7
	}
	if f.NS {
		b[1] |= 1 << 0
	}
	return b
}

// unpackTCPF decodes a TCPF from 2 bytes.
func unpackTCPF(b [2]byte) conf.TCPF {
	return conf.TCPF{
		FIN: b[0]&(1<<0) != 0,
		SYN: b[0]&(1<<1) != 0,
		RST: b[0]&(1<<2) != 0,
		PSH: b[0]&(1<<3) != 0,
		ACK: b[0]&(1<<4) != 0,
		URG: b[0]&(1<<5) != 0,
		ECE: b[0]&(1<<6) != 0,
		CWR: b[0]&(1<<7) != 0,
		NS:  b[1]&(1<<0) != 0,
	}
}

// readICMP reads ICMP data.
// Wire format: isIPv6(1) + dstIP(4 or 16) + payloadLen(2) + payload(payloadLen)
func (p *Proto) readICMP(r io.Reader) error {
	var isIPv6 [1]byte
	if _, err := io.ReadFull(r, isIPv6[:]); err != nil {
		return err
	}

	var dstIP net.IP
	if isIPv6[0] == 1 {
		dstIP = make([]byte, 16)
	} else {
		dstIP = make([]byte, 4)
	}
	if _, err := io.ReadFull(r, dstIP); err != nil {
		return err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(lenBuf[:])

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}

	p.ICMP = &ICMPData{DstIP: dstIP, Payload: payload}
	return nil
}

// writeICMP writes ICMP data.
func (p *Proto) writeICMP(w io.Writer) error {
	if p.ICMP == nil {
		return errors.New("ICMP data is nil")
	}

	// Write IPv6 flag
	isIPv6 := byte(0)
	ip := p.ICMP.DstIP
	if ip.To4() == nil {
		isIPv6 = 1
		ip = ip.To16()
	} else {
		ip = ip.To4()
	}
	if _, err := w.Write([]byte{isIPv6}); err != nil {
		return err
	}

	// Write destination IP
	if _, err := w.Write(ip); err != nil {
		return err
	}

	// Write payload length and payload
	lenBuf := [2]byte{}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p.ICMP.Payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(p.ICMP.Payload)
	return err
}

// Address type constants for binary encoding
const (
	addrTypeIPv4     byte = 0x01
	addrTypeIPv6     byte = 0x02
	addrTypeHostname byte = 0x03
)

// readAddr reads address using binary encoding.
// Wire format: type(1) + address(variable) + port(2)
//   - IPv4: type(0x01) + ip(4) + port(2) = 7 bytes
//   - IPv6: type(0x02) + ip(16) + port(2) = 19 bytes
//   - Hostname: type(0x03) + len(1) + hostname(len) + port(2)
func (p *Proto) readAddr(r io.Reader) error {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return err
	}

	var host string
	switch typeBuf[0] {
	case addrTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return err
		}
		host = net.IP(ipBuf).String()
	case addrTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return err
		}
		host = net.IP(ipBuf).String()
	case addrTypeHostname:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return err
		}
		hostBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, hostBuf); err != nil {
			return err
		}
		host = string(hostBuf)
	default:
		return errors.New("unknown address type")
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))

	p.Addr = &tnet.Addr{Host: host, Port: port}
	return nil
}

// writeAddr writes address using binary encoding.
// Saves ~60% bandwidth vs text encoding for IPv4 addresses.
func (p *Proto) writeAddr(w io.Writer) error {
	if p.Addr == nil {
		return ErrNilAddr
	}

	// Try parsing as IP address first
	ip := net.ParseIP(p.Addr.Host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: 7 bytes total
			if _, err := w.Write([]byte{addrTypeIPv4}); err != nil {
				return err
			}
			if _, err := w.Write(ip4); err != nil {
				return err
			}
		} else {
			// IPv6: 19 bytes total
			if _, err := w.Write([]byte{addrTypeIPv6}); err != nil {
				return err
			}
			if _, err := w.Write(ip.To16()); err != nil {
				return err
			}
		}
	} else {
		// Hostname: variable length
		hostBytes := []byte(p.Addr.Host)
		if len(hostBytes) > 255 {
			return errors.New("hostname too long")
		}
		if _, err := w.Write([]byte{addrTypeHostname, byte(len(hostBytes))}); err != nil {
			return err
		}
		if _, err := w.Write(hostBytes); err != nil {
			return err
		}
	}

	// Write port (2 bytes)
	portBuf := [2]byte{}
	binary.BigEndian.PutUint16(portBuf[:], uint16(p.Addr.Port))
	_, err := w.Write(portBuf[:])
	return err
}
